import * as Y from 'yjs'
import { IndexeddbPersistence } from 'y-indexeddb'
import { treeRoomName, FILETREE_MAP_NAME, type FileTreeEntry } from '@obsidian-teams/shared'
import { createOfflinePersistence } from './offline'
import { EncryptedProvider } from './encrypted-provider'
import { FolderKeyManager } from '../crypto/folder-key-manager'

/**
 * Manages the file tree Y.Map for a shared folder.
 * The Y.Map is keyed by relative file path with FileTreeEntry values.
 * This tracks all files/directories in the shared folder across all peers.
 */
export class FileTreeSync {
  private ydoc: Y.Doc
  private wsProvider: EncryptedProvider
  private persistence: IndexeddbPersistence
  private fileTree: Y.Map<FileTreeEntry>
  private roomName: string

  constructor(
    folderId: string,
    serverUrl: string,
    getToken: (options?: { forceRefresh?: boolean }) => Promise<string | null>,
    keyManager: FolderKeyManager
  ) {
    this.roomName = treeRoomName(folderId)
    this.ydoc = new Y.Doc()

    this.persistence = createOfflinePersistence(this.roomName, this.ydoc)
    this.wsProvider = new EncryptedProvider({
      serverUrl,
      roomName: this.roomName,
      folderId,
      ydoc: this.ydoc,
      getAuthToken: async (_folderId, options) => getToken(options),
      keyManager,
    })

    this.fileTree = this.ydoc.getMap(FILETREE_MAP_NAME)

    this.wsProvider.on('status', ({ status }) => {
      if (this.statusCallback) {
        this.statusCallback(status as 'connected' | 'connecting' | 'disconnected')
      }
    })

    this.wsProvider.on('authenticationFailed', ({ reason }) => {
      void getToken({ forceRefresh: true }).catch(() => null)
      if (this.authFailedCallback) {
        this.authFailedCallback(reason)
      }
    })
  }

  private statusCallback: ((status: 'connected' | 'connecting' | 'disconnected') => void) | null = null
  private authFailedCallback: ((reason: string) => void) | null = null

  /** Set callback for WebSocket connection status changes */
  onStatus(cb: (status: 'connected' | 'connecting' | 'disconnected') => void): void {
    this.statusCallback = cb
  }

  /** Set callback for authentication failures */
  onAuthFailed(cb: (reason: string) => void): void {
    this.authFailedCallback = cb
  }

  /** Add or update a file in the tree */
  addOrUpdateFile(relativePath: string, entry: FileTreeEntry): void {
    this.ydoc.transact(() => {
      this.fileTree.set(relativePath, { ...entry, path: relativePath })
    })
  }

  /** Remove a file from the tree */
  removeFile(relativePath: string): void {
    this.ydoc.transact(() => {
      this.fileTree.delete(relativePath)
    })
  }

  /** Atomic rename: delete old key, set new key in a single transaction */
  renameFile(oldPath: string, newPath: string): void {
    this.ydoc.transact(() => {
      const entry = this.fileTree.get(oldPath)
      if (entry) {
        this.fileTree.delete(oldPath)
        this.fileTree.set(newPath, { ...entry, path: newPath, mtime: new Date().toISOString() })
      }
    })
  }

  /** Get a specific file entry */
  getFile(relativePath: string): FileTreeEntry | undefined {
    return this.fileTree.get(relativePath)
  }

  /** Find a file by immutable file ID */
  getByFileId(fileId: string): { relativePath: string; entry: FileTreeEntry } | null {
    for (const [relativePath, entry] of this.fileTree.entries()) {
      if (entry.fileId === fileId) {
        return { relativePath, entry }
      }
    }
    return null
  }

  /** Get all files in the tree */
  getAllFiles(): Map<string, FileTreeEntry> {
    const result = new Map<string, FileTreeEntry>()
    this.fileTree.forEach((value, key) => {
      result.set(key, value)
    })
    return result
  }

  /** Observe remote changes to the file tree */
  onRemoteChange(callback: (changes: {
    added: Map<string, FileTreeEntry>
    updated: Map<string, FileTreeEntry>
    deleted: string[]
  }) => void): void {
    this.fileTree.observe((event) => {
      if (event.transaction.local) return

      const added = new Map<string, FileTreeEntry>()
      const updated = new Map<string, FileTreeEntry>()
      const deleted: string[] = []

      event.changes.keys.forEach((change, key) => {
        if (change.action === 'add') {
          const entry = this.fileTree.get(key)
          if (entry) added.set(key, entry)
        } else if (change.action === 'update') {
          const entry = this.fileTree.get(key)
          if (entry) updated.set(key, entry)
        } else if (change.action === 'delete') {
          deleted.push(key)
        }
      })

      callback({ added, updated, deleted })
    })
  }

  destroy(): void {
    this.wsProvider.disconnect()
    this.wsProvider.destroy()
    void this.persistence.destroy()
    this.ydoc.destroy()
  }
}
