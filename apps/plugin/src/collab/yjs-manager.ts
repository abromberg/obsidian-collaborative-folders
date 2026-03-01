import * as Y from 'yjs'
import { IndexeddbPersistence } from 'y-indexeddb'
import type { Extension } from '@codemirror/state'
import { docRoomName, YTEXT_NAME } from '@obsidian-teams/shared'
import { createCollabExtension } from './cm6-binding'
import { getRemoteUsers, initAwareness, onAwarenessChange } from './awareness'
import { createOfflinePersistence } from './offline'
import { EncryptedProvider } from './encrypted-provider'
import { FolderKeyManager } from '../crypto/folder-key-manager'

export interface DocSession {
  ydoc: Y.Doc
  wsProvider: EncryptedProvider
  persistence: IndexeddbPersistence
  ytext: Y.Text
  undoManager: Y.UndoManager
  extension: Extension
  roomName: string
  unsubAwareness: () => void
  stopAwarenessRefresh: () => void
}

type ConnectionStatus = 'connected' | 'connecting' | 'disconnected'
type TokenOptions = { forceRefresh?: boolean }
type AuthFailureEvent = { folderId: string; roomName: string; reason: string }

/**
 * Manages Yjs document lifecycle — creates, connects, and destroys Y.Docs
 * for shared files. Each file gets its own Y.Doc with dual providers
 * (encrypted relay + IndexedDB) and a CM6 collaborative editing extension.
 */
export class YjsManager {
  private sessions = new Map<string, DocSession>()
  private onStatusChange: ((status: ConnectionStatus) => void) | null = null
  private onUsersChange:
    | ((roomName: string, users: Array<{ clientId: number; name: string; color: string }>) => void)
    | null = null
  private onAuthFailure: ((event: AuthFailureEvent) => void) | null = null

  constructor(
    private serverUrl: string,
    private clientId: string,
    private displayName: string,
    private getAuthToken: (folderId: string, options?: TokenOptions) => Promise<string | null>,
    private keyManager: FolderKeyManager
  ) {}

  /** Set callback for connection status changes */
  setStatusCallback(cb: (status: ConnectionStatus) => void): void {
    this.onStatusChange = cb
  }

  /** Set callback for remote user presence changes */
  setUsersCallback(
    cb: (roomName: string, users: Array<{ clientId: number; name: string; color: string }>) => void
  ): void {
    this.onUsersChange = cb
  }

  /** Set callback for provider authentication failures */
  setAuthFailureCallback(cb: (event: AuthFailureEvent) => void): void {
    this.onAuthFailure = cb
  }

  /** Get or create a full collaborative session for a file */
  getOrCreateSession(folderId: string, relativePath: string): DocSession | null {
    const roomName = docRoomName(folderId, relativePath)

    const existing = this.sessions.get(roomName)
    if (existing) return existing

    const ydoc = new Y.Doc()

    // Dual provider: IndexedDB (local/offline) + encrypted WebSocket relay (network)
    const persistence = createOfflinePersistence(roomName, ydoc)

    const wsProvider = new EncryptedProvider({
      serverUrl: this.serverUrl,
      roomName,
      folderId,
      ydoc,
      getAuthToken: this.getAuthToken,
      keyManager: this.keyManager,
    })

    const awareness = wsProvider.awareness

    wsProvider.on('status', ({ status }) => {
      if (this.onStatusChange) {
        this.onStatusChange(status as ConnectionStatus)
      }
    })

    wsProvider.on('authenticationFailed', ({ reason }) => {
      void this.getAuthToken(folderId, { forceRefresh: true }).catch(() => null)
      if (this.onAuthFailure) {
        this.onAuthFailure({ folderId, roomName, reason })
      }
    })

    const stopAwarenessRefresh = initAwareness(awareness, this.clientId, this.displayName)

    const unsubAwareness = onAwarenessChange(awareness, (users) => {
      if (this.onUsersChange) {
        this.onUsersChange(roomName, users)
      }
    })

    const ytext = ydoc.getText(YTEXT_NAME)

    const { extension, undoManager } = createCollabExtension(ytext, awareness)

    const session: DocSession = {
      ydoc,
      wsProvider,
      persistence,
      ytext,
      undoManager,
      extension,
      roomName,
      unsubAwareness,
      stopAwarenessRefresh,
    }

    this.sessions.set(roomName, session)
    return session
  }

  /** Destroy a specific session */
  destroySession(roomName: string): void {
    const session = this.sessions.get(roomName)
    if (!session) return

    session.unsubAwareness()
    session.stopAwarenessRefresh()
    session.undoManager.destroy()
    session.wsProvider.awareness.setLocalState(null)
    session.wsProvider.disconnect()
    session.wsProvider.destroy()
    session.ydoc.destroy()
    this.sessions.delete(roomName)
  }

  /** Destroy all sessions */
  destroyAll(): void {
    for (const roomName of [...this.sessions.keys()]) {
      this.destroySession(roomName)
    }
  }

  /** Destroy all sessions belonging to a shared folder. */
  destroySessionsForFolder(folderId: string): void {
    const prefix = `folder:${folderId}:doc:`
    for (const roomName of [...this.sessions.keys()]) {
      if (roomName.startsWith(prefix)) {
        this.destroySession(roomName)
      }
    }
  }

  /** Get a session by room name */
  getSession(roomName: string): DocSession | undefined {
    return this.sessions.get(roomName)
  }

  /** Get current remote users for a room from awareness state. */
  getUsers(roomName: string): Array<{ clientId: number; name: string; color: string }> {
    const session = this.sessions.get(roomName)
    if (!session) return []

    return getRemoteUsers(session.wsProvider.awareness)
  }

  /** Check if a session exists for this file */
  hasSession(folderId: string, relativePath: string): boolean {
    return this.sessions.has(docRoomName(folderId, relativePath))
  }

  /** Get the count of active sessions */
  get sessionCount(): number {
    return this.sessions.size
  }
}
