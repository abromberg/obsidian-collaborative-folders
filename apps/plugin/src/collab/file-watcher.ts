import { FileManager, Vault, TAbstractFile, TFile, TFolder } from 'obsidian'
import {
  SHARED_CONFIG_FILENAME,
  CRDT_EXTENSIONS,
  CANVAS_EXTENSIONS,
  type FileTreeEntry,
} from '@obsidian-teams/shared'
import { FileTreeSync } from './file-tree-sync'
import { uploadBlobWithRetry, downloadBlob, computeHash } from './blob-sync'
import { FolderKeyManager } from '../crypto/folder-key-manager'
import { debugLog } from '../utils/logger'

/**
 * Watches vault events for a shared folder and syncs changes to the Yjs file tree.
 * Also handles incoming remote changes by writing files to the local vault.
 *
 * CRITICAL: Uses a suppressedPaths guard to prevent infinite sync loops.
 * When we write a file due to a remote change, Obsidian fires a vault event,
 * which would trigger another Yjs update. The guard prevents this.
 */
export class SharedFolderWatcher {
  /** Paths we are currently writing locally — suppressed from vault events */
  private suppressedPaths = new Set<string>()
  private pendingAttachmentLocalization = new Map<string, ReturnType<typeof setTimeout>>()

  private externalEditCallback: ((fileId: string, relativePath: string, content: string) => void) | null = null
  private attachmentLocalizationCallback: ((file: TFile) => Promise<void>) | null = null

  constructor(
    private vault: Vault,
    private fileManager: FileManager,
    private fileTree: FileTreeSync,
    private folderId: string,
    private sharedFolderPath: string,
    private serverUrl: string,
    private getAuthToken: () => Promise<string | null>,
    private keyManager: FolderKeyManager
  ) {}

  private initialCrdtCallback: ((fileId: string, relativePath: string, content: string) => void) | null = null

  /** Set callback for when a CRDT file is externally modified (outside of Yjs) */
  onExternalCrdtEdit(cb: (fileId: string, relativePath: string, content: string) => void): void {
    this.externalEditCallback = cb
  }

  /** Set callback for seeding initial CRDT file content into Yjs */
  onInitialCrdtFile(cb: (fileId: string, relativePath: string, content: string) => void): void {
    this.initialCrdtCallback = cb
  }

  /** Set callback for localizing external attachments referenced by shared markdown files */
  onAttachmentLocalization(cb: (file: TFile) => Promise<void>): void {
    this.attachmentLocalizationCallback = cb
  }

  /** Start watching for local and remote changes, and scan existing files */
  start(): void {
    // Watch for remote file tree changes
    this.fileTree.onRemoteChange(({ added, updated, deleted }) => {
      void (async () => {
        for (const [path, entry] of added) {
          await this.handleRemoteAdd(path, entry)
        }
        for (const [path, entry] of updated) {
          await this.handleRemoteUpdate(path, entry)
        }
        for (const path of deleted) {
          await this.handleRemoteDelete(path)
        }
      })()
    })

    // Scan existing local files into the file tree
    void this.scanLocalFolder()
  }

  /** Scan all existing files in the shared folder and add them to the Yjs file tree */
  private async scanLocalFolder(): Promise<void> {
    const folder = this.vault.getAbstractFileByPath(this.sharedFolderPath)
    if (!folder || !(folder instanceof TFolder)) return

    const files = this.collectFiles(folder)
    debugLog(`[teams] Scanning ${files.length} existing files in ${this.sharedFolderPath}`)

    for (const file of files) {
      if (this.isConfigFile(file.path)) continue

      const relativePath = this.getRelativePath(file)
      const existing = this.fileTree.getFile(relativePath)

      if (file instanceof TFolder) {
        if (existing) {
          if (!existing.fileId) {
            this.fileTree.addOrUpdateFile(relativePath, {
              ...existing,
              fileId: crypto.randomUUID(),
              mtime: new Date().toISOString(),
            })
          }
        } else {
          this.fileTree.addOrUpdateFile(relativePath, {
            fileId: crypto.randomUUID(),
            path: relativePath,
            type: 'directory',
            mtime: new Date().toISOString(),
            syncMode: 'crdt',
          })
        }
        continue
      }

      if (!(file instanceof TFile)) continue

      const syncMode = this.determineSyncMode(relativePath)

      if (existing) {
        if (!existing.fileId) {
          this.fileTree.addOrUpdateFile(relativePath, {
            ...existing,
            fileId: crypto.randomUUID(),
            mtime: new Date().toISOString(),
            size: file.stat.size,
          })
        }
        // Already in tree — skip unless it's a blob that needs uploading
        continue
      }

      const entry: FileTreeEntry = {
        fileId: crypto.randomUUID(),
        path: relativePath,
        type: 'file',
        mtime: new Date(file.stat.mtime).toISOString(),
        size: file.stat.size,
        syncMode,
      }

      if (syncMode === 'blob') {
        await this.uploadAndTrack(file, entry)
      } else if (syncMode === 'crdt') {
        this.fileTree.addOrUpdateFile(relativePath, entry)
        // Seed the Yjs doc with the file's current content
        if (this.initialCrdtCallback) {
          try {
            const content = await this.vault.cachedRead(file)
            if (content) {
              this.initialCrdtCallback(entry.fileId, relativePath, content)
            }
          } catch (err) {
            console.error(`[teams] Failed to read CRDT file for seeding: ${file.path}`, err)
          }
        }
      } else {
        this.fileTree.addOrUpdateFile(relativePath, entry)
      }
    }

    await this.localizeAttachmentsInScannedMarkdown(files)

    debugLog(`[teams] Initial scan complete for ${this.sharedFolderPath}`)
  }

  /** Recursively collect all files and folders under a folder */
  private collectFiles(folder: TFolder): TAbstractFile[] {
    const result: TAbstractFile[] = []
    for (const child of folder.children) {
      result.push(child)
      if (child instanceof TFolder) {
        result.push(...this.collectFiles(child))
      }
    }
    return result
  }

  /** Handle a local vault 'create' event */
  onLocalCreate(file: TAbstractFile): void {
    if (!this.isInSharedFolder(file)) return
    if (this.isSuppressed(file.path)) return
    if (this.isConfigFile(file.path)) return

    const relativePath = this.getRelativePath(file)
    const syncMode = this.determineSyncMode(relativePath)

    const entry: FileTreeEntry = {
      fileId: crypto.randomUUID(),
      path: relativePath,
      type: file instanceof TFolder ? 'directory' : 'file',
      mtime: new Date().toISOString(),
      syncMode,
    }

    if (syncMode === 'blob' && file instanceof TFile) {
      // Upload blob content, then update file tree with contentHash
      void this.uploadAndTrack(file, entry)
    } else {
      this.fileTree.addOrUpdateFile(relativePath, entry)
      if (syncMode === 'crdt' && file instanceof TFile) {
        this.scheduleAttachmentLocalization(file)
      }
    }
  }

  /** Handle a local vault 'modify' event */
  onLocalModify(file: TAbstractFile): void {
    if (!this.isInSharedFolder(file)) return
    if (this.isSuppressed(file.path)) return
    if (this.isConfigFile(file.path)) return
    if (!(file instanceof TFile)) return

    const relativePath = this.getRelativePath(file)
    const existing = this.fileTree.getFile(relativePath)
    if (!existing) return

    let entry = existing
    if (!entry.fileId) {
      entry = {
        ...entry,
        fileId: crypto.randomUUID(),
        mtime: new Date().toISOString(),
        size: file.stat.size,
      }
      this.fileTree.addOrUpdateFile(relativePath, entry)
    }

    if (entry.syncMode === 'blob') {
      // Re-upload blob and update contentHash
      void this.uploadAndTrack(file, entry)
    } else if (entry.syncMode === 'crdt') {
      if (this.externalEditCallback) {
        // A CRDT file was modified on disk (possibly by another plugin or external editor).
        // Read content and push it into Yjs so it propagates to other peers.
        this.vault.cachedRead(file).then((content) => {
          this.externalEditCallback!(entry.fileId, relativePath, content)
        }).catch((err) => {
          console.error(`[teams] Failed to read externally modified CRDT file ${file.path}:`, err)
        })
      }
      this.scheduleAttachmentLocalization(file)
    }

    // Always update mtime in file tree
    this.fileTree.addOrUpdateFile(relativePath, {
      ...entry,
      mtime: new Date().toISOString(),
      size: file.stat.size,
    })
  }

  /** Handle a local vault 'delete' event */
  onLocalDelete(file: TAbstractFile): void {
    if (!this.isInSharedFolder(file)) return
    if (this.isSuppressed(file.path)) return
    if (this.isConfigFile(file.path)) return

    const relativePath = this.getRelativePath(file)
    this.fileTree.removeFile(relativePath)
  }

  /** Handle a local vault 'rename' event */
  onLocalRename(file: TAbstractFile, oldPath: string): void {
    const wasInShared = oldPath.startsWith(this.sharedFolderPath + '/')
    const isInShared = this.isInSharedFolder(file)

    if (wasInShared && isInShared) {
      // Rename within the shared folder — atomic rename
      const oldRelative = oldPath.slice(this.sharedFolderPath.length + 1)
      const newRelative = this.getRelativePath(file)
      this.fileTree.renameFile(oldRelative, newRelative)
    } else if (wasInShared && !isInShared) {
      // Moved out of shared folder — treat as delete
      const oldRelative = oldPath.slice(this.sharedFolderPath.length + 1)
      this.fileTree.removeFile(oldRelative)
    } else if (!wasInShared && isInShared) {
      // Moved into shared folder — treat as create
      this.onLocalCreate(file)
    }
  }

  // --- Remote change handlers ---

  private async handleRemoteAdd(relativePath: string, entry: FileTreeEntry): Promise<void> {
    if (!entry.fileId) {
      entry = { ...entry, fileId: crypto.randomUUID() }
      this.fileTree.addOrUpdateFile(relativePath, entry)
    }

    const fullPath = `${this.sharedFolderPath}/${relativePath}`
    this.suppress(fullPath)

    try {
      if (entry.type === 'directory') {
        const existing = this.vault.getAbstractFileByPath(fullPath)
        if (!existing) {
          await this.vault.createFolder(fullPath)
        }
      } else if (entry.syncMode === 'crdt') {
        // CRDT files get their content from the Yjs doc room, not the file tree.
        // Just create the file if it doesn't exist.
        const existing = this.vault.getAbstractFileByPath(fullPath)
        if (!(existing instanceof TFile)) {
          await this.vault.create(fullPath, '')
        }
      } else if (entry.syncMode === 'blob' && entry.contentHash) {
        // Download blob content and write to vault
        await this.applyRemoteBlob(fullPath, entry.contentHash)
      }
    } finally {
      this.unsuppress(fullPath)
    }
  }

  private async handleRemoteUpdate(relativePath: string, entry: FileTreeEntry): Promise<void> {
    if (!entry.fileId) {
      entry = { ...entry, fileId: crypto.randomUUID() }
      this.fileTree.addOrUpdateFile(relativePath, entry)
    }

    // Content updates for CRDT files come through Yjs doc sync, not the file tree.
    if (entry.syncMode !== 'blob' || !entry.contentHash) return

    const fullPath = `${this.sharedFolderPath}/${relativePath}`

    this.suppress(fullPath)
    try {
      await this.applyRemoteBlob(fullPath, entry.contentHash)
    } finally {
      this.unsuppress(fullPath)
    }
  }

  private async handleRemoteDelete(relativePath: string): Promise<void> {
    const fullPath = `${this.sharedFolderPath}/${relativePath}`
    this.suppress(fullPath)

    try {
      const file = this.vault.getAbstractFileByPath(fullPath)
      if (file) {
        await this.fileManager.trashFile(file)
      }
    } finally {
      this.unsuppress(fullPath)
    }
  }

  // --- Blob helpers ---

  /** Read a local file, upload it as a blob, and update the file tree entry with contentHash */
  private async uploadAndTrack(file: TFile, entry: FileTreeEntry): Promise<void> {
    try {
      const content = await this.vault.readBinary(file)
      const hash = await uploadBlobWithRetry(
        this.serverUrl,
        this.folderId,
        this.getAuthToken,
        this.keyManager,
        content
      )
      this.fileTree.addOrUpdateFile(entry.path, {
        ...entry,
        mtime: new Date().toISOString(),
        size: file.stat.size,
        contentHash: hash,
      })
    } catch (err) {
      console.error(`[teams] Blob upload failed for ${file.path}:`, err)
    }
  }

  /** Download a blob by hash and write it to the vault */
  private async downloadAndWrite(fullPath: string, contentHash: string): Promise<void> {
    try {
      const decrypted = await downloadBlob(
        this.serverUrl,
        this.folderId,
        this.getAuthToken,
        this.keyManager,
        contentHash
      )
      const existing = this.vault.getAbstractFileByPath(fullPath)
      if (existing instanceof TFile) {
        await this.vault.modifyBinary(existing, decrypted)
      } else {
        // Ensure parent directory exists
        const dir = fullPath.substring(0, fullPath.lastIndexOf('/'))
        if (dir && !this.vault.getAbstractFileByPath(dir)) {
          await this.vault.createFolder(dir)
        }
        await this.vault.createBinary(fullPath, decrypted)
      }
    } catch (err) {
      console.error(`[teams] Blob download failed for ${fullPath} (${contentHash}):`, err)
    }
  }

  /**
   * Apply remote blob content to a local path.
   * If local content differs, preserve a local conflict copy before overwriting.
   */
  private async applyRemoteBlob(fullPath: string, contentHash: string): Promise<void> {
    const existing = this.vault.getAbstractFileByPath(fullPath)
    if (existing instanceof TFile) {
      const localContent = await this.vault.readBinary(existing)
      const localHash = await computeHash(localContent)
      if (localHash === contentHash) return
      await this.preserveConflictCopy(fullPath, localContent)
    }
    await this.downloadAndWrite(fullPath, contentHash)
  }

  private async preserveConflictCopy(fullPath: string, content: ArrayBuffer): Promise<void> {
    const conflictPath = this.nextConflictPath(fullPath)
    this.suppress(conflictPath)
    try {
      await this.vault.createBinary(conflictPath, content)
      console.warn(`[teams] Preserved local conflicting blob as ${conflictPath}`)
    } catch (err) {
      console.error(`[teams] Failed to preserve local conflict copy for ${fullPath}:`, err)
    } finally {
      this.unsuppress(conflictPath)
    }
  }

  private nextConflictPath(fullPath: string): string {
    const lastSlash = fullPath.lastIndexOf('/')
    const lastDot = fullPath.lastIndexOf('.')
    const hasExtension = lastDot > lastSlash
    const base = hasExtension ? fullPath.slice(0, lastDot) : fullPath
    const extension = hasExtension ? fullPath.slice(lastDot) : ''

    let i = 1
    while (true) {
      const candidate = `${base} (conflict ${i})${extension}`
      if (!this.vault.getAbstractFileByPath(candidate)) {
        return candidate
      }
      i += 1
    }
  }

  // --- Helpers ---

  isInSharedFolder(file: TAbstractFile): boolean {
    return file.path.startsWith(this.sharedFolderPath + '/')
  }

  private getRelativePath(file: TAbstractFile): string {
    return file.path.slice(this.sharedFolderPath.length + 1)
  }

  private isConfigFile(path: string): boolean {
    return path.endsWith('/' + SHARED_CONFIG_FILENAME) || path === SHARED_CONFIG_FILENAME
  }

  private determineSyncMode(path: string): 'crdt' | 'blob' | 'canvas' {
    const ext = '.' + path.split('.').pop()?.toLowerCase()
    if (CRDT_EXTENSIONS.has(ext)) return 'crdt'
    if (CANVAS_EXTENSIONS.has(ext)) return 'canvas'
    return 'blob'
  }

  private scheduleAttachmentLocalization(file: TFile): void {
    if (!this.attachmentLocalizationCallback) return

    const existingTimer = this.pendingAttachmentLocalization.get(file.path)
    if (existingTimer !== undefined) {
      clearTimeout(existingTimer)
    }

    const timer = setTimeout(() => {
      this.pendingAttachmentLocalization.delete(file.path)
      void this.attachmentLocalizationCallback?.(file).catch((err) => {
        console.error(`[teams] Attachment localization failed for ${file.path}:`, err)
      })
    }, 200)

    this.pendingAttachmentLocalization.set(file.path, timer)
  }

  private async localizeAttachmentsInScannedMarkdown(files: TAbstractFile[]): Promise<void> {
    if (!this.attachmentLocalizationCallback) return

    for (const file of files) {
      if (!(file instanceof TFile)) continue
      const relativePath = this.getRelativePath(file)
      if (this.determineSyncMode(relativePath) !== 'crdt') continue

      try {
        await this.attachmentLocalizationCallback(file)
      } catch (err) {
        console.error(`[teams] Initial attachment localization failed for ${file.path}:`, err)
      }
    }
  }

  private suppress(path: string): void {
    this.suppressedPaths.add(path)
  }

  private unsuppress(path: string): void {
    // Use a short delay so the vault event has time to fire
    setTimeout(() => this.suppressedPaths.delete(path), 500)
  }

  private isSuppressed(path: string): boolean {
    if (this.suppressedPaths.has(path)) {
      this.suppressedPaths.delete(path)
      return true
    }
    return false
  }

  /** Run a file write while suppressing vault events to avoid sync feedback loops. */
  async runWithSuppressedPath<T>(path: string, fn: () => Promise<T>): Promise<T> {
    this.suppress(path)
    try {
      return await fn()
    } finally {
      this.unsuppress(path)
    }
  }
}
