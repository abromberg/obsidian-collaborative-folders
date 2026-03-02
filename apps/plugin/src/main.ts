import {
  Plugin,
  TAbstractFile,
  TFolder,
  TFile,
  MarkdownView,
  Notice,
  setIcon,
  requestUrl,
  type ObsidianProtocolData,
} from 'obsidian'
import type { Extension } from '@codemirror/state'
import {
  DEFAULT_SERVER_URL,
  SHARED_CONFIG_FILENAME,
  docRoomName,
  normalizeRelativePath,
  resolveSharedPath,
} from '@obsidian-teams/shared'
import {
  ObsidianTeamsSettingTab,
  DEFAULT_SETTINGS,
  SELF_DEPLOY_DEFAULT_SERVER_URL,
  type ObsidianTeamsSettings,
} from './settings'
import { findSharedFolders, removeSharedConfig, type SharedFolderLocation } from './utils/dotfile'
import { YjsManager, type DocSession } from './collab/yjs-manager'
import { FileTreeSync } from './collab/file-tree-sync'
import { SharedFolderWatcher } from './collab/file-watcher'
import { AttachmentLocalizer } from './collab/attachment-localizer'
import {
  createHostedCheckoutSession,
  createHostedPortalSession,
  startHostedOtp,
  verifyHostedOtp,
  silentHostedRelink,
  getHostedAuthMe,
  decodeAccessToken,
  getAccessToken,
  getFolderRole,
  getOrRefreshToken,
  removeAccessToken,
  removeFolderMember,
  createFileShareLink,
  previewFileShareLink,
  resolveFileShareLink,
} from './utils/auth'
import { ShareFolderModal } from './ui/share-modal'
import { JoinFolderModal, joinSharedFolderByInvite } from './ui/join-modal'
import { OnboardingModal } from './ui/onboarding-modal'
import { DashboardModal } from './ui/dashboard-modal'
import { FolderKeyManager } from './crypto/folder-key-manager'
import { keyHealthLabel, type KeyHealthState } from './ui/key-health-status'
import { registerObsidianRequestUrl } from './utils/http'
import { debugLog, setDebugLogging } from './utils/logger'
import { friendlyError, isConfigError, isHostedSessionError, rawErrorMessage } from './utils/friendly-errors'
import {
  hasFileSharePermission,
  relativePathWithinSharedFolder,
  resolveFileShareTokenParam,
} from './utils/file-share-links'

interface FolderSession {
  fileTree: FileTreeSync
  watcher: SharedFolderWatcher
  keyManager: FolderKeyManager
  sharedFolderPath: string
}

interface BackgroundMirror {
  folderId: string
  sharedFolderPath: string
  relativePath: string
  fileId: string | null
  session: DocSession
  pendingWriteTimer: number | null
  onYTextChange: (_event: unknown, transaction: { local?: boolean }) => void
  onSynced: ({ state }: { state: boolean }) => void
}

export default class ObsidianTeamsPlugin extends Plugin {
  settings: ObsidianTeamsSettings = DEFAULT_SETTINGS
  yjsManager: YjsManager | null = null
  keyManager: FolderKeyManager | null = null
  attachmentLocalizer: AttachmentLocalizer | null = null
  private statusBarEl: HTMLElement | null = null
  private connectionStatus: 'connected' | 'offline' | 'syncing' = 'offline'
  private authStatus: 'ok' | 'auth-failed' | 'auth-expired' = 'ok'
  private keyHealth: KeyHealthState = 'healthy'
  private statusUsers: Array<{ clientId: number; name: string; color: string }> = []
  private editorExtensions: Extension[] = []
  private sharedFolders: SharedFolderLocation[] = []
  private activeSession: DocSession | null = null
  private folderSessions = new Map<string, FolderSession>()
  private folderNoticeCooldownMs = 60_000
  private folderNoticeAt = new Map<string, number>()
  private backgroundMirrors = new Map<string, BackgroundMirror>()
  private pendingBindTimeout: number | null = null
  private sharedFolderBadgeObserver: MutationObserver | null = null
  private sharedFolderBadgeTimer: number | null = null
  private ownerEnvelopeCoverageTimer: number | null = null
  private ownerEnvelopeCoverageInFlight = false
  private networkNoticeCooldownMs = 90_000
  private lastNetworkNoticeAt = 0
  private membershipDetachInFlight = new Set<string>()
  private protocolBillingInFlight = false
  private inviteJoinInFlight = new Map<string, Promise<boolean>>()
  private pendingRootRebinds = new Map<string, { newPath: string; expiresAt: number }>()

  async onload() {
    await this.loadSettings()
    setDebugLogging(this.settings.debugLogging)
    registerObsidianRequestUrl(requestUrl)

    // Generate client ID on first load
    if (!this.settings.clientId) {
      this.settings.clientId = crypto.randomUUID()
      await this.saveSettings()
    }

    if (this.isHostedMode() && this.settings.hostedAccountEmail) {
      void silentHostedRelink(this)
    }

    this.keyManager = new FolderKeyManager(
      this.settings.serverUrl,
      this.settings.clientId,
      (folderId, options) => getOrRefreshToken(this, folderId, options)
    )
    this.attachmentLocalizer = new AttachmentLocalizer(this.app)

    // Initialize YjsManager
    this.yjsManager = new YjsManager(
      this.settings.serverUrl,
      this.settings.clientId,
      this.settings.displayName || 'Anonymous',
      (folderId, options) => getOrRefreshToken(this, folderId, options),
      this.keyManager
    )

    this.yjsManager.setStatusCallback((status) => {
      if (status === 'connected') {
        this.updateKeyHealth('healthy')
      }
      this.updateStatusBar(status === 'connected' ? 'connected' : status === 'connecting' ? 'syncing' : 'offline')
    })

    this.yjsManager.setAuthFailureCallback(({ folderId, reason }) => {
      void this.handleFolderAuthFailure(folderId, reason)
    })

    this.yjsManager.setUsersCallback((roomName, users) => {
      if (this.activeSession?.roomName === roomName && this.editorExtensions.length > 0) {
        this.updatePresenceDisplay(users)
      }
    })

    // Settings tab
    this.addSettingTab(new ObsidianTeamsSettingTab(this.app, this))

    // Status bar
    this.statusBarEl = this.addStatusBarItem()
    this.updateStatusBar('offline')

    // Ribbon icon
    this.addRibbonIcon('users', 'Collaborative folders', () => {
      new DashboardModal(this.app, this).open()
    })

    // Command: Join shared folder
    this.addCommand({
      id: 'join-shared-folder',
      name: 'Join shared folder',
      callback: () => {
        if (!this.settings.onboardingComplete) {
          new OnboardingModal(this.app, this).open()
          return
        }
        new JoinFolderModal(this.app, this).open()
      },
    })

    this.addCommand({
      id: 'shared-folders-dashboard',
      name: 'View shared folders',
      callback: () => {
        new DashboardModal(this.app, this).open()
      },
    })

    this.registerObsidianProtocolHandler('teams-join', (params) => {
      void this.handleInviteDeepLink(params)
    })
    this.registerObsidianProtocolHandler('teams-billing', (params) => {
      void this.handleBillingDeepLink(params)
    })
    this.registerObsidianProtocolHandler('teams-open-file', (params) => {
      void this.handleFileShareDeepLink(params)
    })

    // Register editor extensions (mutated dynamically per-file)
    this.registerEditorExtension(this.editorExtensions)

    // Suppress known transient CM6 cursor position errors from awareness updates
    // that can race with document hydration during initial sync.
    this.registerDomEvent(
      window,
      'error',
      (event: ErrorEvent) => {
        if (!this.shouldIgnorePresenceRangeError(event)) return
        event.preventDefault()
      },
      { capture: true }
    )

    this.registerEvent(
      this.app.workspace.on('layout-change', () => {
        this.scheduleSharedFolderBadgeRefresh()
      })
    )

    // Context menu: right-click folder → "Share folder" / "Manage shared folder"
    this.registerEvent(
      this.app.workspace.on('file-menu', (menu, file) => {
        if (file instanceof TFolder) {
          const sharedFolder = this.getSharedFolderForPath(file.path)
          if (sharedFolder && sharedFolder.path === file.path) {
            const roleFromToken = getFolderRole(this, sharedFolder.config.folderId)
            const isOwner =
              roleFromToken === 'owner' ||
              sharedFolder.config.members.some(
                (m) => m.clientId === this.settings.clientId && m.role === 'owner'
              )
            if (isOwner) {
              menu.addItem((item) => {
                item
                  .setTitle('Manage shared folder...')
                  .setIcon('settings')
                  .onClick(() => {
                    new ShareFolderModal(this.app, file, this).open()
                  })
              })
            } else {
              menu.addItem((item) => {
                item
                  .setTitle('Leave shared folder')
                  .setIcon('log-out')
                  .onClick(() => this.leaveSharedFolder(sharedFolder))
              })
            }
          } else if (!sharedFolder) {
            menu.addItem((item) => {
              item
                .setTitle('Share folder...')
                .setIcon('share-2')
                .onClick(() => {
                  if (!this.settings.onboardingComplete) {
                    new OnboardingModal(this.app, this).open()
                    return
                  }
                  new ShareFolderModal(this.app, file, this).open()
                })
            })
          }
          return
        }

        if (!(file instanceof TFile)) return

        const sharedFolder = this.getSharedFolderForPath(file.path)
        if (!sharedFolder) return
        const roleFromToken = getFolderRole(this, sharedFolder.config.folderId)
        const roleFromConfig =
          sharedFolder.config.members.find((member) => member.clientId === this.settings.clientId)?.role || null
        const effectiveRole = roleFromToken || roleFromConfig
        if (!hasFileSharePermission(effectiveRole)) return

        menu.addItem((item) => {
          item
            .setTitle('Create share link')
            .setIcon('share-2')
            .onClick(() => {
              void this.createFileShareLinkForFile(file)
            })
        })
      })
    )

    // Bind Yjs when a file is opened (fires after Obsidian loads file content into the editor).
    this.registerEvent(
      this.app.workspace.on('file-open', (file) => {
        this.scheduleSharedFolderBadgeRefresh()
        if (file instanceof TFile) {
          this.scheduleFileBind(file)
        } else {
          this.clearPendingBind()
          this.unbindCollaboration()
        }
      })
    )

    // Vault events — forwarded to the appropriate SharedFolderWatcher
    this.registerEvent(
      this.app.vault.on('create', (file) => {
        for (const session of this.folderSessions.values()) {
          session.watcher.onLocalCreate(file)
        }
      })
    )
    this.registerEvent(
      this.app.vault.on('modify', (file) => {
        for (const session of this.folderSessions.values()) {
          session.watcher.onLocalModify(file)
        }
      })
    )
    this.registerEvent(
      this.app.vault.on('delete', (file) => {
        for (const session of this.folderSessions.values()) {
          session.watcher.onLocalDelete(file)
        }
      })
    )
    this.registerEvent(
      this.app.vault.on('rename', (file, oldPath) => {
        for (const session of this.folderSessions.values()) {
          session.watcher.onLocalRename(file, oldPath)
        }
        this.refreshSharedFoldersOnRootRename(file, oldPath)
      })
    )

    // Defer initialization until layout is ready, then bind current file if any.
    this.app.workspace.onLayoutReady(() => {
      this.startSharedFolderBadgeObserver()
      this.initializeSharedFolders()
        .then(() => {
          const activeFile = this.app.workspace.getActiveFile()
          if (activeFile instanceof TFile) {
            this.scheduleFileBind(activeFile)
          }
        })
        .catch((err) => {
          console.error('[teams] Failed to initialize shared folders:', err)
        })

      if (!this.settings.onboardingComplete) {
        new OnboardingModal(this.app, this).open()
      }
    })

    debugLog('Collaborative Folders plugin loaded')
  }

  private shouldIgnorePresenceRangeError(event: ErrorEvent): boolean {
    const message =
      typeof event.message === 'string' && event.message.length > 0
        ? event.message
        : event.error instanceof Error
          ? event.error.message
          : ''
    if (!/^Invalid position \d+ in document of length \d+$/.test(message)) {
      return false
    }

    const stack = event.error instanceof Error ? event.error.stack || '' : ''
    const fromPlugin =
      (typeof event.filename === 'string' && event.filename.includes('plugin:collaborative-folders'))
      || stack.includes('plugin:collaborative-folders')

    // Limit suppression to the known awareness/selection rendering failure mode.
    return fromPlugin && stack.includes('lineAt')
  }

  private decodeProtocolParam(value: string): string {
    try {
      return decodeURIComponent(value)
    } catch {
      return value
    }
  }

  private resolveInviteTokenFromDeepLink(params: ObsidianProtocolData): string | null {
    const fromToken = typeof params.token === 'string' ? params.token : ''
    const fromInviteToken = typeof params.inviteToken === 'string' ? params.inviteToken : ''
    const raw = (fromToken || fromInviteToken).trim()
    if (!raw) return null
    const decoded = this.decodeProtocolParam(raw).trim()
    return decoded.length > 0 ? decoded : null
  }

  private resolveFileShareTokenFromDeepLink(params: ObsidianProtocolData): string | null {
    return resolveFileShareTokenParam(params as unknown as Record<string, unknown>)
  }

  private async createFileShareLinkForFile(file: TFile): Promise<void> {
    if (!this.settings.onboardingComplete) {
      new OnboardingModal(this.app, this).open()
      return
    }

    const sharedFolder = this.getSharedFolderForPath(file.path)
    if (!sharedFolder) {
      new Notice('This file is not inside a shared folder.')
      return
    }

    const relativePath = relativePathWithinSharedFolder(sharedFolder.path, file.path)
    if (!relativePath) {
      new Notice('Could not resolve this file path inside the shared folder.')
      return
    }

    const folderId = sharedFolder.config.folderId
    const fileId = this.folderSessions.get(folderId)?.fileTree.getFile(relativePath)?.fileId || null

    try {
      const result = await createFileShareLink(this, folderId, {
        fileId,
        relativePath,
        fileName: file.name,
      })

      try {
        await navigator.clipboard.writeText(result.shareUrl)
        new Notice(`Share link copied for ${file.name}`)
      } catch {
        new Notice(`Share link created: ${result.shareUrl}`)
      }
    } catch (error) {
      const raw = rawErrorMessage(error, 'Failed to create file share link')
      new Notice(friendlyError(raw))
      console.error('[teams] File share link creation failed:', error)
    }
  }

  private resolveOpenRelativePath(
    folderId: string,
    target: { fileId: string | null; relativePath: string }
  ): string {
    const folderSession = this.folderSessions.get(folderId)
    if (target.fileId && folderSession) {
      const mapped = folderSession.fileTree.getByFileId(target.fileId)
      if (mapped) return mapped.relativePath
    }
    return target.relativePath
  }

  private async waitForSharedFileOnDisk(fullPath: string): Promise<TFile | null> {
    const maxAttempts = 8
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const abstract = this.app.vault.getAbstractFileByPath(fullPath)
      if (abstract instanceof TFile) {
        return abstract
      }

      if (attempt < maxAttempts - 1) {
        await this.waitForMs(350)
      }
    }
    return null
  }

  private async handleFileShareDeepLink(params: ObsidianProtocolData): Promise<void> {
    const token = this.resolveFileShareTokenFromDeepLink(params)
    if (!token) {
      new Notice('File link is missing token')
      return
    }

    try {
      const preview = await previewFileShareLink(this.settings.serverUrl, token)
      const sharedFolder = this.sharedFolders.find((sf) => sf.config.folderId === preview.folderId)
      if (!sharedFolder) {
        new Notice(`Shared folder '${preview.folderName}' is not joined on this device yet.`)
        return
      }

      const target = await resolveFileShareLink(this, preview.folderId, token)
      const resolvedRelativePath = this.resolveOpenRelativePath(preview.folderId, target)
      const fullPath = `${sharedFolder.path}/${resolvedRelativePath}`
      const targetFile = await this.waitForSharedFileOnDisk(fullPath)
      if (!targetFile) {
        const folderSession = this.folderSessions.get(preview.folderId)
        const fileStillInTree = target.fileId
          ? Boolean(folderSession?.fileTree.getByFileId(target.fileId))
          : Boolean(folderSession?.fileTree.getFile(resolvedRelativePath))
        if (fileStillInTree) {
          new Notice('File is not synced yet. Try again shortly.')
        } else {
          new Notice('This shared file no longer exists.')
        }
        return
      }

      const leaf = this.app.workspace.getLeaf(true)
      await leaf.openFile(targetFile)
    } catch (error) {
      const raw = rawErrorMessage(error, 'Failed to open shared file')
      new Notice(friendlyError(raw))
      console.error('[teams] File-link deep-link handling failed:', error)
    }
  }

  private openPluginSettings(): void {
    const settingsRoot = (this.app as unknown as {
      setting?: { open?: () => void; openTabById?: (id: string) => void }
    }).setting
    settingsRoot?.open?.()
    settingsRoot?.openTabById?.('collaborative-folders')
  }

  private async joinInviteTokenWithRetry(inviteToken: string) {
    try {
      return await joinSharedFolderByInvite(this.app, this, inviteToken)
    } catch (error) {
      const raw = rawErrorMessage(error, 'Join failed')
      if (!isHostedSessionError(raw)) {
        throw error
      }
      const relinked = await silentHostedRelink(this, { force: true })
      if (!relinked) {
        throw error
      }
      return joinSharedFolderByInvite(this.app, this, inviteToken)
    }
  }

  async attemptInviteJoin(
    inviteToken: string,
    options: { openSettingsOnConfigError?: boolean; suppressSuccessNotice?: boolean } = {}
  ): Promise<boolean> {
    const token = inviteToken.trim()
    if (!token) {
      new Notice('Invite link is missing token')
      return false
    }

    const existingJoin = this.inviteJoinInFlight.get(token)
    if (existingJoin) {
      return existingJoin
    }

    const joinAttempt = (async (): Promise<boolean> => {
      try {
        const result = await this.joinInviteTokenWithRetry(token)
        if (this.settings.pendingInviteToken) {
          this.settings.pendingInviteToken = ''
          await this.saveSettings()
        }
        if (!options.suppressSuccessNotice) {
          new Notice(`Joined shared folder: ${result.folderName}`)
        }
        return true
      } catch (error) {
        const raw = rawErrorMessage(error, 'Unknown error')
        const message = friendlyError(raw)

        if (isConfigError(raw)) {
          this.settings.pendingInviteToken = token
          await this.saveSettings()
          if (options.openSettingsOnConfigError ?? true) {
            this.openPluginSettings()
          }
          new Notice('Configure your account to join the shared folder. Your invite is saved.')
          return false
        }

        new Notice(`Failed to join folder: ${message}`)
        console.error('[teams] Join error:', error)
        return false
      }
    })()

    this.inviteJoinInFlight.set(token, joinAttempt)
    try {
      return await joinAttempt
    } finally {
      this.inviteJoinInFlight.delete(token)
    }
  }

  private async handleInviteDeepLink(params: ObsidianProtocolData): Promise<void> {
    const inviteToken = this.resolveInviteTokenFromDeepLink(params)
    if (!inviteToken) {
      new Notice('Invite link is missing token')
      if (!this.settings.onboardingComplete) {
        new OnboardingModal(this.app, this).open()
      } else {
        new JoinFolderModal(this.app, this).open()
      }
      return
    }

    if (!this.settings.onboardingComplete) {
      this.settings.pendingInviteToken = inviteToken
      await this.saveSettings()
      new OnboardingModal(this.app, this).open()
      return
    }

    await this.attemptInviteJoin(inviteToken)
  }

  private normalizeBillingStatus(value: string): 'success' | 'cancel' | 'return' {
    if (value === 'success' || value === 'cancel' || value === 'return') {
      return value
    }
    return 'return'
  }

  private resolveBillingStatusFromDeepLink(params: ObsidianProtocolData): 'success' | 'cancel' | 'return' {
    const fromStatus = typeof params.status === 'string' ? params.status : ''
    const fromResult = typeof params.result === 'string' ? params.result : ''
    const fromBilling = typeof params.billing === 'string' ? params.billing : ''
    const raw = (fromStatus || fromResult || fromBilling).trim().toLowerCase()
    const decoded = this.decodeProtocolParam(raw).trim().toLowerCase()
    return this.normalizeBillingStatus(decoded)
  }

  private isHostedSubscriptionActive(status: string): boolean {
    const normalized = status.trim().toLowerCase()
    return normalized === 'active' || normalized === 'trialing'
  }

  private isHostedSubscriptionManagedInPortal(status: string): boolean {
    const normalized = status.trim().toLowerCase()
    return (
      normalized === 'active'
      || normalized === 'trialing'
      || normalized === 'past_due'
      || normalized === 'unpaid'
      || normalized === 'incomplete'
      || normalized === 'paused'
    )
  }

  private buildHostedBillingReturnUrl(status: 'success' | 'cancel' | 'return'): string {
    const baseUrl = this.settings.serverUrl.trim().replace(/\/+$/, '')
    return `${baseUrl}/api/hosted/billing/return?status=${encodeURIComponent(status)}`
  }

  private waitForMs(durationMs: number): Promise<void> {
    return new Promise((resolve) => {
      window.setTimeout(resolve, durationMs)
    })
  }

  private async refreshHostedBillingSnapshot(
    hostedSessionToken: string,
    options: { waitForActive?: boolean } = {}
  ) {
    const waitForActive = options.waitForActive ?? false
    const maxAttempts = waitForActive ? 8 : 1
    let latestSnapshot: Awaited<ReturnType<typeof getHostedAuthMe>> | null = null
    let latestError: unknown = null

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      try {
        const snapshot = await getHostedAuthMe(this.settings.serverUrl, hostedSessionToken)
        latestSnapshot = snapshot
        if (!waitForActive || this.isHostedSubscriptionActive(snapshot.billing.subscriptionStatus)) {
          return snapshot
        }
      } catch (error) {
        latestError = error
      }

      if (attempt < maxAttempts - 1) {
        await this.waitForMs(1_250)
      }
    }

    if (latestSnapshot) return latestSnapshot
    if (latestError instanceof Error) throw latestError
    throw new Error('Failed to refresh hosted billing state')
  }

  async refreshHostedSubscriptionStatus(): Promise<string | null> {
    if (!this.isHostedMode()) return null
    if (!this.settings.hostedSessionToken) return null

    try {
      const snapshot = await this.refreshHostedBillingSnapshot(this.settings.hostedSessionToken)
      this.settings.hostedSubscriptionStatus = snapshot.billing.subscriptionStatus || 'inactive'
      this.settings.hostedAccountEmail = snapshot.account.email
      this.settings.hostedSessionExpiresAt = snapshot.account.expiresAt
      if (snapshot.account.displayName) {
        this.settings.hostedAccountDisplayName = snapshot.account.displayName
        if (!this.settings.displayName) {
          this.settings.displayName = snapshot.account.displayName
        }
      }
      await this.saveSettings()
      return this.settings.hostedSubscriptionStatus
    } catch {
      return this.settings.hostedSubscriptionStatus || null
    }
  }

  private async handleBillingDeepLink(params: ObsidianProtocolData): Promise<void> {
    if (!this.isHostedMode()) return

    const status = this.resolveBillingStatusFromDeepLink(params)

    if (status === 'cancel') {
      new Notice('Checkout canceled. No billing changes were applied.')
      return
    }

    if (this.protocolBillingInFlight) {
      new Notice('Billing update is already in progress')
      return
    }

    this.protocolBillingInFlight = true
    try {
      const hostedSessionToken = await this.ensureHostedBillingSession()
      if (!hostedSessionToken) {
        new Notice('Hosted account session missing. Set your hosted email and retry billing.')
        return
      }

      const snapshot = await this.refreshHostedBillingSnapshot(hostedSessionToken, {
        waitForActive: status === 'success',
      })
      const subscriptionStatus = snapshot.billing.subscriptionStatus || 'inactive'

      this.settings.hostedAccountEmail = snapshot.account.email
      this.settings.hostedSubscriptionStatus = subscriptionStatus
      const displayName =
        snapshot.account.displayName || this.settings.displayName || this.effectiveHostedDisplayName()
      this.settings.hostedAccountDisplayName = displayName
      this.settings.hostedSessionExpiresAt = snapshot.account.expiresAt
      if (!this.settings.displayName) {
        this.settings.displayName = displayName
      }
      await this.saveSettings()

      if (status === 'success') {
        if (this.isHostedSubscriptionActive(subscriptionStatus)) {
          new Notice('Subscription active. Hosted collaboration is ready.')
        } else {
          new Notice(`Checkout completed. Billing status is '${subscriptionStatus}'. It may take a moment to sync.`)
        }
      } else if (this.isHostedSubscriptionActive(subscriptionStatus)) {
        new Notice('Returned from billing portal. Subscription is active.')
      } else {
        new Notice(`Returned from billing portal. Current billing status: ${subscriptionStatus}.`)
      }

      if (this.isHostedSubscriptionActive(subscriptionStatus) && this.settings.pendingInviteToken) {
        new Notice('You have a pending invite. Joining now...')
        await this.attemptInviteJoin(this.settings.pendingInviteToken)
      }

      void this.refreshSharedFolders()
    } catch (error) {
      const message = this.describeHostedRequestError(error, 'Failed to refresh hosted billing status')
      new Notice(message)
      console.error('[teams] Billing deep-link handling failed:', error)
    } finally {
      this.protocolBillingInFlight = false
    }
  }

  onunload() {
    this.clearPendingBind()
    this.destroyAllBackgroundMirrors()
    this.stopSharedFolderBadgeObserver()
    this.stopOwnerEnvelopeCoverageLoop()

    // Destroy all folder-level file tree sessions
    for (const session of this.folderSessions.values()) {
      session.fileTree.destroy()
    }
    this.folderSessions.clear()

    if (this.yjsManager) {
      this.yjsManager.destroyAll()
      this.yjsManager = null
    }
    this.attachmentLocalizer = null
    this.keyManager = null
    this.activeSession = null
    this.editorExtensions.length = 0
    debugLog('Collaborative Folders plugin unloaded')
  }

  /** Scan vault for shared folders on startup and start file tree sync */
  private async initializeSharedFolders() {
    this.sharedFolders = await findSharedFolders(this.app.vault)
    if (this.sharedFolders.length > 0) {
      debugLog(`[teams] Found ${this.sharedFolders.length} shared folder(s):`,
        this.sharedFolders.map(f => f.path))
    }
    this.syncFolderSessions()
    this.startOwnerEnvelopeCoverageLoop()
    void this.reconcileOwnerEnvelopeCoverage()
    this.scheduleSharedFolderBadgeRefresh()
  }

  /** Public method to refresh the shared folders list (called after share/join) */
  async refreshSharedFolders() {
    this.sharedFolders = await findSharedFolders(this.app.vault)
    this.syncFolderSessions()
    void this.reconcileOwnerEnvelopeCoverage()
    this.scheduleSharedFolderBadgeRefresh()
    const activeFile = this.app.workspace.getActiveFile()
    if (activeFile instanceof TFile) {
      this.scheduleFileBind(activeFile)
    }
  }

  /** Owner-only member removal with mandatory rekey payload and local key persistence. */
  async removeMemberWithRekey(folderId: string, memberClientId: string): Promise<void> {
    if (!this.keyManager) {
      throw new Error('Encryption key manager is unavailable')
    }

    const rotatePlan = await this.keyManager.buildRotatePayloadForMemberRemoval(folderId, memberClientId)
    const result = await removeFolderMember(this, folderId, memberClientId, rotatePlan.rotate)
    if (!result.rotatedEpoch) {
      throw new Error('Member removed without key rotation; refusing to continue')
    }

    await this.keyManager.storeContentKeyForEpoch(folderId, result.rotatedEpoch, rotatePlan.contentKey)
    await this.refreshSharedFolders()
  }

  /** Owner-only cleanup when a folder no longer has active/pending shares. */
  async clearOwnerShareState(folderId: string, folderPath: string): Promise<void> {
    const removedSharedFolder = await this.clearLocalFolderLink(folderId)
    if (removedSharedFolder) return

    await removeSharedConfig(this.app.vault, folderPath)
    await removeAccessToken(this, folderId)
    this.keyManager?.clearFolderKeys(folderId)
    await this.refreshSharedFolders()
  }

  private startOwnerEnvelopeCoverageLoop() {
    if (this.ownerEnvelopeCoverageTimer !== null) return

    this.ownerEnvelopeCoverageTimer = window.setInterval(() => {
      void this.reconcileOwnerEnvelopeCoverage()
    }, 5_000)
  }

  private stopOwnerEnvelopeCoverageLoop() {
    if (this.ownerEnvelopeCoverageTimer === null) return
    window.clearInterval(this.ownerEnvelopeCoverageTimer)
    this.ownerEnvelopeCoverageTimer = null
  }

  private async reconcileOwnerEnvelopeCoverage(): Promise<void> {
    if (this.ownerEnvelopeCoverageInFlight) return
    if (!this.keyManager) return

    this.ownerEnvelopeCoverageInFlight = true
    try {
      for (const sharedFolder of this.sharedFolders) {
        const folderId = sharedFolder.config.folderId
        const token = getAccessToken(this, folderId)
        if (!token) continue

        const access = decodeAccessToken(token)
        if (!access || access.role !== 'owner') continue

        try {
          const updated = await this.keyManager.ensureOwnerEnvelopeCoverage(folderId)
          if (updated) {
            debugLog(`[teams] Updated key envelope coverage for folder ${folderId}`)
          }
        } catch (error) {
          console.warn(`[teams] Failed to update key envelope coverage for folder ${folderId}`, error)
        }
      }
    } finally {
      this.ownerEnvelopeCoverageInFlight = false
    }
  }

  /** Leave a shared folder: disconnect, remove config, keep local files as snapshot */
  private async leaveSharedFolder(sf: SharedFolderLocation) {
    const { folderId } = sf.config
    await this.clearLocalFolderLink(folderId)

    new Notice(`Left shared folder: ${sf.config.displayName || sf.path}. Local files kept as snapshot.`)
  }

  private getDashboardStatus(folderId: string): 'connected' | 'offline' | 'auth-expired' {
    const token = getAccessToken(this, folderId)
    if (!token) return 'auth-expired'

    const payload = decodeAccessToken(token)
    if (!payload) return 'auth-expired'
    if (payload.exp && payload.exp * 1000 <= Date.now()) {
      return 'auth-expired'
    }
    return this.connectionStatus === 'connected' && this.authStatus === 'ok' ? 'connected' : 'offline'
  }

  getDashboardEntries(): Array<{
    folderId: string
    folderName: string
    folderPath: string
    role: 'owner' | 'editor'
    memberCount: number
    status: 'connected' | 'offline' | 'auth-expired'
  }> {
    return this.sharedFolders.map((sharedFolder) => {
      const roleFromToken = getFolderRole(this, sharedFolder.config.folderId)
      const roleFromConfig = sharedFolder.config.members.find(
        (member) => member.clientId === this.settings.clientId
      )?.role
      const role = roleFromToken || roleFromConfig || 'editor'

      return {
        folderId: sharedFolder.config.folderId,
        folderName: sharedFolder.config.displayName || sharedFolder.path,
        folderPath: sharedFolder.path,
        role,
        memberCount: sharedFolder.config.members.length || 1,
        status: this.getDashboardStatus(sharedFolder.config.folderId),
      }
    })
  }

  openShareModalForPath(folderPath: string): boolean {
    const target = this.app.vault.getAbstractFileByPath(folderPath)
    if (!(target instanceof TFolder)) return false
    new ShareFolderModal(this.app, target, this).open()
    return true
  }

  async leaveSharedFolderById(folderId: string): Promise<void> {
    const sharedFolder = this.sharedFolders.find((item) => item.config.folderId === folderId)
    if (!sharedFolder) return
    await this.leaveSharedFolder(sharedFolder)
  }

  revealFolderInExplorer(folderPath: string): boolean {
    const target = this.app.vault.getAbstractFileByPath(folderPath)
    if (!target) return false

    const leaves = this.app.workspace.getLeavesOfType('file-explorer')
    if (leaves.length === 0) return false
    const explorerView = leaves[0]?.view as { revealInFolder?: (target: unknown) => void } | undefined
    if (!explorerView || typeof explorerView.revealInFolder !== 'function') return false

    explorerView.revealInFolder(target)
    return true
  }

  /** Start/stop FileTreeSync + SharedFolderWatcher to match discovered shared folders */
  private syncFolderSessions() {
    const desiredFolderPathById = new Map(
      this.sharedFolders.map((sf) => [sf.config.folderId, this.normalizePath(sf.path)])
    )

    // Tear down sessions for folders that no longer exist or moved to a new path.
    for (const [folderId, session] of this.folderSessions) {
      const desiredPath = desiredFolderPathById.get(folderId)
      if (!desiredPath) {
        this.removeBackgroundMirrorsForFolder(folderId, true)
        session.fileTree.destroy()
        this.folderSessions.delete(folderId)
        debugLog(`[teams] Stopped file tree sync for removed folder ${folderId}`)
        continue
      }

      const sessionPath = this.normalizePath(session.sharedFolderPath)
      if (sessionPath !== desiredPath) {
        this.pendingRootRebinds.delete(sessionPath)
        this.removeBackgroundMirrorsForFolder(folderId, true)
        session.fileTree.destroy()
        this.folderSessions.delete(folderId)
        debugLog(`[teams] Restarting file tree sync after folder move: ${folderId} (${sessionPath} -> ${desiredPath})`)
      }
    }

    // Start sessions for new folders
    for (const sf of this.sharedFolders) {
      const { folderId } = sf.config
      if (this.folderSessions.has(folderId)) continue

      const token = getAccessToken(this, folderId)
      if (!token) {
        const folderName = sf.config.displayName || sf.path
        if (this.shouldShowFolderNotice(folderId)) {
          new Notice(
            `Shared folder '${folderName}' needs re-authentication. ` +
            `Right-click the folder to re-share or request a new invite.`
          )
        }
        console.warn(`[teams] No auth token for folder ${folderId}, skipping file tree sync`)
        continue
      }

      if (!this.keyManager) {
        console.warn('[teams] Key manager unavailable, skipping folder session start')
        continue
      }

      const fileTree = new FileTreeSync(
        folderId,
        this.settings.serverUrl,
        (options) => getOrRefreshToken(this, folderId, options),
        this.keyManager
      )

      // Update status bar from file tree sync connection
      fileTree.onStatus((status) => {
        if (status === 'connected') {
          this.updateKeyHealth('healthy')
        }
        this.updateStatusBar(
          status === 'connected' ? 'connected' : status === 'connecting' ? 'syncing' : 'offline'
        )
      })

      fileTree.onAuthFailed((reason) => {
        void this.handleFolderAuthFailure(folderId, reason)
      })

      const watcher = new SharedFolderWatcher(
        this.app.vault,
        this.app.fileManager,
        fileTree,
        folderId,
        sf.path,
        this.settings.serverUrl,
        () => getOrRefreshToken(this, folderId),
        this.keyManager,
        (oldPath, newPath) => this.isRootRebindRename(oldPath, newPath)
      )

      // Seed initial CRDT file content into Yjs when scanning existing files
      watcher.onInitialCrdtFile((_fileId, relativePath, content) => {
        if (!this.yjsManager) return
        const session = this.yjsManager.getOrCreateSession(folderId, relativePath)
        if (!session) return

        if (content.length === 0) return

        const seedLocalContent = () => {
          // Only seed if the Yjs doc is empty after initial sync (don't overwrite existing content).
          if (session.ytext.length !== 0) return
          session.ydoc.transact(() => {
            session.ytext.insert(0, content)
          })
          debugLog(`[teams] Seeded CRDT content for ${relativePath} (${content.length} chars)`)
        }

        // Wait for initial sync before seeding, otherwise stale local content can race with server state.
        if (session.wsProvider.isSynced) {
          seedLocalContent()
          return
        }

        const onSync = ({ state }: { state: boolean }) => {
          if (!state) return
          session.wsProvider.off('synced', onSync)
          seedLocalContent()
        }

        session.wsProvider.on('synced', onSync)
        // Handle the race where sync completes between the isSynced check and listener registration.
        if (session.wsProvider.isSynced) {
          session.wsProvider.off('synced', onSync)
          seedLocalContent()
        }
      })

      // Handle external CRDT file edits (e.g., another plugin modifies a .md file on disk)
      watcher.onExternalCrdtEdit((fileId, relativePath, diskContent) => {
        if (!this.yjsManager) return
        const folderSession = this.folderSessions.get(folderId)
        const mapped = folderSession?.fileTree.getByFileId(fileId)
        const currentRelativePath = mapped?.relativePath ?? relativePath
        const normalizedRelativePath = normalizeRelativePath(currentRelativePath)
        if (!normalizedRelativePath) {
          console.warn('[teams] Blocked external CRDT import for unsafe path', { folderId, currentRelativePath })
          return
        }

        const session = this.yjsManager.getSession(docRoomName(folderId, normalizedRelativePath))
        if (!session) return

        const yjsContent = this.readSessionContent(session)
        if (yjsContent !== diskContent) {
          session.ydoc.transact(() => {
            session.ytext.delete(0, session.ytext.length)
            session.ytext.insert(0, diskContent)
          })
          debugLog(`[teams] Imported external edit for ${normalizedRelativePath}`)
        }
      })

      watcher.onAttachmentLocalization(async (file) => {
        if (!this.attachmentLocalizer) return
        const result = await this.attachmentLocalizer.localizeForMarkdown(sf.path, file)
        if (result.rewrittenEmbeds === 0) return

        debugLog(
          `[teams] Localized ${result.localizedAttachments} attachment(s) and rewrote ` +
          `${result.rewrittenEmbeds} embed(s) in ${file.path}`
        )
      })

      // Start watching (also triggers initial scan of existing files)
      watcher.start()

      // Keep CRDT files in the background synced to disk for reliable reopen/off-screen updates.
      this.ensureBackgroundMirrorsForKnownFiles(folderId, sf.path, fileTree)
      fileTree.onRemoteChange(({ added, updated, deleted }) => {
        for (const [relativePath, entry] of [...added.entries(), ...updated.entries()]) {
          if (entry.type === 'file' && entry.syncMode === 'crdt') {
            this.ensureBackgroundMirror(folderId, sf.path, relativePath, entry.fileId ?? null)
          }
        }
        for (const relativePath of deleted) {
          this.removeBackgroundMirror(docRoomName(folderId, relativePath), true)
        }
      })

      this.folderSessions.set(folderId, { fileTree, watcher, keyManager: this.keyManager, sharedFolderPath: sf.path })
      debugLog(`[teams] Started file tree sync for ${sf.path} (${folderId})`)
    }
  }

  private ensureBackgroundMirrorsForKnownFiles(
    folderId: string,
    sharedFolderPath: string,
    fileTree: FileTreeSync
  ) {
    for (const [relativePath, entry] of fileTree.getAllFiles()) {
      if (entry.type === 'file' && entry.syncMode === 'crdt') {
        this.ensureBackgroundMirror(folderId, sharedFolderPath, relativePath, entry.fileId ?? null)
      }
    }
  }

  private ensureBackgroundMirror(
    folderId: string,
    sharedFolderPath: string,
    relativePath: string,
    fileId: string | null = null
  ) {
    if (!this.yjsManager) return

    const session = this.yjsManager.getOrCreateSession(folderId, relativePath)
    if (!session) return

    const roomName = session.roomName
    const existing = this.backgroundMirrors.get(roomName)
    if (existing) {
      existing.folderId = folderId
      existing.sharedFolderPath = sharedFolderPath
      existing.relativePath = relativePath
      if (fileId) existing.fileId = fileId
      return
    }

    const mirror: BackgroundMirror = {
      folderId,
      sharedFolderPath,
      relativePath,
      fileId,
      session,
      pendingWriteTimer: null,
      onYTextChange: (_event, transaction) => {
        // Only mirror remote changes; local edits already flow through the active editor save path.
        if (transaction.local) return
        this.scheduleBackgroundMirrorWrite(roomName)
      },
      onSynced: ({ state }) => {
        if (!state) return
        this.scheduleBackgroundMirrorWrite(roomName)
      },
    }

    session.ytext.observe(mirror.onYTextChange)
    session.wsProvider.on('synced', mirror.onSynced)
    this.backgroundMirrors.set(roomName, mirror)

    if (session.wsProvider.isSynced) {
      this.scheduleBackgroundMirrorWrite(roomName)
    }
  }

  private scheduleBackgroundMirrorWrite(roomName: string) {
    const mirror = this.backgroundMirrors.get(roomName)
    if (!mirror) return

    if (mirror.pendingWriteTimer !== null) {
      window.clearTimeout(mirror.pendingWriteTimer)
    }

    mirror.pendingWriteTimer = window.setTimeout(() => {
      mirror.pendingWriteTimer = null
      void this.flushBackgroundMirrorWrite(roomName)
    }, 120)
  }

  private async flushBackgroundMirrorWrite(roomName: string) {
    const mirror = this.backgroundMirrors.get(roomName)
    if (!mirror) return

    const folderSession = this.folderSessions.get(mirror.folderId)
    if (!folderSession) return

    mirror.sharedFolderPath = folderSession.sharedFolderPath

    const mappedById = mirror.fileId ? folderSession.fileTree.getByFileId(mirror.fileId) : null
    if (mappedById && mappedById.relativePath !== mirror.relativePath) {
      debugLog(`[teams] Rebinding stale background mirror ${mirror.relativePath} -> ${mappedById.relativePath}`)
      this.removeBackgroundMirror(roomName, true)
      this.ensureBackgroundMirror(mirror.folderId, folderSession.sharedFolderPath, mappedById.relativePath, mirror.fileId)
      return
    }

    const currentRelativePath = mappedById?.relativePath ?? mirror.relativePath
    const currentEntry = mappedById?.entry ?? folderSession.fileTree.getFile(currentRelativePath)
    if (!currentEntry || currentEntry.type !== 'file' || currentEntry.syncMode !== 'crdt') {
      return
    }

    mirror.relativePath = currentRelativePath
    mirror.fileId = currentEntry.fileId ?? mirror.fileId

    const fullPath = resolveSharedPath(folderSession.sharedFolderPath, currentRelativePath)
    if (!fullPath) {
      console.warn('[teams] Blocked unsafe background mirror write', { roomName, currentRelativePath })
      return
    }

    const yjsContent = this.readSessionContent(mirror.session)

    await folderSession.watcher.runWithSuppressedPath(fullPath, async () => {
      const abstract = this.app.vault.getAbstractFileByPath(fullPath)
      if (abstract instanceof TFile) {
        const diskContent = await this.app.vault.cachedRead(abstract)
        if (diskContent !== yjsContent) {
          await this.app.vault.modify(abstract, yjsContent)
        }
        return
      }

      if (abstract) return

      const parentPath = fullPath.slice(0, Math.max(0, fullPath.lastIndexOf('/')))
      if (parentPath) {
        await this.ensureFolderPathExists(parentPath)
      }
      await this.app.vault.create(fullPath, yjsContent)
    })
  }

  private async ensureFolderPathExists(path: string) {
    const segments = path.split('/').filter(Boolean)
    let current = ''
    for (const segment of segments) {
      current = current ? `${current}/${segment}` : segment
      const existing = this.app.vault.getAbstractFileByPath(current)
      if (!existing) {
        await this.app.vault.createFolder(current)
      }
    }
  }

  private removeBackgroundMirror(roomName: string, destroySession: boolean) {
    const mirror = this.backgroundMirrors.get(roomName)
    if (mirror) {
      if (mirror.pendingWriteTimer !== null) {
        window.clearTimeout(mirror.pendingWriteTimer)
      }
      mirror.session.ytext.unobserve(mirror.onYTextChange)
      mirror.session.wsProvider.off('synced', mirror.onSynced)
      this.backgroundMirrors.delete(roomName)
    }

    if (destroySession && this.activeSession?.roomName !== roomName) {
      this.yjsManager?.destroySession(roomName)
    }
  }

  private removeBackgroundMirrorsForFolder(folderId: string, destroySessions: boolean) {
    const prefix = `folder:${folderId}:doc:`
    for (const roomName of [...this.backgroundMirrors.keys()]) {
      if (roomName.startsWith(prefix)) {
        this.removeBackgroundMirror(roomName, destroySessions)
      }
    }
  }

  private destroyAllBackgroundMirrors() {
    for (const roomName of [...this.backgroundMirrors.keys()]) {
      this.removeBackgroundMirror(roomName, false)
    }
  }

  private normalizePath(path: string): string {
    let normalized = path.trim()
    while (normalized.startsWith('/')) normalized = normalized.slice(1)
    while (normalized.endsWith('/')) normalized = normalized.slice(0, -1)
    return normalized
  }

  private isSharedConfigPath(path: string): boolean {
    return path === SHARED_CONFIG_FILENAME || path.endsWith(`/${SHARED_CONFIG_FILENAME}`)
  }

  private registerPendingRootRebind(oldPath: string, newPath: string): void {
    const oldRoot = this.normalizePath(oldPath)
    const newRoot = this.normalizePath(newPath)
    if (!oldRoot || !newRoot || oldRoot === newRoot) return

    this.pendingRootRebinds.set(oldRoot, {
      newPath: newRoot,
      expiresAt: Date.now() + 15_000,
    })
    debugLog(`[teams] Pending shared-root rebind ${oldRoot} -> ${newRoot}`)
  }

  private prunePendingRootRebinds(): void {
    const now = Date.now()
    for (const [oldRoot, pending] of this.pendingRootRebinds) {
      if (pending.expiresAt <= now) {
        this.pendingRootRebinds.delete(oldRoot)
      }
    }
  }

  private isRootRebindRename(oldPath: string, newPath: string): boolean {
    const normalizedOldPath = this.normalizePath(oldPath)
    const normalizedNewPath = this.normalizePath(newPath)
    if (!normalizedOldPath || !normalizedNewPath) return false

    this.prunePendingRootRebinds()

    for (const [oldRoot, pending] of this.pendingRootRebinds) {
      const newRoot = pending.newPath

      if (normalizedOldPath === oldRoot && normalizedNewPath === newRoot) {
        return true
      }

      if (normalizedOldPath.startsWith(`${oldRoot}/`)) {
        const suffix = normalizedOldPath.slice(oldRoot.length + 1)
        if (`${newRoot}/${suffix}` === normalizedNewPath) {
          return true
        }
      }

      if (normalizedNewPath.startsWith(`${newRoot}/`)) {
        const suffix = normalizedNewPath.slice(newRoot.length + 1)
        if (`${oldRoot}/${suffix}` === normalizedOldPath) {
          return true
        }
      }
    }

    return false
  }

  private refreshSharedFoldersOnRootRename(file: TAbstractFile, oldPath: string): void {
    const normalizedOldPath = this.normalizePath(oldPath)
    const normalizedNewPath = this.normalizePath(file.path)
    const wasKnownSharedRoot = this.sharedFolders.find(
      (sf) => this.normalizePath(sf.path) === normalizedOldPath
    )

    if (wasKnownSharedRoot) {
      this.registerPendingRootRebind(normalizedOldPath, normalizedNewPath)
    } else if (this.isSharedConfigPath(oldPath) && this.isSharedConfigPath(file.path)) {
      const oldRoot = oldPath.slice(0, Math.max(0, oldPath.lastIndexOf('/')))
      const newRoot = file.path.slice(0, Math.max(0, file.path.lastIndexOf('/')))
      this.registerPendingRootRebind(oldRoot, newRoot)
    }

    if (!wasKnownSharedRoot && !this.isSharedConfigPath(oldPath) && !this.isSharedConfigPath(file.path)) {
      return
    }

    void this.refreshSharedFolders()
  }

  /** Find the shared folder that contains the given path */
  private getSharedFolderForPath(filePath: string): SharedFolderLocation | null {
    const targetPath = this.normalizePath(filePath)
    for (const sf of this.sharedFolders) {
      const sharedPath = this.normalizePath(sf.path)
      if (targetPath === sharedPath || targetPath.startsWith(sharedPath + '/')) {
        return sf
      }
    }
    return null
  }

  /** Called when user opens a file — bind/unbind Yjs collaboration */
  private handleFileOpen(file: TFile) {
    if (!this.yjsManager) return

    // Check if this file is in a shared folder
    const sharedFolder = this.getSharedFolderForPath(file.path)

    if (!sharedFolder || !file.path.endsWith('.md')) {
      // Not in a shared folder or not a markdown file — remove collab extension
      this.unbindCollaboration()
      return
    }

    // Get relative path within the shared folder
    const relativePath = file.path.slice(sharedFolder.path.length + 1)
    const folderId = sharedFolder.config.folderId
    const folderSession = this.folderSessions.get(folderId)
    if (!folderSession) {
      console.warn(`[teams] No folder session for ${folderId}`)
      return
    }

    const nowIso = new Date().toISOString()
    const existingEntry = folderSession.fileTree.getFile(relativePath)
    const fileId = existingEntry?.fileId || crypto.randomUUID()

    if (!existingEntry) {
      folderSession.fileTree.addOrUpdateFile(relativePath, {
        fileId,
        path: relativePath,
        type: 'file',
        mtime: nowIso,
        size: file.stat.size,
        syncMode: 'crdt',
      })
    } else if (!existingEntry.fileId) {
      folderSession.fileTree.addOrUpdateFile(relativePath, {
        ...existingEntry,
        fileId,
        mtime: nowIso,
        size: file.stat.size,
      })
    }

    // Check if we already have a session for this exact file
    if (
      this.activeSession?.roomName === docRoomName(folderId, relativePath)
      && this.editorExtensions.length > 0
    ) {
      return // Already bound
    }

    // Unbind previous session's extension
    this.unbindCollaboration()

    // Create or get the session
    const session = this.yjsManager.getOrCreateSession(folderId, relativePath)

    if (!session) {
      console.warn(`[teams] Could not create session for ${file.path}`)
      return
    }
    this.ensureBackgroundMirror(folderId, sharedFolder.path, relativePath, fileId)

    // Wait for initial sync before binding the editor to avoid
    // cursor position errors (awareness arrives before doc content)
    if (session.wsProvider.isSynced) {
      this.bindSession(session, relativePath, file)
    } else {
      // Mark as pending so we don't start another session
      this.activeSession = session
      const onSync = ({ state }: { state: boolean }) => {
        if (!state) return
        session.wsProvider.off('synced', onSync)
        if (this.activeSession === session) {
          this.bindSession(session, relativePath, file)
        }
      }
      session.wsProvider.on('synced', onSync)
      // Handle race where sync completes before the listener is attached.
      if (session.wsProvider.isSynced) {
        session.wsProvider.off('synced', onSync)
        if (this.activeSession === session) {
          this.bindSession(session, relativePath, file)
        }
      }
    }
  }

  /** Delay binding slightly to avoid races with late file-load writes from Obsidian/plugins. */
  private scheduleFileBind(file: TFile) {
    this.clearPendingBind()

    const targetPath = file.path
    this.pendingBindTimeout = window.setTimeout(() => {
      this.pendingBindTimeout = null
      const activeFile = this.app.workspace.getActiveFile()
      if (activeFile instanceof TFile && activeFile.path === targetPath) {
        this.handleFileOpen(activeFile)
      }
    }, 120)
  }

  private clearPendingBind() {
    if (this.pendingBindTimeout !== null) {
      window.clearTimeout(this.pendingBindTimeout)
      this.pendingBindTimeout = null
    }
  }

  private readSessionContent(session: DocSession): string {
    // eslint-disable-next-line @typescript-eslint/no-base-to-string -- Y.Text#toString() returns document text.
    return session.ytext.toString()
  }

  /** Bind a synced Yjs session to the active editor */
  private bindSession(session: DocSession, relativePath: string, file: TFile) {
    this.activeSession = session

    const view = this.app.workspace.getActiveViewOfType(MarkdownView)
    const yjsContent = this.readSessionContent(session)
    void this.reconcileDiskWithYjs(file, yjsContent)

    if (view?.file?.path === file.path) {
      if (view.editor.getValue() !== yjsContent) {
        view.editor.setValue(yjsContent)
      }
    }

    this.editorExtensions.length = 0
    this.editorExtensions.push(session.extension)
    this.app.workspace.updateOptions()
    if (this.yjsManager) {
      this.updatePresenceDisplay(this.yjsManager.getUsers(session.roomName))
    }
    debugLog(`[teams] Bound collaboration for ${relativePath}`)
  }

  /** Keep local file content aligned with CRDT state so subsequent loads are never stale. */
  private async reconcileDiskWithYjs(file: TFile, yjsContent: string) {
    try {
      const sharedFolder = this.getSharedFolderForPath(file.path)
      if (!sharedFolder) return

      const folderSession = this.folderSessions.get(sharedFolder.config.folderId)
      if (!folderSession) return

      const relativePath = normalizeRelativePath(file.path.slice(sharedFolder.path.length + 1))
      if (!relativePath) {
        console.warn('[teams] Blocked reconcile for unsafe path', { filePath: file.path })
        return
      }

      const resolvedPath = resolveSharedPath(sharedFolder.path, relativePath)
      if (!resolvedPath || resolvedPath !== file.path) {
        console.warn('[teams] Blocked reconcile for non-canonical shared path', { filePath: file.path, relativePath })
        return
      }

      const currentEntry = folderSession.fileTree.getFile(relativePath)
      if (!currentEntry || currentEntry.type !== 'file' || currentEntry.syncMode !== 'crdt') return

      if (currentEntry.fileId) {
        const mapped = folderSession.fileTree.getByFileId(currentEntry.fileId)
        if (!mapped || mapped.relativePath !== relativePath) {
          debugLog(`[teams] Skipped reconcile due to stale mapping for ${relativePath}`)
          return
        }
      }

      const diskContent = await this.app.vault.cachedRead(file)
      if (diskContent === yjsContent) return
      await this.app.vault.modify(file, yjsContent)
      debugLog(`[teams] Reconciled disk content for ${file.path}`)
    } catch (err) {
      console.error(`[teams] Failed to reconcile disk content for ${file.path}:`, err)
    }
  }

  /** Remove the collaborative extension from the editor */
  private unbindCollaboration() {
    if (this.activeSession) {
      this.activeSession = null
      this.editorExtensions.length = 0
      this.app.workspace.updateOptions()
      this.statusUsers = []
      this.renderStatusBar()
    }
  }

  updateStatusBar(status: 'connected' | 'offline' | 'syncing' | 'auth-failed' | 'auth-expired') {
    if (status === 'auth-failed' || status === 'auth-expired') {
      this.authStatus = status
    } else {
      this.connectionStatus = status
      if (status === 'connected') {
        this.authStatus = 'ok'
      } else {
        this.statusUsers = []
      }
    }

    this.renderStatusBar()
  }

  updateKeyHealth(state: KeyHealthState) {
    this.keyHealth = state
    this.renderStatusBar()
  }

  private isStatusHealthy(): boolean {
    return this.authStatus === 'ok' && this.connectionStatus === 'connected' && this.keyHealth === 'healthy'
  }

  private getStatusDetails(): string {
    const details: string[] = []

    if (this.authStatus === 'auth-failed') {
      details.push('Reconnecting...')
    } else if (this.authStatus === 'auth-expired') {
      details.push('Session expired - right-click folder to fix')
    } else if (this.connectionStatus === 'offline') {
      details.push('Teams: offline')
    } else if (this.connectionStatus === 'syncing') {
      details.push('Teams: syncing...')
    } else {
      details.push('Teams: connected')
    }

    details.push(keyHealthLabel(this.keyHealth))

    if (this.connectionStatus === 'connected' && this.authStatus === 'ok') {
      if (this.statusUsers.length === 0) {
        details.push('Editors: just you')
      } else {
        const visibleNames = this.statusUsers.slice(0, 5).map((user) => user.name)
        const overflowCount = this.statusUsers.length - visibleNames.length
        const overflowLabel = overflowCount > 0 ? `, +${overflowCount} more` : ''
        details.push(`Editors: you + ${this.statusUsers.length} (${visibleNames.join(', ')}${overflowLabel})`)
      }
    }

    return details.join('\n')
  }

  private renderStatusBar() {
    if (!this.statusBarEl) return
    this.statusBarEl.empty()

    const details = this.getStatusDetails()
    const healthy = this.isStatusHealthy()
    const container = this.statusBarEl.createEl('span', {
      cls: 'obsidian-teams-status',
      attr: {
        role: 'button',
        tabindex: '0',
        title: details,
        'aria-label': details.replace(/\n/g, ', '),
      },
    })
    container.createEl('span', { cls: 'obsidian-teams-status-label', text: 'Collab' })
    const icon = container.createEl('span', {
      cls: `obsidian-teams-status-icon ${healthy ? 'is-healthy' : 'is-unhealthy'}`,
      attr: { 'aria-hidden': 'true' },
    })
    setIcon(icon, healthy ? 'check' : 'x')

    container.addEventListener('click', () => {
      new Notice(details)
    })
    container.addEventListener('keydown', (event: KeyboardEvent) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        new Notice(details)
      }
    })
  }

  private updatePresenceDisplay(users: Array<{ clientId: number; name: string; color: string }>) {
    this.statusUsers = users
    this.renderStatusBar()
  }

  private shouldShowFolderNotice(folderId: string): boolean {
    const now = Date.now()
    const last = this.folderNoticeAt.get(folderId) ?? 0
    if (now - last < this.folderNoticeCooldownMs) {
      return false
    }
    this.folderNoticeAt.set(folderId, now)
    return true
  }

  private getFolderDisplayName(folderId: string): string {
    const folder = this.sharedFolders.find((sf) => sf.config.folderId === folderId)
    return folder?.config.displayName || folder?.path || folderId
  }

  private isMembershipRemovedReason(reason: string): boolean {
    return reason.toLowerCase().includes('no active membership')
  }

  private async clearLocalFolderLink(folderId: string): Promise<SharedFolderLocation | null> {
    const sharedFolder = this.sharedFolders.find((sf) => sf.config.folderId === folderId) || null

    if (this.activeSession?.roomName.startsWith(`folder:${folderId}:doc:`)) {
      this.unbindCollaboration()
    }

    this.removeBackgroundMirrorsForFolder(folderId, true)
    this.yjsManager?.destroySessionsForFolder(folderId)

    const session = this.folderSessions.get(folderId)
    if (session) {
      session.fileTree.destroy()
      this.folderSessions.delete(folderId)
    }

    if (sharedFolder) {
      await removeSharedConfig(this.app.vault, sharedFolder.path)
    }

    await removeAccessToken(this, folderId)
    this.keyManager?.clearFolderKeys(folderId)
    await this.refreshSharedFolders()

    return sharedFolder
  }

  private async handleMembershipRemoved(folderId: string, reason: string) {
    if (this.membershipDetachInFlight.has(folderId)) {
      return
    }

    this.membershipDetachInFlight.add(folderId)
    try {
      const sharedFolder = await this.clearLocalFolderLink(folderId)
      const folderName = sharedFolder?.config.displayName || sharedFolder?.path || folderId

      if (this.shouldShowFolderNotice(folderId)) {
        new Notice(
          `You were removed from shared folder '${folderName}'. ` +
          `Local files are kept, but sync is now disconnected.`
        )
      }

      this.updateStatusBar('auth-expired')
      console.warn(`[teams] Detached folder ${folderId} after membership removal: ${reason}`)
    } finally {
      this.membershipDetachInFlight.delete(folderId)
    }
  }

  private async handleFolderAuthFailure(folderId: string, reason: string) {
    if (reason.includes('Failed to fetch') || reason.toLowerCase().includes('network')) {
      this.updateStatusBar('offline')
      const now = Date.now()
      if (now - this.lastNetworkNoticeAt >= this.networkNoticeCooldownMs) {
        this.lastNetworkNoticeAt = now
        new Notice('Teams cannot reach the server right now (network/cors). Retrying automatically.')
      }
      return
    }

    if (
      reason.includes('Folder key epoch is missing') ||
      reason.includes('rekey') ||
      reason.includes('envelope is unavailable')
    ) {
      this.updateKeyHealth('rekey-required')
      if (this.shouldShowFolderNotice(folderId)) {
        const folderName = this.getFolderDisplayName(folderId)
        new Notice(`Shared folder '${folderName}' needs owner rekey before syncing can continue.`)
      }
      return
    }

    if (this.isMembershipRemovedReason(reason)) {
      await this.handleMembershipRemoved(folderId, reason)
      return
    }

    if (reason.includes('Missing key') || reason.includes('missing')) {
      this.updateKeyHealth('missing-key')
    }

    this.updateStatusBar('auth-failed')
    try {
      await getOrRefreshToken(this, folderId, { forceRefresh: true })
      this.updateKeyHealth('healthy')
      this.updateStatusBar('syncing')
      return
    } catch {
      this.updateStatusBar('auth-expired')
    }

    if (this.shouldShowFolderNotice(folderId)) {
      const folderName = this.getFolderDisplayName(folderId)
      new Notice(
        `Shared folder '${folderName}' — access expired. ` +
        `Right-click the folder to re-share or request a new invite.`
      )
    }

    if (reason) {
      console.warn(`[teams] Authentication failed for folder ${folderId}: ${reason}`)
    }
  }

  private openExternalUrl(url: string): void {
    const opened = window.open(url, '_blank', 'noopener,noreferrer')
    if (!opened) {
      new Notice(`Open this URL manually in your browser: ${url}`)
    }
  }

  private effectiveHostedDisplayName(): string {
    return (
      this.settings.displayName ||
      this.settings.hostedAccountDisplayName ||
      this.settings.hostedAccountEmail.split('@')[0] ||
      'Collaborator'
    )
  }

  private isHostedMode(): boolean {
    return this.settings.deploymentMode === 'hosted-service'
  }

  private describeHostedRequestError(error: unknown, fallback: string): string {
    const message =
      typeof error === 'string'
        ? error
        : error instanceof Error
          ? error.message
          : ''
    const lower = message.toLowerCase()

    if (
      lower.includes('failed to fetch') ||
      lower.includes('err_name_not_resolved') ||
      lower.includes('name_not_resolved') ||
      lower.includes('enotfound')
    ) {
      return `Could not reach ${this.settings.serverUrl}. Check DNS/network/CORS and retry.`
    }

    return friendlyError(message || fallback)
  }

  private ensureHostedBillingSession(): Promise<string | null> {
    if (this.settings.hostedSessionToken) {
      return Promise.resolve(this.settings.hostedSessionToken)
    }

    new Notice('Hosted account verification required. Send and verify a code in settings first.')
    return Promise.resolve(null)
  }

  async startHostedAccountOtp(): Promise<boolean> {
    if (!this.isHostedMode()) {
      new Notice('Switch service mode to hosted service to link a hosted account')
      return false
    }

    const email = this.settings.hostedAccountEmail.trim().toLowerCase()
    if (!email) {
      new Notice('Hosted account email is required')
      return false
    }

    try {
      await startHostedOtp(
        this.settings.serverUrl,
        email
      )
      this.settings.hostedAccountEmail = email
      await this.saveSettings()
      new Notice(`Verification code sent to ${email}`)
      return true
    } catch (error) {
      const message = this.describeHostedRequestError(error, 'Failed to send verification code')
      new Notice(message)
      console.error('[teams] Hosted OTP start failed:', error)
      return false
    }
  }

  async verifyHostedAccountOtp(
    code: string,
    options: { silentSuccess?: boolean } = {}
  ): Promise<boolean> {
    if (!this.isHostedMode()) {
      new Notice('Switch service mode to hosted service to link a hosted account')
      return false
    }

    const email = this.settings.hostedAccountEmail.trim().toLowerCase()
    const trimmedCode = code.trim()
    if (!email) {
      new Notice('Hosted account email is required')
      return false
    }
    if (!trimmedCode) {
      new Notice('Verification code is required')
      return false
    }

    try {
      const session = await verifyHostedOtp(
        this.settings.serverUrl,
        email,
        trimmedCode,
        this.effectiveHostedDisplayName()
      )
      this.settings.hostedAccountEmail = session.account.email
      const linkedDisplayName =
        session.account.displayName || this.settings.displayName || this.effectiveHostedDisplayName()
      this.settings.displayName = linkedDisplayName
      this.settings.hostedAccountDisplayName = linkedDisplayName
      this.settings.hostedSessionToken = session.sessionToken
      this.settings.hostedSessionExpiresAt = session.expiresAt
      this.settings.hostedSubscriptionStatus = ''
      this.settings.hostedOtpCode = ''
      await this.saveSettings()
      await this.refreshHostedSubscriptionStatus()
      if (!options.silentSuccess) {
        new Notice(`Hosted account linked: ${session.account.email}`)
      }
      return true
    } catch (error) {
      const message = this.describeHostedRequestError(error, 'Failed to verify hosted account code')
      new Notice(message)
      console.error('[teams] Hosted OTP verification failed:', error)
      return false
    }
  }

  async clearHostedAccountLink(): Promise<void> {
    this.settings.hostedSessionToken = ''
    this.settings.hostedSessionExpiresAt = ''
    this.settings.hostedSubscriptionStatus = ''
    this.settings.hostedOtpCode = ''
    await this.saveSettings()
    new Notice('Hosted account link cleared')
  }

  async openHostedCheckout(): Promise<void> {
    if (!this.isHostedMode()) {
      new Notice('Switch service mode to hosted service to open managed billing')
      return
    }

    const knownStatus = this.settings.hostedSubscriptionStatus
    if (knownStatus && this.isHostedSubscriptionManagedInPortal(knownStatus)) {
      await this.openHostedBillingPortal()
      return
    }

    const hostedSessionToken = await this.ensureHostedBillingSession()
    if (!hostedSessionToken) return

    try {
      const checkout = await createHostedCheckoutSession(
        this.settings.serverUrl,
        hostedSessionToken,
        {
          successUrl: this.buildHostedBillingReturnUrl('success'),
          cancelUrl: this.buildHostedBillingReturnUrl('cancel'),
        }
      )
      this.openExternalUrl(checkout.checkoutUrl)
    } catch (error) {
      const message = this.describeHostedRequestError(error, 'Failed to start hosted checkout')
      new Notice(message)
      console.error('[teams] Hosted checkout failed:', error)
    }
  }

  async openHostedBillingPortal(): Promise<void> {
    if (!this.isHostedMode()) {
      new Notice('Switch service mode to hosted service to open managed billing')
      return
    }

    const hostedSessionToken = await this.ensureHostedBillingSession()
    if (!hostedSessionToken) return

    try {
      const portal = await createHostedPortalSession(
        this.settings.serverUrl,
        hostedSessionToken,
        {
          returnUrl: this.buildHostedBillingReturnUrl('return'),
        }
      )
      this.openExternalUrl(portal.portalUrl)
    } catch (error) {
      const message = this.describeHostedRequestError(error, 'Failed to open billing portal')
      new Notice(message)
      console.error('[teams] Hosted billing portal failed:', error)
    }
  }

  async loadSettings() {
    const loaded = (await this.loadData()) as Partial<ObsidianTeamsSettings> | null
    this.settings = Object.assign({}, DEFAULT_SETTINGS, loaded || {})
    let requiresSave = false

    if (this.settings.deploymentMode !== 'hosted-service' && this.settings.deploymentMode !== 'self-deployment') {
      const configuredUrl = (this.settings.serverUrl || '').trim().replace(/\/+$/, '')
      const defaultHostedUrl = DEFAULT_SERVER_URL.trim().replace(/\/+$/, '')
      this.settings.deploymentMode =
        configuredUrl.length > 0 && configuredUrl !== defaultHostedUrl ? 'self-deployment' : 'hosted-service'
    }

    if (!this.settings.displayName && this.settings.hostedAccountDisplayName) {
      this.settings.displayName = this.settings.hostedAccountDisplayName
    }
    if (this.settings.displayName) {
      this.settings.hostedAccountDisplayName = this.settings.displayName
    }

    if (this.settings.deploymentMode === 'hosted-service') {
      this.settings.serverUrl = DEFAULT_SERVER_URL
    } else {
      this.settings.serverUrl = (this.settings.serverUrl || '').trim()
      if (!this.settings.serverUrl) {
        this.settings.serverUrl = SELF_DEPLOY_DEFAULT_SERVER_URL
      }
    }

    this.settings.folderTokens = this.settings.folderTokens || {}
    this.settings.folderRefreshTokens = this.settings.folderRefreshTokens || {}

    if (!this.settings.onboardingComplete && this.settings.displayName.trim()) {
      this.settings.onboardingComplete = true
      requiresSave = true
    }

    if (requiresSave) {
      await this.saveSettings()
    }
  }

  async saveSettings() {
    setDebugLogging(this.settings.debugLogging)
    await this.saveData(this.settings)
  }

  private startSharedFolderBadgeObserver() {
    if (this.sharedFolderBadgeObserver) return

    this.sharedFolderBadgeObserver = new MutationObserver(() => {
      this.scheduleSharedFolderBadgeRefresh()
    })

    this.sharedFolderBadgeObserver.observe(document.body, {
      childList: true,
      subtree: true,
    })
    this.scheduleSharedFolderBadgeRefresh()
  }

  private stopSharedFolderBadgeObserver() {
    if (this.sharedFolderBadgeObserver) {
      this.sharedFolderBadgeObserver.disconnect()
      this.sharedFolderBadgeObserver = null
    }
    if (this.sharedFolderBadgeTimer !== null) {
      window.clearTimeout(this.sharedFolderBadgeTimer)
      this.sharedFolderBadgeTimer = null
    }
  }

  private scheduleSharedFolderBadgeRefresh() {
    if (this.sharedFolderBadgeTimer !== null) {
      window.clearTimeout(this.sharedFolderBadgeTimer)
    }
    this.sharedFolderBadgeTimer = window.setTimeout(() => {
      this.sharedFolderBadgeTimer = null
      this.renderSharedBadges()
    }, 80)
  }

  private renderSharedBadges() {
    this.renderSharedFolderBadges()
    this.renderSharedFileBadges()
    this.renderTabBadges()
    this.renderEditorTitleBadges()
  }

  private isSharedPath(path: string): boolean {
    return this.getSharedFolderForPath(path) !== null
  }

  private getElementPath(element: Element): string | null {
    const direct = element.getAttribute('data-path')
    if (direct) return this.normalizePath(direct)

    const owner = element.closest('[data-path]')
    const path = owner?.getAttribute('data-path')
    return path ? this.normalizePath(path) : null
  }

  private createSharedBadge(extraClass: string): HTMLElement {
    const badge = document.createElement('span')
    badge.className = `obsidian-teams-shared-badge ${extraClass}`
    badge.setAttribute('aria-label', 'Shared folder')
    badge.setAttribute('title', 'Shared folder')
    setIcon(badge, 'users')
    return badge
  }

  private updateSharedBadge(
    host: Element | null,
    isShared: boolean,
    badgeClass: string
  ) {
    if (!host) return
    if (!(host instanceof HTMLElement)) return
    const existingBadge = host.querySelector<HTMLElement>(`.${badgeClass}`)
    if (!isShared) {
      existingBadge?.remove()
      return
    }
    if (existingBadge) return
    host.appendChild(this.createSharedBadge(badgeClass))
  }

  private renderSharedFolderBadges() {
    const sharedPaths = new Set(this.sharedFolders.map((sf) => this.normalizePath(sf.path)))
    const folderTitles = document.querySelectorAll('.nav-folder-title')

    folderTitles.forEach((titleEl) => {
      const path = this.getElementPath(titleEl)
      const isSharedFolder = path ? sharedPaths.has(path) : false
      this.updateSharedBadge(titleEl, isSharedFolder, 'obsidian-teams-shared-badge-folder')
    })
  }

  private renderSharedFileBadges() {
    const fileTitles = document.querySelectorAll('.nav-file-title')
    fileTitles.forEach((titleEl) => {
      const path = this.getElementPath(titleEl)
      this.updateSharedBadge(titleEl, Boolean(path && this.isSharedPath(path)), 'obsidian-teams-shared-badge-file')
    })
  }

  private renderTabBadges() {
    const tabHeaders = document.querySelectorAll('.workspace-tab-header')
    tabHeaders.forEach((tabEl) => {
      const path = this.getElementPath(tabEl)
      const title = tabEl.querySelector<HTMLElement>('.workspace-tab-header-inner-title')
      this.updateSharedBadge(title, Boolean(path && this.isSharedPath(path)), 'obsidian-teams-shared-badge-tab')
    })
  }

  private renderEditorTitleBadges() {
    document
      .querySelectorAll('.obsidian-teams-shared-badge-header-title, .obsidian-teams-shared-badge-inline-title')
      .forEach((badge) => badge.remove())

    const activePath = this.app.workspace.getActiveFile()?.path
    if (!activePath) return

    const activeLeaf = document.querySelector('.workspace-leaf.mod-active')
    if (!activeLeaf) return

    const isShared = this.isSharedPath(activePath)
    const headerTitle = activeLeaf.querySelector('.view-header-title')
    const inlineTitle = activeLeaf.querySelector('.inline-title')

    this.updateSharedBadge(headerTitle, isShared, 'obsidian-teams-shared-badge-header-title')
    this.updateSharedBadge(inlineTitle, isShared, 'obsidian-teams-shared-badge-inline-title')
  }
}
