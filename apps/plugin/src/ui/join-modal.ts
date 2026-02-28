import { App, Modal, Notice, Setting, TFolder } from 'obsidian'
import type { InvitePreviewResponse, SharedFolderConfig } from '@obsidian-teams/shared'
import type ObsidianTeamsPlugin from '../main'
import {
  decodeAccessToken,
  previewInvite,
  redeemInvite,
  silentHostedRelink,
  storeAccessToken,
  storeRefreshToken,
} from '../utils/auth'
import { readSharedConfigAsync, writeSharedConfig } from '../utils/dotfile'
import {
  friendlyError,
  isConfigError,
  isHostedSessionError,
  rawErrorMessage,
} from '../utils/friendly-errors'

export interface JoinSharedFolderResult {
  folderId: string
  folderName: string
}

function normalizeFolderPath(value: string): string {
  return value
    .split('/')
    .map((segment) => segment.trim())
    .filter(Boolean)
    .join('/')
}

async function ensureFolderHierarchy(app: App, targetPath: string): Promise<void> {
  const segments = normalizeFolderPath(targetPath).split('/').filter(Boolean)
  let currentPath = ''

  for (const segment of segments) {
    currentPath = currentPath ? `${currentPath}/${segment}` : segment
    const existing = app.vault.getAbstractFileByPath(currentPath)
    if (!existing) {
      await app.vault.createFolder(currentPath)
      continue
    }
    if (!(existing instanceof TFolder)) {
      throw new Error(`Path '${currentPath}' already exists and is not a folder`)
    }
  }
}

async function assertNoSharedFolderConflict(
  app: App,
  targetPath: string,
  expectedFolderId: string
): Promise<void> {
  const existingConfig = await readSharedConfigAsync(app.vault, targetPath)
  if (existingConfig && existingConfig.folderId !== expectedFolderId) {
    throw new Error('Target path already contains a different shared folder')
  }
}

export async function joinSharedFolderByInvite(
  app: App,
  plugin: ObsidianTeamsPlugin,
  inviteToken: string,
  folderPath?: string
): Promise<JoinSharedFolderResult> {
  const normalizedInviteToken = inviteToken.trim()
  if (!normalizedInviteToken) {
    throw new Error('Please enter an invite token')
  }

  const { clientId, displayName, serverUrl } = plugin.settings
  const hostedSessionToken =
    plugin.settings.deploymentMode === 'hosted-service'
      ? plugin.settings.hostedSessionToken || undefined
      : undefined

  const result = await redeemInvite(
    serverUrl,
    normalizedInviteToken,
    clientId,
    displayName || 'Anonymous',
    hostedSessionToken
  )

  await storeAccessToken(plugin, result.folderId, result.accessToken)
  await storeRefreshToken(plugin, result.folderId, result.refreshToken)

  const targetPath = normalizeFolderPath(folderPath || result.folderName)
  if (!targetPath) {
    throw new Error('Choose where to place the shared folder in your vault')
  }

  await ensureFolderHierarchy(app, targetPath)
  await assertNoSharedFolderConflict(app, targetPath, result.folderId)

  const targetFolder = app.vault.getAbstractFileByPath(targetPath)
  if (!targetFolder || !(targetFolder instanceof TFolder)) {
    throw new Error(`Unable to create target folder at '${targetPath}'`)
  }

  const access = decodeAccessToken(result.accessToken)
  const config: SharedFolderConfig = {
    folderId: result.folderId,
    serverUrl: result.serverUrl,
    displayName: result.folderName,
    members: [
      {
        clientId,
        name: displayName || 'Anonymous',
        role: access?.role || 'editor',
      },
    ],
    createdAt: new Date().toISOString(),
  }
  await writeSharedConfig(app.vault, targetPath, config)

  await plugin.refreshSharedFolders()

  return {
    folderId: result.folderId,
    folderName: result.folderName,
  }
}

export class JoinFolderModal extends Modal {
  private plugin: ObsidianTeamsPlugin
  private inviteToken = ''
  private folderPath = ''
  private preview: InvitePreviewResponse | null = null
  private actionInFlight = false
  private errorMessage = ''

  constructor(app: App, plugin: ObsidianTeamsPlugin, options: { inviteToken?: string } = {}) {
    super(app)
    this.plugin = plugin
    this.inviteToken = options.inviteToken?.trim() || ''
  }

  onOpen() {
    this.render()
    if (this.inviteToken) {
      void this.previewToken()
    }
  }

  private render() {
    const { contentEl } = this
    contentEl.empty()
    contentEl.addClass('obsidian-teams-join-modal')

    contentEl.createEl('h2', { text: 'Join shared folder' })

    if (!this.preview) {
      contentEl.createEl('p', {
        text: 'Paste the invite token you received from the folder owner.',
        cls: 'setting-item-description',
      })
    } else {
      contentEl.createEl('p', {
        text: `Ready to join '${this.preview.folderName}'. Choose where it should live in your vault.`,
        cls: 'setting-item-description',
      })
    }

    if (this.errorMessage) {
      contentEl.createEl('p', {
        cls: 'setting-item-description obsidian-teams-join-error',
        text: this.errorMessage,
      })
    }

    new Setting(contentEl)
      .setName('Invite token')
      .addText((text) => {
        text
          .setPlaceholder('Paste invite token here...')
          .setValue(this.inviteToken)
          .setDisabled(this.actionInFlight || Boolean(this.preview))
          .onChange((value) => {
            this.inviteToken = value.trim()
          })
      })

    if (!this.preview) {
      new Setting(contentEl).addButton((btn) => {
        btn
          .setButtonText(this.actionInFlight ? 'Previewing...' : 'Preview')
          .setCta()
          .setDisabled(this.actionInFlight || !this.inviteToken.trim())
          .onClick(async () => {
            await this.previewToken()
          })
      })
      return
    }

    const metadataBits: string[] = []
    if (this.preview.ownerDisplayName) {
      metadataBits.push(`Owner: ${this.preview.ownerDisplayName}`)
    }
    if (this.preview.expiresAt) {
      const expiresDate = new Date(this.preview.expiresAt)
      metadataBits.push(`Expires: ${Number.isFinite(expiresDate.getTime()) ? expiresDate.toLocaleString() : this.preview.expiresAt}`)
    }
    metadataBits.push(`Uses remaining: ${this.preview.remainingUses}`)

    contentEl.createEl('p', {
      cls: 'setting-item-description',
      text: metadataBits.join(' · '),
    })

    new Setting(contentEl)
      .setName('Folder location')
      .setDesc('Path in your vault where the shared folder will appear')
      .addText((text) => {
        text
          .setPlaceholder(this.preview?.folderName || 'Shared Folder')
          .setValue(this.folderPath)
          .setDisabled(this.actionInFlight)
          .onChange((value) => {
            this.folderPath = value
          })
      })

    new Setting(contentEl)
      .addButton((btn) => {
        btn
          .setButtonText('Use different token')
          .setDisabled(this.actionInFlight)
          .onClick(() => {
            this.preview = null
            this.errorMessage = ''
            this.render()
          })
      })
      .addButton((btn) => {
        btn
          .setButtonText(this.actionInFlight ? 'Joining...' : 'Join folder')
          .setCta()
          .setDisabled(this.actionInFlight || !normalizeFolderPath(this.folderPath))
          .onClick(async () => {
            await this.joinFolder()
          })
      })
  }

  private async previewToken(): Promise<void> {
    const token = this.inviteToken.trim()
    if (!token || this.actionInFlight) return

    this.actionInFlight = true
    this.errorMessage = ''
    this.render()

    try {
      this.preview = await previewInvite(this.plugin.settings.serverUrl, token)
      if (!normalizeFolderPath(this.folderPath)) {
        this.folderPath = this.preview.folderName
      }
    } catch (err: unknown) {
      const raw = rawErrorMessage(err, 'Unable to preview invite')
      this.preview = null
      this.errorMessage = friendlyError(raw)
    } finally {
      this.actionInFlight = false
      if (this.contentEl.isConnected) {
        this.render()
      }
    }
  }

  private async joinOnce(): Promise<JoinSharedFolderResult> {
    return joinSharedFolderByInvite(this.app, this.plugin, this.inviteToken, this.folderPath)
  }

  private async joinWithRetry(): Promise<JoinSharedFolderResult> {
    try {
      return await this.joinOnce()
    } catch (error) {
      const raw = rawErrorMessage(error, 'Join failed')
      if (!isHostedSessionError(raw)) {
        throw error
      }

      const relinked = await silentHostedRelink(this.plugin, { force: true })
      if (!relinked) {
        throw error
      }
      return this.joinOnce()
    }
  }

  private async persistPendingInvite(): Promise<void> {
    const token = this.inviteToken.trim()
    if (!token) return
    this.plugin.settings.pendingInviteToken = token
    await this.plugin.saveSettings()
  }

  private openPluginSettings(): void {
    const settingsRoot = (this.app as unknown as {
      setting?: { open?: () => void; openTabById?: (id: string) => void }
    }).setting
    settingsRoot?.open?.()
    settingsRoot?.openTabById?.('collaborative-folders')
  }

  private async joinFolder() {
    if (this.actionInFlight) return

    this.actionInFlight = true
    this.errorMessage = ''
    this.render()

    try {
      const result = await this.joinWithRetry()
      if (this.plugin.settings.pendingInviteToken) {
        this.plugin.settings.pendingInviteToken = ''
        await this.plugin.saveSettings()
      }
      new Notice(`Joined shared folder: ${result.folderName}`)
      this.close()
    } catch (err: unknown) {
      const raw = rawErrorMessage(err, 'Unknown error')
      const message = friendlyError(raw)

      if (isConfigError(raw)) {
        await this.persistPendingInvite()
        this.close()
        this.openPluginSettings()
        new Notice('Configure your account to join the shared folder. Your invite is saved.')
      } else {
        this.errorMessage = message
        new Notice(`Failed to join folder: ${message}`)
      }
      console.error('[teams] Join error:', err)
    } finally {
      this.actionInFlight = false
      if (this.contentEl.isConnected) {
        this.render()
      }
    }
  }

  onClose() {
    const { contentEl } = this
    contentEl.empty()
  }
}
