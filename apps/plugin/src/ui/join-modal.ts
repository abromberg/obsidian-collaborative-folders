import { App, Modal, Setting, Notice } from 'obsidian'
import type ObsidianTeamsPlugin from '../main'
import { decodeAccessToken, redeemInvite, storeAccessToken, storeRefreshToken } from '../utils/auth'
import { writeSharedConfig } from '../utils/dotfile'
import { type SharedFolderConfig } from '@obsidian-teams/shared'

export interface JoinSharedFolderResult {
  folderId: string
  folderName: string
}

export async function joinSharedFolderByInvite(
  app: App,
  plugin: ObsidianTeamsPlugin,
  inviteToken: string
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

  const folderPath = result.folderName
  const exists = await app.vault.adapter.exists(folderPath)
  if (!exists) {
    await app.vault.createFolder(folderPath)
  }

  const access = decodeAccessToken(result.accessToken)
  const config: SharedFolderConfig = {
    folderId: result.folderId,
    serverUrl: result.serverUrl,
    displayName: result.folderName,
    members: [{
      clientId,
      name: displayName || 'Anonymous',
      role: access?.role || 'editor',
    }],
    createdAt: new Date().toISOString(),
  }
  await writeSharedConfig(app.vault, folderPath, config)

  await plugin.refreshSharedFolders()

  return {
    folderId: result.folderId,
    folderName: result.folderName,
  }
}

export class JoinFolderModal extends Modal {
  private plugin: ObsidianTeamsPlugin
  private inviteToken = ''

  constructor(app: App, plugin: ObsidianTeamsPlugin, options: { inviteToken?: string } = {}) {
    super(app)
    this.plugin = plugin
    this.inviteToken = options.inviteToken?.trim() || ''
  }

  onOpen() {
    const { contentEl } = this
    contentEl.empty()

    contentEl.createEl('h2', { text: 'Join shared folder' })
    contentEl.createEl('p', {
      text: 'Paste the invite token you received from the folder owner.',
      cls: 'setting-item-description',
    })

    new Setting(contentEl)
      .setName('Invite token')
      .addText((text) => {
        text
          .setPlaceholder('Paste invite token here...')
          .setValue(this.inviteToken)
          .onChange((value) => {
            this.inviteToken = value.trim()
          })
      })

    new Setting(contentEl)
      .addButton((btn) => {
        btn
          .setButtonText('Join folder')
          .setCta()
          .onClick(async () => {
            await this.joinFolder()
          })
      })
  }

  private async joinFolder() {
    try {
      const result = await joinSharedFolderByInvite(this.app, this.plugin, this.inviteToken)
      new Notice(`Joined shared folder: ${result.folderName}`)
      this.close()
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      const lower = message.toLowerCase()
      let actionable = message
      if (lower.includes('subscription_inactive') || lower.includes('subscription is not active')) {
        actionable = 'Hosted subscription is inactive. Activate billing and retry join.'
      } else if (lower.includes('subscription_past_due')) {
        actionable = 'Hosted subscription is past due. Resolve billing before joining.'
      } else if (lower.includes('hosted_session_required')) {
        actionable = 'Hosted session missing. Add hosted account email and click Subscribe in plugin settings.'
      }
      new Notice(`Failed to join folder: ${actionable}`)
      console.error('[teams] Join error:', err)
    }
  }

  onClose() {
    const { contentEl } = this
    contentEl.empty()
  }
}
