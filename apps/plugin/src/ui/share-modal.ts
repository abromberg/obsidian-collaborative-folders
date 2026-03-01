import { App, Modal, Notice, Setting, TFolder } from 'obsidian'
import type ObsidianTeamsPlugin from '../main'
import {
  createInvite,
  getFolderRole,
  getOrRefreshToken,
  listFolderInvites,
  listFolderMembers,
  revokeFolderInvite,
  silentHostedRelink,
  storeAccessToken,
  storeRefreshToken,
} from '../utils/auth'
import { readSharedConfigAsync, writeSharedConfig } from '../utils/dotfile'
import { type FolderInviteRecord, type FolderMemberRecord, type SharedFolderConfig } from '@obsidian-teams/shared'
import { hasPendingOrActiveShares } from './share-state'
import { ConfirmModal } from './confirm-modal'
import {
  friendlyError,
  isHostedSessionError,
  rawErrorMessage,
} from '../utils/friendly-errors'

const DEFAULT_INVITE_EXPIRY_HOURS = 24 * 7
const DEFAULT_INVITE_MAX_USES = 1

export class ShareFolderModal extends Modal {
  private folder: TFolder
  private plugin: ObsidianTeamsPlugin
  private folderId: string | null = null
  private inviteLabel = ''
  private latestInviteToken: string | null = null
  private latestInviteLabel: string | null = null
  private latestInviteUrl: string | null = null
  private cachedMembers: FolderMemberRecord[] = []
  private cachedInvites: FolderInviteRecord[] = []
  private hasLoadedRemoteData = false
  private actionInFlight = false

  constructor(app: App, folder: TFolder, plugin: ObsidianTeamsPlugin) {
    super(app)
    this.folder = folder
    this.plugin = plugin
  }

  onOpen() {
    void this.render()
  }

  private isHostedMode(): boolean {
    return this.plugin.settings.deploymentMode === 'hosted-service'
  }

  private formatDate(value: string | null): string {
    if (!value) return 'n/a'
    const date = new Date(value)
    if (!Number.isFinite(date.getTime())) return value
    return date.toLocaleString()
  }

  private errorMessage(error: unknown, fallback: string): string {
    if (error instanceof Error && error.message) return error.message
    if (typeof error === 'string' && error) return error
    return fallback
  }

  private shortId(value: string): string {
    if (!value) return ''
    if (value.length <= 8) return value
    return `${value.slice(0, 4)}...${value.slice(-4)}`
  }

  private async resolveFolderContext(): Promise<{ folderId: string; existingConfig: SharedFolderConfig | null }> {
    const existingConfig = await readSharedConfigAsync(this.app.vault, this.folder.path)
    if (!this.folderId) {
      this.folderId = existingConfig?.folderId || crypto.randomUUID()
    }
    return { folderId: this.folderId, existingConfig }
  }

  private async loadRemoteData(folderId: string): Promise<string | null> {
    try {
      const [members, invites] = await Promise.all([
        listFolderMembers(this.plugin, folderId),
        listFolderInvites(this.plugin, folderId),
      ])
      this.cachedMembers = members
      this.cachedInvites = invites
      this.hasLoadedRemoteData = true
      return null
    } catch (err: unknown) {
      return friendlyError(this.errorMessage(err, 'Failed to load members and invites'))
    }
  }

  private async handleCreateInvite(): Promise<void> {
    if (this.actionInFlight) return
    this.actionInFlight = true
    await this.render({ useCachedRemoteData: true })

    let folderIdForRefresh: string | null = null
    let shouldRefreshRemoteData = false
    try {
      const { folderId, existingConfig } = await this.resolveFolderContext()
      folderIdForRefresh = folderId
      const { displayName, clientId, serverUrl } = this.plugin.settings
      const existingAccessToken = await getOrRefreshToken(this.plugin, folderId)
      const inviteLabel = this.inviteLabel.trim()

      const issueInvite = async () =>
        createInvite(
          serverUrl,
          folderId,
          this.folder.name,
          clientId,
          displayName || 'Anonymous',
          existingAccessToken,
          {
            hostedSessionToken: this.isHostedMode() ? this.plugin.settings.hostedSessionToken || undefined : undefined,
            inviteeLabel: inviteLabel || undefined,
            expiresInHours: DEFAULT_INVITE_EXPIRY_HOURS,
            maxUses: DEFAULT_INVITE_MAX_USES,
          }
        )

      let result
      try {
        result = await issueInvite()
      } catch (error) {
        const raw = rawErrorMessage(error, 'Request failed')
        if (!isHostedSessionError(raw) || !this.isHostedMode()) {
          throw error
        }

        const relinked = await silentHostedRelink(this.plugin, { force: true })
        if (!relinked) {
          throw error
        }
        result = await issueInvite()
      }

      if (result.ownerAccessToken) {
        await storeAccessToken(this.plugin, folderId, result.ownerAccessToken)
      }
      if (result.ownerRefreshToken) {
        await storeRefreshToken(this.plugin, folderId, result.ownerRefreshToken)
      }

      if (!existingConfig) {
        const config: SharedFolderConfig = {
          folderId,
          serverUrl: this.plugin.settings.serverUrl,
          displayName: this.folder.name,
          members: [
            {
              clientId,
              name: displayName || 'Anonymous',
              role: 'owner',
            },
          ],
          createdAt: new Date().toISOString(),
        }
        await writeSharedConfig(this.app.vault, this.folder.path, config)
        void this.plugin.refreshSharedFolders()
        this.hasLoadedRemoteData = false
      } else {
        shouldRefreshRemoteData = true
      }

      this.latestInviteToken = result.inviteToken
      this.latestInviteUrl = result.inviteUrl
      this.latestInviteLabel = inviteLabel || null
      new Notice('Invite generated')
    } catch (err: unknown) {
      const raw = rawErrorMessage(err, 'Request failed')
      new Notice(`Failed to generate invite: ${friendlyError(raw)}`)
      console.error('[teams] Share error:', err)
    } finally {
      this.actionInFlight = false
      await this.render({ useCachedRemoteData: true })

      // Refresh server-backed lists in the background for smoother invite UX.
      if (folderIdForRefresh && shouldRefreshRemoteData) {
        void this.loadRemoteData(folderIdForRefresh).then(() => this.render({ useCachedRemoteData: true }))
      }
    }
  }

  private handleRemoveMember(folderId: string, member: FolderMemberRecord): void {
    if (this.actionInFlight) return
    if (member.role === 'owner') return

    new ConfirmModal(
      this.app,
      'Remove member',
      `Remove '${member.displayName}' from this shared folder?\n\nThis revokes access immediately and rotates folder keys for future content.`,
      'Remove',
      async () => {
        this.actionInFlight = true
        try {
          await this.plugin.removeMemberWithRekey(folderId, member.clientId)
          this.hasLoadedRemoteData = false
          new Notice(`Removed member: ${member.displayName}`)
          await this.render()
        } catch (err: unknown) {
          const raw = rawErrorMessage(err, 'Request failed')
          new Notice(`Failed to remove member: ${friendlyError(raw)}`)
          console.error('[teams] Remove member error:', err)
        } finally {
          this.actionInFlight = false
        }
      },
      true
    ).open()
  }

  private handleRevokeInvite(folderId: string, invite: FolderInviteRecord): void {
    if (this.actionInFlight) return
    if (invite.status !== 'active') return

    const label = invite.inviteeLabel || this.shortId(invite.tokenHash)

    new ConfirmModal(
      this.app,
      'Revoke invite',
      `Revoke invite '${label}'?`,
      'Revoke',
      async () => {
        this.actionInFlight = true
        try {
          await revokeFolderInvite(this.plugin, folderId, invite.tokenHash)
          this.hasLoadedRemoteData = false
          new Notice(`Revoked invite: ${label}`)
          await this.render()
        } catch (err: unknown) {
          const raw = rawErrorMessage(err, 'Request failed')
          new Notice(`Failed to revoke invite: ${friendlyError(raw)}`)
          console.error('[teams] Revoke invite error:', err)
        } finally {
          this.actionInFlight = false
        }
      },
      true
    ).open()
  }

  private async clearSharedStateIfNoRecipients(folderId: string): Promise<boolean> {
    if (hasPendingOrActiveShares(this.cachedMembers, this.cachedInvites)) {
      return false
    }

    await this.plugin.clearOwnerShareState(folderId, this.folder.path)
    this.hasLoadedRemoteData = false
    this.latestInviteToken = null
    this.latestInviteLabel = null
    this.latestInviteUrl = null
    new Notice('No pending or active shares remain. Folder is no longer marked shared.')
    return true
  }

  private async render(options: { useCachedRemoteData?: boolean } = {}) {
    const { contentEl } = this
    contentEl.empty()
    contentEl.addClass('obsidian-teams-manage-modal')

    const { folderId, existingConfig } = await this.resolveFolderContext()
    const role = getFolderRole(this.plugin, folderId)
    const isShared = existingConfig !== null
    const isOwner = role === 'owner'
    const canBootstrap = !isShared
    const canCreateInvite = isOwner || canBootstrap

    contentEl.createEl('h2', { text: `Manage shared folder: ${this.folder.name}` })
    contentEl.createEl('p', {
      cls: 'setting-item-description',
      text: isShared
        ? 'Manage invites and members for this folder.'
        : 'Generate the first invite to initialize sharing for this folder.',
    })

    if (!isOwner && isShared) {
      contentEl.createEl('p', {
        cls: 'setting-item-description',
        text: 'You are not the owner for this folder. Owner-only actions are disabled.',
      })
    }

    contentEl.createEl('h3', { text: 'Create invite' })
    contentEl.createEl('p', {
      cls: 'setting-item-description obsidian-teams-manage-copy',
      text: 'Invites expire in 1 week and can only be used once.',
    })
    new Setting(contentEl)
      .setName('Invite label (optional)')
      .setDesc('Label is for your own tracking.')
      .addText((text) => {
        text.setPlaceholder('Andy')
        text.setValue(this.inviteLabel)
        text.onChange((value) => {
          this.inviteLabel = value
        })
      })

    new Setting(contentEl).addButton((btn) => {
      const baseText = canBootstrap ? 'Start sharing + generate invite' : 'Generate invite'
      btn
        .setButtonText(this.actionInFlight ? 'Generating invite...' : baseText)
        .setCta()
        .setDisabled(!canCreateInvite || this.actionInFlight)
        .onClick(() => {
          void this.handleCreateInvite()
        })
    })

    if (!canCreateInvite) {
      contentEl.createEl('p', {
        cls: 'setting-item-description',
        text: 'Only the folder owner can create new invites.',
      })
    }

    if (this.latestInviteToken) {
      const readyCard = contentEl.createDiv({ cls: 'obsidian-teams-invite-ready' })
      readyCard.createEl('div', {
        cls: 'obsidian-teams-invite-ready-title',
        text: this.latestInviteLabel
          ? `Invite ready for: ${this.latestInviteLabel}`
          : 'Invite ready',
      })
      readyCard.createEl('p', {
        cls: 'setting-item-description obsidian-teams-invite-ready-help',
        text: this.latestInviteLabel
          ? `Send this link to ${this.latestInviteLabel}. They'll be able to join with one click.`
          : "Send this link to your collaborator. They'll be able to join with one click.",
      })

      if (this.latestInviteUrl) {
        const urlSetting = new Setting(readyCard).setName('Redeem URL')
        urlSetting.settingEl.addClass('obsidian-teams-token-row')
        urlSetting.addText((text) => {
          text.setValue(this.latestInviteUrl || '')
          text.inputEl.setAttr('readonly', 'true')
        })
        urlSetting.addButton((btn) => {
          btn.setButtonText('Copy link').setCta().onClick(async () => {
            if (!this.latestInviteUrl) return
            await navigator.clipboard.writeText(this.latestInviteUrl)
            new Notice('Invite URL copied')
          })
        })
      }

      const disclosure = readyCard.createEl('details', { cls: 'obsidian-teams-token-disclosure' })
      disclosure.createEl('summary', { text: 'Show raw token (advanced)' })
      const disclosureBody = disclosure.createDiv()

      const tokenSetting = new Setting(disclosureBody).setName('Invite token')
      tokenSetting.settingEl.addClass('obsidian-teams-token-row')
      tokenSetting.addText((text) => {
        text.setValue(this.latestInviteToken || '')
        text.inputEl.setAttr('readonly', 'true')
      })
      tokenSetting.addButton((btn) => {
        btn.setButtonText('Copy').onClick(async () => {
          if (!this.latestInviteToken) return
          await navigator.clipboard.writeText(this.latestInviteToken)
          new Notice('Invite token copied')
        })
      })
    }

    if (!isShared || !isOwner) {
      new Setting(contentEl).addButton((btn) => {
        btn.setButtonText('Done').onClick(() => this.close())
      })
      return
    }

    contentEl.createEl('hr', { cls: 'obsidian-teams-manage-divider' })

    let loadError: string | null = null
    if (!options.useCachedRemoteData || !this.hasLoadedRemoteData) {
      loadError = await this.loadRemoteData(folderId)
    }
    const members = this.cachedMembers
    const invites = this.cachedInvites

    if (!loadError) {
      const wasCleared = await this.clearSharedStateIfNoRecipients(folderId)
      if (wasCleared) {
        await this.render({ useCachedRemoteData: true })
        return
      }
    }

    contentEl.createEl('h3', { text: 'Members' })
    if (loadError) {
      contentEl.createEl('p', {
        cls: 'setting-item-description',
        text: loadError,
      })
    } else if (members.length === 0) {
      contentEl.createEl('p', {
        cls: 'setting-item-description',
        text: 'No members found.',
      })
    } else {
      for (const member of members) {
        const summary =
          `${member.role} · ${this.shortId(member.clientId)} · joined ${this.formatDate(member.joinedAt)}`
        const title = member.inviteeLabel
          ? `${member.inviteeLabel} (${member.displayName})`
          : member.displayName
        const row = new Setting(contentEl)
          .setName(title)
          .setDesc(summary)
        row.settingEl.addClass('obsidian-teams-manage-row')

        if (member.role !== 'owner') {
          row.addButton((btn) => {
            btn
              .setButtonText('Remove')
              .setDisabled(this.actionInFlight)
              .onClick(() => {
                void this.handleRemoveMember(folderId, member)
              })
          })
        }
      }
    }

    contentEl.createEl('h3', { text: 'Pending invites' })
    if (loadError) {
      contentEl.createEl('p', {
        cls: 'setting-item-description',
        text: 'Invite list unavailable while loading failed.',
      })
    } else {
      const pending = invites.filter((invite) => invite.status === 'active')
      if (pending.length === 0) {
        contentEl.createEl('p', {
          cls: 'setting-item-description',
          text: 'No pending invites.',
        })
      } else {
        for (const invite of pending) {
          const label = invite.inviteeLabel || this.shortId(invite.tokenHash)
          const desc = `${invite.status} · created ${this.formatDate(invite.createdAt)}`
          const row = new Setting(contentEl)
            .setName(label)
            .setDesc(desc)
          row.settingEl.addClass('obsidian-teams-manage-row')

          if (invite.status === 'active') {
            row.addButton((btn) => {
              btn
                .setButtonText('Revoke')
                .setDisabled(this.actionInFlight)
                .onClick(() => {
                  void this.handleRevokeInvite(folderId, invite)
                })
            })
          }
        }
      }
    }

    new Setting(contentEl).addButton((btn) => {
      btn.setButtonText('Done').onClick(() => this.close())
    })
  }

  onClose() {
    const { contentEl } = this
    contentEl.empty()
  }
}
