import { App, Notice, PluginSettingTab, Setting, requestUrl } from 'obsidian'
import { DEFAULT_SERVER_URL } from '@obsidian-teams/shared'
import type ObsidianTeamsPlugin from './main'
import { JoinFolderModal } from './ui/join-modal'

export const SELF_DEPLOY_DEFAULT_SERVER_URL = 'http://localhost:1234'

export type DeploymentMode = 'hosted-service' | 'self-deployment'

export interface ObsidianTeamsSettings {
  deploymentMode: DeploymentMode
  serverUrl: string
  displayName: string
  onboardingComplete: boolean
  pendingInviteToken: string
  clientId: string
  debugLogging: boolean
  hostedAccountEmail: string
  hostedAccountDisplayName: string
  hostedOtpCode: string
  hostedSessionToken: string
  hostedSessionExpiresAt: string
  hostedSubscriptionStatus: string
  /** Map of folderId → access JWT */
  folderTokens: Record<string, string>
  /** Map of folderId → rotating refresh token */
  folderRefreshTokens: Record<string, string>
}

export const DEFAULT_SETTINGS: ObsidianTeamsSettings = {
  deploymentMode: 'hosted-service',
  serverUrl: DEFAULT_SERVER_URL,
  displayName: '',
  onboardingComplete: false,
  pendingInviteToken: '',
  clientId: '',
  debugLogging: false,
  hostedAccountEmail: '',
  hostedAccountDisplayName: '',
  hostedOtpCode: '',
  hostedSessionToken: '',
  hostedSessionExpiresAt: '',
  hostedSubscriptionStatus: '',
  folderTokens: {},
  folderRefreshTokens: {},
}

function normalizeUrl(value: string): string {
  return value.trim().replace(/\/+$/, '')
}

export class ObsidianTeamsSettingTab extends PluginSettingTab {
  plugin: ObsidianTeamsPlugin
  private refreshingHostedSubscriptionStatus = false

  constructor(app: App, plugin: ObsidianTeamsPlugin) {
    super(app, plugin)
    this.plugin = plugin
  }

  private isHostedMode(): boolean {
    return this.plugin.settings.deploymentMode === 'hosted-service'
  }

  private async saveAndRefresh(): Promise<void> {
    await this.plugin.saveSettings()
    this.display()
  }

  private async switchMode(nextMode: DeploymentMode): Promise<void> {
    const previousMode = this.plugin.settings.deploymentMode
    if (previousMode === nextMode) return

    this.plugin.settings.deploymentMode = nextMode

    const currentUrl = normalizeUrl(this.plugin.settings.serverUrl || '')
    const defaultHostedUrl = normalizeUrl(DEFAULT_SERVER_URL)

    if (nextMode === 'hosted-service') {
      this.plugin.settings.serverUrl = DEFAULT_SERVER_URL
    } else if (currentUrl === defaultHostedUrl) {
      this.plugin.settings.serverUrl = SELF_DEPLOY_DEFAULT_SERVER_URL
    }

    await this.saveAndRefresh()
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

  private renderPendingInviteBanner(containerEl: HTMLElement): void {
    const pendingToken = this.plugin.settings.pendingInviteToken.trim()
    if (!pendingToken) return

    const banner = containerEl.createDiv({ cls: 'obsidian-teams-pending-invite-banner' })
    banner.createEl('p', {
      text: 'You have a pending folder invite. Complete setup below, then click "join now".',
    })

    new Setting(banner)
      .addButton((btn) => {
        btn.setButtonText('Join now').setCta().onClick(() => {
          new JoinFolderModal(this.app, this.plugin, { inviteToken: pendingToken }).open()
        })
      })
      .addButton((btn) => {
        btn.setButtonText('Dismiss').onClick(async () => {
          this.plugin.settings.pendingInviteToken = ''
          await this.saveAndRefresh()
        })
      })
  }

  private renderIdentitySettings(containerEl: HTMLElement): void {
    new Setting(containerEl)
      .setName('Display name')
      .setDesc('Your name shown to collaborators on cursor labels')
      .addText((text) =>
        text
          .setPlaceholder('Your name')
          .setValue(this.plugin.settings.displayName)
          .onChange(async (value) => {
            this.plugin.settings.displayName = value
            this.plugin.settings.hostedAccountDisplayName = value
            await this.plugin.saveSettings()
          })
      )

    new Setting(containerEl)
      .setName('Client ID')
      .setDesc('Unique identifier for this vault (auto-generated)')
      .addText((text) => {
        text.setValue(this.plugin.settings.clientId)
        text.inputEl.setAttr('readonly', 'true')
        text.inputEl.addClass('obsidian-teams-readonly-input')
      })
  }

  private renderHostedSettings(containerEl: HTMLElement): void {
    new Setting(containerEl)
      .setName('Hosted service (collaborativefolders.com)')
      .setHeading()
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text:
        'Managed hosted service flow. Verify your email with a one-time code before billing actions.',
    })

    new Setting(containerEl)
      .setName('Hosted account email')
      .setDesc('Used for one-time-code verification before opening checkout or billing portal.')
      .addText((text) =>
        text
          .setPlaceholder('Email address')
          .setValue(this.plugin.settings.hostedAccountEmail)
          .onChange(async (value) => {
            const previousEmail = this.plugin.settings.hostedAccountEmail.trim().toLowerCase()
            const nextEmail = value.trim().toLowerCase()
            this.plugin.settings.hostedAccountEmail = nextEmail

            // Changing account email invalidates the current hosted session context.
            if (nextEmail !== previousEmail) {
              this.plugin.settings.hostedSessionToken = ''
              this.plugin.settings.hostedSessionExpiresAt = ''
              this.plugin.settings.hostedSubscriptionStatus = ''
              this.plugin.settings.hostedOtpCode = ''
            }

            await this.plugin.saveSettings()
          })
      )

    new Setting(containerEl)
      .setName('Verification code')
      .setDesc('Enter the email code, then verify to create a hosted session.')
      .addText((text) =>
        text
          .setPlaceholder('123456')
          .setValue(this.plugin.settings.hostedOtpCode)
          .onChange(async (value) => {
            this.plugin.settings.hostedOtpCode = value.trim()
            await this.plugin.saveSettings()
          })
      )
      .addButton((btn) => {
        btn.setButtonText('Send code').onClick(async () => {
          const sent = await this.plugin.startHostedAccountOtp()
          if (sent) this.display()
        })
      })
      .addButton((btn) => {
        btn.setButtonText('Verify').setCta().onClick(async () => {
          const verified = await this.plugin.verifyHostedAccountOtp(this.plugin.settings.hostedOtpCode)
          if (verified) this.display()
        })
      })

    const hasHostedSession = Boolean(this.plugin.settings.hostedSessionToken)
    const hasResolvedSubscriptionStatus = this.plugin.settings.hostedSubscriptionStatus.trim().length > 0
    const subscriptionStatus = hasResolvedSubscriptionStatus
      ? this.plugin.settings.hostedSubscriptionStatus
      : 'unknown'
    const subscriptionActive = hasResolvedSubscriptionStatus && this.isHostedSubscriptionActive(subscriptionStatus)
    const subscriptionManagedInPortal =
      hasResolvedSubscriptionStatus && this.isHostedSubscriptionManagedInPortal(subscriptionStatus)
    const statusMessage = hasHostedSession
      ? subscriptionActive
        ? 'Hosted account session is active. Subscription is active.'
        : hasResolvedSubscriptionStatus
          ? `Hosted account session is active. Subscription status: ${subscriptionStatus}.`
          : 'Hosted account session is active. Checking subscription status...'
      : 'No hosted session yet. Verify your email above to get started.'
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: statusMessage,
    })

    if (
      hasHostedSession &&
      !this.plugin.settings.hostedSubscriptionStatus &&
      !this.refreshingHostedSubscriptionStatus
    ) {
      this.refreshingHostedSubscriptionStatus = true
      void this.plugin.refreshHostedSubscriptionStatus().finally(() => {
        this.refreshingHostedSubscriptionStatus = false
        this.display()
      })
    }

    new Setting(containerEl)
      .setName('Hosted billing')
      .setDesc(
        hasHostedSession && !hasResolvedSubscriptionStatus
          ? 'Checking subscription status...'
          : subscriptionManagedInPortal
            ? 'Manage your billing subscription.'
            : hasHostedSession
              ? 'Start your hosted subscription.'
              : 'Verify your email first, then start your subscription.'
      )
      .addButton((btn) => {
        if (hasHostedSession && !hasResolvedSubscriptionStatus) {
          btn.setButtonText('Checking...').setDisabled(true)
          return
        }
        if (subscriptionManagedInPortal) {
          btn.setButtonText('Manage billing').onClick(async () => {
            await this.plugin.openHostedBillingPortal()
          })
          return
        }
        btn
          .setButtonText('Subscribe ($9/month)')
          .setCta()
          .onClick(async () => {
            await this.plugin.openHostedCheckout()
          })
      })
  }

  private renderSelfHostedSettings(containerEl: HTMLElement): void {
    new Setting(containerEl).setName('Self-deployment').setHeading()
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text:
        'Connect directly to your own server. Hosted account linking and billing controls are hidden in this mode.',
    })

    new Setting(containerEl)
      .setName('Self-hosted server URL')
      .setDesc('Base URL for your deployment (for example: http://localhost:1234 or https://teams.yourdomain.com).')
      .addText((text) =>
        text
          .setPlaceholder(SELF_DEPLOY_DEFAULT_SERVER_URL)
          .setValue(this.plugin.settings.serverUrl)
          .onChange(async (value) => {
            this.plugin.settings.serverUrl = value.trim()
            await this.plugin.saveSettings()
          })
      )
      .addButton((btn) => {
        btn.setButtonText('Use localhost').onClick(async () => {
          this.plugin.settings.serverUrl = SELF_DEPLOY_DEFAULT_SERVER_URL
          await this.saveAndRefresh()
        })
      })

    new Setting(containerEl)
      .setName('Test connection')
      .setDesc('Verify your server is reachable')
      .addButton((btn) => {
        btn.setButtonText('Test').onClick(async () => {
          const serverUrl = normalizeUrl(this.plugin.settings.serverUrl || '')
          if (!serverUrl) {
            new Notice('Set a server URL first')
            return
          }

          btn.setButtonText('Testing...')
          btn.setDisabled(true)
          try {
            const response = await requestUrl({
              url: `${serverUrl}/health`,
              method: 'GET',
              throw: false,
            })

            const payload = response.json as { status?: string; version?: string } | undefined
            if (response.status >= 200 && response.status < 300 && payload?.status === 'ok') {
              const versionSuffix = payload.version ? ` (v${payload.version})` : ''
              new Notice(`Connected to server${versionSuffix}`)
            } else {
              new Notice('Server responded but returned unexpected data')
            }
          } catch {
            new Notice(`Cannot reach ${serverUrl}. Check the URL and ensure the server is running.`)
          } finally {
            btn.setButtonText('Test')
            btn.setDisabled(false)
          }
        })
      })
  }

  display(): void {
    const { containerEl } = this
    containerEl.empty()

    new Setting(containerEl).setName('Overview').setHeading()
    this.renderPendingInviteBanner(containerEl)

    new Setting(containerEl)
      .setName('Service mode')
      .setDesc('Choose between the managed hosted service and your own self-deployed server.')
      .addDropdown((dropdown) => {
        dropdown
          .addOption('hosted-service', 'Hosted service (recommended)')
          .addOption('self-deployment', 'Self-deployment')
          .setValue(this.plugin.settings.deploymentMode)
          .onChange(async (value) => {
            const nextMode: DeploymentMode =
              value === 'self-deployment' ? 'self-deployment' : 'hosted-service'
            await this.switchMode(nextMode)
          })
      })

    this.renderIdentitySettings(containerEl)

    if (this.isHostedMode()) {
      this.renderHostedSettings(containerEl)
    } else {
      this.renderSelfHostedSettings(containerEl)
    }
  }
}
