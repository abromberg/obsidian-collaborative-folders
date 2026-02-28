import { App, PluginSettingTab, Setting } from 'obsidian'
import { DEFAULT_SERVER_URL } from '@obsidian-teams/shared'
import type ObsidianTeamsPlugin from './main'

export const SELF_DEPLOY_DEFAULT_SERVER_URL = 'http://localhost:1234'

export type DeploymentMode = 'hosted-service' | 'self-deployment'

export interface ObsidianTeamsSettings {
  deploymentMode: DeploymentMode
  serverUrl: string
  displayName: string
  clientId: string
  hostedAccountEmail: string
  hostedAccountDisplayName: string
  hostedSessionToken: string
  hostedSessionExpiresAt: string
  /** Map of folderId → access JWT */
  folderTokens: Record<string, string>
  /** Map of folderId → rotating refresh token */
  folderRefreshTokens: Record<string, string>
}

export const DEFAULT_SETTINGS: ObsidianTeamsSettings = {
  deploymentMode: 'hosted-service',
  serverUrl: DEFAULT_SERVER_URL,
  displayName: '',
  clientId: '',
  hostedAccountEmail: '',
  hostedAccountDisplayName: '',
  hostedSessionToken: '',
  hostedSessionExpiresAt: '',
  folderTokens: {},
  folderRefreshTokens: {},
}

function normalizeUrl(value: string): string {
  return value.trim().replace(/\/+$/, '')
}

export class ObsidianTeamsSettingTab extends PluginSettingTab {
  plugin: ObsidianTeamsPlugin

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
        text.inputEl.style.opacity = '0.7'
      })
  }

  private renderHostedSettings(containerEl: HTMLElement): void {
    containerEl.createEl('h3', { text: 'Hosted service (collaborativefolders.com)' })
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text:
        'Managed hosted service flow. Subscription actions automatically create/refresh your hosted account session.',
    })

    new Setting(containerEl)
      .setName('Hosted account email')
      .setDesc('Used by Subscribe/Manage billing to create or refresh your hosted account session.')
      .addText((text) =>
        text
          .setPlaceholder('name@example.com')
          .setValue(this.plugin.settings.hostedAccountEmail)
          .onChange(async (value) => {
            const previousEmail = this.plugin.settings.hostedAccountEmail.trim().toLowerCase()
            const nextEmail = value.trim().toLowerCase()
            this.plugin.settings.hostedAccountEmail = nextEmail

            // Changing account email invalidates the current hosted session context.
            if (nextEmail !== previousEmail) {
              this.plugin.settings.hostedSessionToken = ''
              this.plugin.settings.hostedSessionExpiresAt = ''
            }

            await this.plugin.saveSettings()
          })
      )

    const hasHostedSession = Boolean(this.plugin.settings.hostedSessionToken)
    const statusMessage = hasHostedSession
      ? 'Hosted account session is active.'
      : 'No hosted session yet. Click Subscribe to begin; account session is created automatically.'
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: statusMessage,
    })

    new Setting(containerEl)
      .setName('Hosted billing')
      .setDesc('Subscribe or manage billing. If needed, account linking is performed automatically first.')
      .addButton((btn) => {
        btn
          .setButtonText('Subscribe ($9/month)')
          .setCta()
          .onClick(async () => {
            await this.plugin.openHostedCheckout()
          })
      })
      .addButton((btn) => {
        btn.setButtonText('Manage billing').onClick(async () => {
          await this.plugin.openHostedBillingPortal()
        })
      })
  }

  private renderSelfHostedSettings(containerEl: HTMLElement): void {
    containerEl.createEl('h3', { text: 'Self-deployment' })
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text:
        'Connect directly to your own server. Hosted account linking and Stripe billing controls are hidden in this mode.',
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
  }

  display(): void {
    const { containerEl } = this
    containerEl.empty()

    containerEl.createEl('h2', { text: 'Collaborative Folders' })

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
