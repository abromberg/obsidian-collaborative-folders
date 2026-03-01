import { App, Modal, Notice, Setting } from 'obsidian'
import { DEFAULT_SERVER_URL } from '@obsidian-teams/shared'
import type ObsidianTeamsPlugin from '../main'
import { SELF_DEPLOY_DEFAULT_SERVER_URL, type DeploymentMode } from '../settings'

export class OnboardingModal extends Modal {
  private plugin: ObsidianTeamsPlugin
  private displayName: string
  private deploymentMode: DeploymentMode
  private hostedEmail: string
  private selfHostedUrl: string
  private submitButton: HTMLButtonElement | null = null

  constructor(app: App, plugin: ObsidianTeamsPlugin) {
    super(app)
    this.plugin = plugin
    this.displayName = plugin.settings.displayName
    this.deploymentMode = plugin.settings.deploymentMode
    this.hostedEmail = plugin.settings.hostedAccountEmail
    this.selfHostedUrl = plugin.settings.serverUrl || SELF_DEPLOY_DEFAULT_SERVER_URL
  }

  onOpen() {
    const { contentEl } = this
    contentEl.empty()
    contentEl.addClass('obsidian-teams-onboarding-modal')

    contentEl.createEl('h2', { text: 'Welcome to collaborative folders' })
    contentEl.createEl('p', {
      cls: 'setting-item-description',
      text: 'Complete setup to start sharing and joining folders.',
    })

    if (this.plugin.settings.pendingInviteToken) {
      contentEl.createEl('div', {
        cls: 'obsidian-teams-onboarding-pending',
        text: 'You have a pending invite. Complete setup to join it.',
      })
    }

    new Setting(contentEl)
      .setName('Display name')
      .setDesc('Shown to collaborators while editing')
      .addText((text) => {
        text
          .setPlaceholder('Your name')
          .setValue(this.displayName)
          .onChange((value) => {
            this.displayName = value
            this.updateSubmitState()
          })
      })

    const modeSpecificEl = contentEl.createDiv()

    const renderModeFields = () => {
      modeSpecificEl.empty()

      if (this.deploymentMode === 'hosted-service') {
        new Setting(modeSpecificEl)
          .setName('Email')
          .setDesc('Used for hosted account linking and billing')
          .addText((text) => {
            text
              .setPlaceholder('Email address')
              .setValue(this.hostedEmail)
              .onChange((value) => {
                this.hostedEmail = value.trim().toLowerCase()
              })
          })
      } else {
        new Setting(modeSpecificEl)
          .setName('Server URL')
          .setDesc('URL for your self-hosted collaborative folders server')
          .addText((text) => {
            text
              .setPlaceholder(SELF_DEPLOY_DEFAULT_SERVER_URL)
              .setValue(this.selfHostedUrl)
              .onChange((value) => {
                this.selfHostedUrl = value.trim()
              })
          })
      }
    }

    new Setting(contentEl)
      .setName('Service mode')
      .addDropdown((dropdown) => {
        dropdown
          .addOption('hosted-service', 'Hosted service (recommended)')
          .addOption('self-deployment', 'Self-deployment')
          .setValue(this.deploymentMode)
          .onChange((value) => {
            this.deploymentMode = value === 'self-deployment' ? 'self-deployment' : 'hosted-service'
            renderModeFields()
          })
      })

    renderModeFields()

    new Setting(contentEl).addButton((btn) => {
      btn
        .setButtonText('Get started')
        .setCta()
        .onClick(async () => {
          await this.completeOnboarding()
        })
      this.submitButton = btn.buttonEl
      this.updateSubmitState()
    })
  }

  private updateSubmitState() {
    if (!this.submitButton) return
    this.submitButton.disabled = this.displayName.trim().length === 0
  }

  private async completeOnboarding(): Promise<void> {
    const trimmedDisplayName = this.displayName.trim()
    if (!trimmedDisplayName) {
      new Notice('Display name is required')
      return
    }

    this.plugin.settings.displayName = trimmedDisplayName
    this.plugin.settings.hostedAccountDisplayName = trimmedDisplayName
    this.plugin.settings.deploymentMode = this.deploymentMode
    this.plugin.settings.onboardingComplete = true

    if (this.deploymentMode === 'hosted-service') {
      this.plugin.settings.serverUrl = DEFAULT_SERVER_URL
      this.plugin.settings.hostedAccountEmail = this.hostedEmail.trim().toLowerCase()
      this.plugin.settings.hostedSubscriptionStatus = ''
    } else {
      this.plugin.settings.serverUrl = this.selfHostedUrl.trim() || SELF_DEPLOY_DEFAULT_SERVER_URL
      this.plugin.settings.hostedSessionToken = ''
      this.plugin.settings.hostedSessionExpiresAt = ''
      this.plugin.settings.hostedSubscriptionStatus = ''
    }

    const pendingInviteToken = this.plugin.settings.pendingInviteToken.trim()
    await this.plugin.saveSettings()
    this.close()

    if (pendingInviteToken) {
      void this.plugin.attemptInviteJoin(pendingInviteToken)
    }
  }

  onClose() {
    this.contentEl.empty()
  }
}
