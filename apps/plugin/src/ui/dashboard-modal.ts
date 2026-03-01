import { App, Modal, Notice, Setting } from 'obsidian'
import type ObsidianTeamsPlugin from '../main'
import { ConfirmModal } from './confirm-modal'

interface DashboardEntry {
  folderId: string
  folderName: string
  folderPath: string
  role: 'owner' | 'editor'
  memberCount: number
  status: 'connected' | 'offline' | 'auth-expired'
}

function statusLabel(status: DashboardEntry['status']): string {
  if (status === 'connected') return 'Connected'
  if (status === 'auth-expired') return 'Auth expired'
  return 'Offline'
}

export class DashboardModal extends Modal {
  private plugin: ObsidianTeamsPlugin

  constructor(app: App, plugin: ObsidianTeamsPlugin) {
    super(app)
    this.plugin = plugin
  }

  onOpen() {
    this.render()
  }

  private render() {
    const { contentEl } = this
    contentEl.empty()
    contentEl.addClass('obsidian-teams-dashboard-modal')
    contentEl.createEl('h2', { text: 'Shared folders' })

    const entries = this.plugin.getDashboardEntries()
    if (entries.length === 0) {
      contentEl.createEl('p', {
        cls: 'setting-item-description',
        text: 'No shared folders yet. Right-click a folder to start sharing.',
      })
      return
    }

    const listEl = contentEl.createDiv({ cls: 'obsidian-teams-dashboard-list' })

    for (const entry of entries) {
      this.renderEntry(listEl, entry)
    }

    const footer = contentEl.createEl('p', { cls: 'setting-item-description obsidian-teams-dashboard-footer' })
    footer.setText(`Display name: ${this.plugin.settings.displayName || 'Anonymous'} · Client ID: ${this.plugin.settings.clientId}`)
  }

  private renderEntry(containerEl: HTMLElement, entry: DashboardEntry) {
    const row = containerEl.createDiv({ cls: 'obsidian-teams-dashboard-row' })

    const heading = row.createDiv({ cls: 'obsidian-teams-dashboard-heading' })
    const folderButton = heading.createEl('button', {
      cls: 'obsidian-teams-dashboard-folder-link',
      text: entry.folderName,
      attr: { type: 'button' },
    })
    folderButton.addEventListener('click', () => {
      const revealed = this.plugin.revealFolderInExplorer(entry.folderPath)
      if (!revealed) {
        new Notice(`Could not reveal folder '${entry.folderPath}' in file explorer`)
      }
    })

    heading.createDiv({
      cls: `obsidian-teams-dashboard-status is-${entry.status}`,
      text: statusLabel(entry.status),
    })

    row.createEl('p', {
      cls: 'obsidian-teams-dashboard-meta',
      text: `${entry.memberCount} member${entry.memberCount === 1 ? '' : 's'} · ${entry.role === 'owner' ? 'Owner' : 'Editor'}`,
    })

    const actions = row.createDiv({ cls: 'obsidian-teams-dashboard-actions' })
    if (entry.role === 'owner') {
      const manageSetting = new Setting(actions)
      manageSetting.addButton((btn) => {
        btn.setButtonText('Manage').setCta().onClick(() => {
          const opened = this.plugin.openShareModalForPath(entry.folderPath)
          if (!opened) {
            new Notice(`Could not open manage view for '${entry.folderPath}'`)
          }
        })
      })
    } else {
      const leaveSetting = new Setting(actions)
      leaveSetting.addButton((btn) => {
        btn.setButtonText('Leave').setWarning().onClick(() => {
          new ConfirmModal(
            this.app,
            'Leave shared folder',
            `Leave '${entry.folderName}'? Local files stay in your vault, but sync will stop.`,
            'Leave',
            async () => {
              await this.plugin.leaveSharedFolderById(entry.folderId)
              this.render()
            },
            true
          ).open()
        })
      })
    }
  }

  onClose() {
    this.contentEl.empty()
  }
}
