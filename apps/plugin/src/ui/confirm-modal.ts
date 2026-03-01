import { App, Modal, Setting } from 'obsidian'

export class ConfirmModal extends Modal {
  private title: string
  private message: string
  private confirmLabel: string
  private onConfirm: () => void | Promise<void>
  private destructive: boolean

  constructor(
    app: App,
    title: string,
    message: string,
    confirmLabel: string,
    onConfirm: () => void | Promise<void>,
    destructive = false
  ) {
    super(app)
    this.title = title
    this.message = message
    this.confirmLabel = confirmLabel
    this.onConfirm = onConfirm
    this.destructive = destructive
  }

  onOpen() {
    const { contentEl } = this
    contentEl.empty()
    contentEl.addClass('obsidian-teams-confirm-modal')

    contentEl.createEl('h3', { text: this.title })
    contentEl.createEl('p', { text: this.message })

    new Setting(contentEl)
      .addButton((btn) => {
        btn.setButtonText('Cancel').onClick(() => this.close())
      })
      .addButton((btn) => {
        btn.setButtonText(this.confirmLabel)
        if (this.destructive) {
          btn.setWarning()
        } else {
          btn.setCta()
        }
        btn.onClick(async () => {
          await this.onConfirm()
          this.close()
        })
      })
  }

  onClose() {
    this.contentEl.empty()
  }
}
