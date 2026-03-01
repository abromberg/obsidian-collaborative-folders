import { App, TFile, normalizePath, parseLinktext } from 'obsidian'
import { CRDT_EXTENSIONS, CANVAS_EXTENSIONS } from '@obsidian-teams/shared'

export interface AttachmentLocalizationResult {
  localizedAttachments: number
  rewrittenEmbeds: number
}

const WIKILINK_EMBED_REGEX = /!\[\[([^\]\n]+)\]\]/g

interface LocalizedAttachment {
  file: TFile
  created: boolean
}

/**
 * Copies externally referenced attachments into the shared folder and rewrites
 * embed links so the existing shared-folder sync pipeline can pick them up.
 */
export class AttachmentLocalizer {
  private sourceTargetCache = new Map<string, string>()

  constructor(private app: App) {}

  async localizeForMarkdown(
    sharedFolderPath: string,
    file: TFile
  ): Promise<AttachmentLocalizationResult> {
    const liveFile = this.app.vault.getFileByPath(file.path)
    if (!liveFile) {
      return { localizedAttachments: 0, rewrittenEmbeds: 0 }
    }
    if (!this.isInSharedFolder(liveFile.path, sharedFolderPath)) {
      return { localizedAttachments: 0, rewrittenEmbeds: 0 }
    }
    if (!this.isCrdtPath(liveFile.path)) {
      return { localizedAttachments: 0, rewrittenEmbeds: 0 }
    }

    const content = await this.app.vault.cachedRead(liveFile)
    const matches = [...content.matchAll(WIKILINK_EMBED_REGEX)]
    if (matches.length === 0) {
      return { localizedAttachments: 0, rewrittenEmbeds: 0 }
    }

    let localizedAttachments = 0
    let rewrittenEmbeds = 0
    let cursor = 0
    let rewritten = ''

    for (const match of matches) {
      const fullMatch = match[0]
      const inner = match[1] ?? ''
      const start = match.index ?? 0

      rewritten += content.slice(cursor, start)
      cursor = start + fullMatch.length

      const rewrittenMatch = await this.rewriteEmbed(
        sharedFolderPath,
        liveFile,
        inner
      )

      if (!rewrittenMatch) {
        rewritten += fullMatch
        continue
      }

      rewritten += rewrittenMatch.embed
      rewrittenEmbeds += 1
      if (rewrittenMatch.createdAttachment) {
        localizedAttachments += 1
      }
    }

    rewritten += content.slice(cursor)

    if (rewrittenEmbeds > 0 && rewritten !== content) {
      await this.app.vault.modify(liveFile, rewritten)
    }

    return { localizedAttachments, rewrittenEmbeds }
  }

  private async rewriteEmbed(
    sharedFolderPath: string,
    note: TFile,
    inner: string
  ): Promise<{ embed: string; createdAttachment: boolean } | null> {
    const { linkTarget, displaySuffix } = this.splitLinkInner(inner)
    if (!linkTarget) return null

    const parsed = parseLinktext(linkTarget)
    const linkPath = parsed.path?.trim() || ''
    if (!linkPath) return null

    const resolved = this.app.metadataCache.getFirstLinkpathDest(linkPath, note.path)
    if (!resolved) return null
    if (this.isInSharedFolder(resolved.path, sharedFolderPath)) return null
    if (!this.isBlobPath(resolved.path)) return null

    const localized = await this.ensureLocalizedAttachment(sharedFolderPath, resolved)
    const relativeTarget = this.relativePathFromNote(note.path, localized.file.path)
    const rewrittenTarget = `${relativeTarget}${parsed.subpath || ''}`
    if (rewrittenTarget === linkTarget) return null

    return {
      embed: `![[${rewrittenTarget}${displaySuffix}]]`,
      createdAttachment: localized.created,
    }
  }

  private splitLinkInner(inner: string): { linkTarget: string; displaySuffix: string } {
    const pipeIndex = inner.indexOf('|')
    if (pipeIndex < 0) {
      return { linkTarget: inner.trim(), displaySuffix: '' }
    }

    return {
      linkTarget: inner.slice(0, pipeIndex).trim(),
      displaySuffix: inner.slice(pipeIndex),
    }
  }

  private async ensureLocalizedAttachment(
    sharedFolderPath: string,
    source: TFile
  ): Promise<LocalizedAttachment> {
    const cacheKey = `${sharedFolderPath}::${source.path}`
    const cachedPath = this.sourceTargetCache.get(cacheKey)
    if (cachedPath) {
      const cachedFile = this.app.vault.getFileByPath(cachedPath)
      if (cachedFile) {
        return { file: cachedFile, created: false }
      }
      this.sourceTargetCache.delete(cacheKey)
    }

    const attachmentDir = normalizePath(`${sharedFolderPath}/attachments`)
    await this.ensureFolderPathExists(attachmentDir)

    const sourceBytes = await this.app.vault.readBinary(source)
    const sourceHash = await this.computeHash(sourceBytes)

    const { stem, ext } = this.splitName(source.name)
    let index = 0

    while (true) {
      const candidateName = index === 0 ? source.name : `${stem} (${index})${ext}`
      const candidatePath = normalizePath(`${attachmentDir}/${candidateName}`)
      const existing = this.app.vault.getAbstractFileByPath(candidatePath)

      if (!existing) {
        const createdFile = await this.app.vault.createBinary(candidatePath, sourceBytes)
        this.sourceTargetCache.set(cacheKey, createdFile.path)
        return { file: createdFile, created: true }
      }

      if (!(existing instanceof TFile)) {
        index += 1
        continue
      }

      const existingBytes = await this.app.vault.readBinary(existing)
      const existingHash = await this.computeHash(existingBytes)
      if (existingHash === sourceHash) {
        this.sourceTargetCache.set(cacheKey, existing.path)
        return { file: existing, created: false }
      }

      index += 1
    }
  }

  private async ensureFolderPathExists(path: string): Promise<void> {
    const segments = path.split('/').filter(Boolean)
    let current = ''
    for (const segment of segments) {
      current = current ? `${current}/${segment}` : segment
      const existing = this.app.vault.getAbstractFileByPath(current)
      if (existing) continue
      await this.app.vault.createFolder(current)
    }
  }

  private async computeHash(content: ArrayBuffer): Promise<string> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', content)
    return Array.from(new Uint8Array(hashBuffer))
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')
  }

  private splitName(name: string): { stem: string; ext: string } {
    const lastDot = name.lastIndexOf('.')
    if (lastDot <= 0) {
      return { stem: name, ext: '' }
    }
    return {
      stem: name.slice(0, lastDot),
      ext: name.slice(lastDot),
    }
  }

  private relativePathFromNote(notePath: string, targetPath: string): string {
    const noteDirectory = this.parentPath(notePath)
    const fromSegments = noteDirectory ? noteDirectory.split('/') : []
    const toSegments = targetPath.split('/')

    let common = 0
    const maxCommon = Math.min(fromSegments.length, toSegments.length)
    while (common < maxCommon && fromSegments[common] === toSegments[common]) {
      common += 1
    }

    const upward = new Array<string>(fromSegments.length - common).fill('..')
    const downward = toSegments.slice(common)
    const relative = upward.concat(downward).join('/')
    return relative || targetPath
  }

  private parentPath(path: string): string {
    const lastSlash = path.lastIndexOf('/')
    return lastSlash >= 0 ? path.slice(0, lastSlash) : ''
  }

  private isInSharedFolder(path: string, sharedFolderPath: string): boolean {
    return path === sharedFolderPath || path.startsWith(sharedFolderPath + '/')
  }

  private isCrdtPath(path: string): boolean {
    const ext = this.extension(path)
    return CRDT_EXTENSIONS.has(ext)
  }

  private isBlobPath(path: string): boolean {
    const ext = this.extension(path)
    return !CRDT_EXTENSIONS.has(ext) && !CANVAS_EXTENSIONS.has(ext)
  }

  private extension(path: string): string {
    const lastSlash = path.lastIndexOf('/')
    const lastDot = path.lastIndexOf('.')
    if (lastDot <= lastSlash) return ''
    return path.slice(lastDot).toLowerCase()
  }
}
