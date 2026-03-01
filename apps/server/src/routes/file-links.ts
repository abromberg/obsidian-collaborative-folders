/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import { Router, type Request, type Response } from 'express'
import crypto from 'crypto'
import type {
  CreateFileShareLinkResponse,
  FileShareLinkPreviewResponse,
  ResolveFileShareLinkResponse,
} from '@obsidian-teams/shared'
import { getDb } from '../db/schema.js'
import { requireHttpAuth, type AuthenticatedRequest } from '../middleware/http-auth.js'
import { requireFolderRole } from '../middleware/require-role.js'
import { createRateLimiter } from '../security/rate-limit.js'
import { writeAuditEvent } from '../security/audit.js'
import { redactValue } from '../security/redaction.js'

export const fileLinksRouter: ReturnType<typeof Router> = Router()

const DEFAULT_FILE_LINK_EXPIRY_HOURS = Number(process.env.FILE_LINK_DEFAULT_EXPIRY_HOURS || 24 * 7)
const MAX_FILE_LINK_EXPIRY_HOURS = Number(process.env.FILE_LINK_MAX_EXPIRY_HOURS || 24 * 30)
const FILE_LINK_CLEANUP_INTERVAL_MS = Number(process.env.FILE_LINK_CLEANUP_INTERVAL_MS || 10 * 60_000)
const FAVICON_DATA_URL =
  'data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270%200%20100%20100%27%3E%3Ctext y=%27.9em%27 font-size=%2790%27%3E%F0%9F%93%99%3C/text%3E%3C/svg%3E'

interface CreateFileShareBody {
  fileId?: string
  relativePath?: string
  fileName?: string
  expiresInHours?: number
}

interface ResolveFileShareBody {
  token?: string
}

interface FileShareLinkRow {
  token_hash: string
  folder_id: string
  file_id: string | null
  relative_path: string
  file_name: string
  created_by: string
  created_at: string
  expires_at: string
  revoked_at: string | null
  revoked_by: string | null
  open_count: number
}

interface FolderNameRow {
  id: string
  name: string
}

type FileLinkValidationErrorKind = 'not_found' | 'revoked' | 'expired'

class FileLinkValidationError extends Error {
  readonly status: number
  readonly kind: FileLinkValidationErrorKind

  constructor(kind: FileLinkValidationErrorKind) {
    const messageByKind: Record<FileLinkValidationErrorKind, string> = {
      not_found: 'File link not found',
      revoked: 'File link revoked',
      expired: 'File link expired',
    }
    const statusByKind: Record<FileLinkValidationErrorKind, number> = {
      not_found: 404,
      revoked: 410,
      expired: 410,
    }
    super(messageByKind[kind])
    this.status = statusByKind[kind]
    this.kind = kind
  }
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '')
}

function readForwarded(req: Request, key: 'x-forwarded-proto' | 'x-forwarded-host'): string | null {
  const value = req.headers[key]
  if (!value) return null
  if (Array.isArray(value)) return value[0] ?? null
  return value.split(',')[0]?.trim() || null
}

function shouldUseForwardedHeaders(req: Request): boolean {
  const trustProxy: unknown = req.app.get('trust proxy')
  if (typeof trustProxy === 'boolean') return trustProxy
  if (typeof trustProxy === 'number') return trustProxy > 0
  return Boolean(trustProxy)
}

function resolveHttpBaseUrl(req: Request): string {
  const configured = process.env.PUBLIC_HTTP_URL || process.env.SERVER_URL
  if (configured) return trimTrailingSlash(configured)

  const trustForwarded = shouldUseForwardedHeaders(req)
  const proto = (trustForwarded ? readForwarded(req, 'x-forwarded-proto') : null) || req.protocol || 'http'
  const host = (trustForwarded ? readForwarded(req, 'x-forwarded-host') : null) || req.get('host')
  if (!host) return 'https://collaborativefolders.com'
  return `${proto}://${host}`
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function parseBoundedInt(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === 'number' ? Math.trunc(value) : Number(value)
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}

function normalizeRelativePath(value: string): string {
  const slashNormalized = value.trim().replace(/\\/g, '/')
  const trimmedLeading = slashNormalized.replace(/^\/+/, '')
  return trimmedLeading.replace(/\/{2,}/g, '/')
}

function isValidRelativePath(relativePath: string): boolean {
  if (!relativePath) return false
  if (relativePath.includes('\0')) return false
  const segments = relativePath.split('/')
  return segments.length > 0 && segments.every((segment) => segment.length > 0 && segment !== '.' && segment !== '..')
}

function tokenHashFromToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex')
}

function generateFileShareToken(): string {
  return `file-${crypto.randomBytes(20).toString('hex')}`
}

let lastCleanupAtMs = 0

function cleanupExpiredLinksIfNeeded(): void {
  const now = Date.now()
  if (now - lastCleanupAtMs < FILE_LINK_CLEANUP_INTERVAL_MS) return

  lastCleanupAtMs = now
  const db = getDb()
  db.prepare(
    `
      DELETE FROM file_share_links
      WHERE julianday(expires_at) <= julianday('now')
    `
  ).run()
}

function getValidatedFileLinkByToken(token: string): FileShareLinkRow {
  const db = getDb()
  const tokenHash = tokenHashFromToken(token)
  const row = db
    .prepare('SELECT * FROM file_share_links WHERE token_hash = ?')
    .get(tokenHash) as FileShareLinkRow | undefined

  if (!row) {
    throw new FileLinkValidationError('not_found')
  }
  if (row.revoked_at) {
    throw new FileLinkValidationError('revoked')
  }
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    throw new FileLinkValidationError('expired')
  }

  return row
}

function getFolderName(folderId: string): string {
  const db = getDb()
  const folder = db
    .prepare('SELECT id, name FROM folders WHERE id = ?')
    .get(folderId) as FolderNameRow | undefined
  return folder?.name || 'Shared Folder'
}

function renderFileLinkErrorPage(kind: FileLinkValidationErrorKind): string {
  const titleByKind: Record<FileLinkValidationErrorKind, string> = {
    not_found: 'File link not found',
    expired: 'File link expired',
    revoked: 'File link revoked',
  }
  const title = titleByKind[kind]

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${title}</title>
    <link rel="icon" href="${FAVICON_DATA_URL}">
    <style>
      :root {
        --bg: #f1eee2;
        --surface: #fbf8ef;
        --text-strong: #352e22;
        --text-soft: #615847;
        --line: #d5ccb5;
        --accent-soft: #e7ddc5;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        padding: 24px;
        display: grid;
        place-items: center;
        background: var(--bg);
        color: var(--text-strong);
        font-family: "Avenir Next", "Nunito Sans", "Segoe UI", sans-serif;
      }
      .card {
        width: min(640px, 100%);
        border-radius: 18px;
        border: 1px solid var(--line);
        background: var(--surface);
        box-shadow: 0 20px 48px rgba(39, 30, 11, 0.08);
        padding: 24px;
      }
      h1 {
        margin: 0;
        font-size: clamp(28px, 5vw, 40px);
        line-height: 1;
      }
      p {
        color: var(--text-soft);
        font-size: 16px;
        line-height: 1.5;
        margin-top: 14px;
      }
      button {
        margin-top: 20px;
        border: 1px solid #ddd3ba;
        border-radius: 12px;
        background: var(--accent-soft);
        color: var(--text-strong);
        padding: 11px 16px;
        font-size: 16px;
        font-weight: 700;
        cursor: pointer;
      }
    </style>
  </head>
  <body>
    <article class="card">
      <h1>${title}</h1>
      <p>This file link is no longer valid. Ask a collaborator to generate a new link.</p>
      <button type="button" onclick="window.close(); history.back();">Back</button>
    </article>
  </body>
</html>`
}

const fileLinkCreateRateLimiter = createRateLimiter({
  name: 'file-link-create',
  windowMs: 60_000,
  maxRequests: Number(process.env.FILE_LINK_CREATE_MAX_PER_MINUTE || 60),
  keyFn: (req) => {
    const actor = (req as AuthenticatedRequest).actor
    return `${req.ip}:${req.params.id}:${actor?.clientId || 'anonymous'}`
  },
})

const fileLinkPreviewRateLimiter = createRateLimiter({
  name: 'file-link-preview',
  windowMs: 60_000,
  maxRequests: Number(process.env.FILE_LINK_PREVIEW_MAX_PER_MINUTE || 120),
  keyFn: (req) => `${req.ip}`,
})

const fileLinkResolveRateLimiter = createRateLimiter({
  name: 'file-link-resolve',
  windowMs: 60_000,
  maxRequests: Number(process.env.FILE_LINK_RESOLVE_MAX_PER_MINUTE || 120),
  keyFn: (req) => {
    const actor = (req as AuthenticatedRequest).actor
    return `${req.ip}:${req.params.id}:${actor?.clientId || 'anonymous'}`
  },
})

/** POST /api/folders/:id/file-links — Create an opaque file share link for this folder. */
fileLinksRouter.post(
  '/folders/:id/file-links',
  requireHttpAuth,
  requireFolderRole(['editor']),
  fileLinkCreateRateLimiter,
  (req: AuthenticatedRequest, res: Response<CreateFileShareLinkResponse | { error: string }>) => {
    try {
      cleanupExpiredLinksIfNeeded()

      const actor = req.actor
      if (!actor) {
        res.status(401).json({ error: 'Missing actor context' })
        return
      }

      const folderId = req.params.id
      const body = (req.body || {}) as CreateFileShareBody
      const relativePath = normalizeRelativePath(body.relativePath || '')
      if (!isValidRelativePath(relativePath)) {
        res.status(400).json({ error: 'Invalid relativePath' })
        return
      }

      const fileName = (body.fileName || relativePath.split('/').pop() || '').trim()
      if (!fileName) {
        res.status(400).json({ error: 'Missing required field: fileName' })
        return
      }

      const effectiveExpiryHours = parseBoundedInt(
        body.expiresInHours,
        DEFAULT_FILE_LINK_EXPIRY_HOURS,
        1,
        MAX_FILE_LINK_EXPIRY_HOURS
      )
      const expiresAt = new Date(Date.now() + effectiveExpiryHours * 3600_000).toISOString()

      const db = getDb()
      let shareToken = ''
      let tokenHash = ''
      let inserted = false
      for (let attempt = 0; attempt < 3; attempt += 1) {
        shareToken = generateFileShareToken()
        tokenHash = tokenHashFromToken(shareToken)

        const insertResult = db.prepare(
          `
          INSERT OR IGNORE INTO file_share_links (
            token_hash, folder_id, file_id, relative_path, file_name, created_by, expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `
        ).run(
          tokenHash,
          folderId,
          body.fileId?.trim() || null,
          relativePath,
          fileName,
          actor.clientId,
          expiresAt
        )

        if (insertResult.changes === 1) {
          inserted = true
          break
        }
      }

      if (!inserted) {
        res.status(500).json({ error: 'Unable to generate file link token' })
        return
      }

      writeAuditEvent(db, {
        folderId,
        actorClientId: actor.clientId,
        eventType: 'file_link_create',
        target: tokenHash,
        metadata: {
          fileId: body.fileId?.trim() || null,
          relativePath,
          fileName,
          expiresAt,
        },
      })

      const serverUrl = resolveHttpBaseUrl(req)
      const shareUrl = `${serverUrl}/api/file-links/open?token=${encodeURIComponent(shareToken)}`

      res.status(201).json({
        shareToken,
        shareUrl,
        expiresAt,
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Internal server error'
      console.error('[file-links] Error creating file link:', redactValue({ message, body: req.body }))
      res.status(500).json({ error: message })
    }
  }
)

/** GET /api/file-links/preview — Public, non-sensitive metadata for a file link token. */
fileLinksRouter.get(
  '/file-links/preview',
  fileLinkPreviewRateLimiter,
  (req: Request, res: Response<FileShareLinkPreviewResponse | { error: string }>) => {
    try {
      cleanupExpiredLinksIfNeeded()

      const queryToken = req.query.token
      const token = typeof queryToken === 'string' ? queryToken.trim() : ''
      if (!token) {
        res.status(400).json({ error: 'Missing token' })
        return
      }

      const link = getValidatedFileLinkByToken(token)
      const folderName = getFolderName(link.folder_id)

      writeAuditEvent(getDb(), {
        folderId: link.folder_id,
        eventType: 'file_link_open_preview',
        target: link.token_hash,
        metadata: {
          ip: req.ip,
        },
      })

      res.json({
        folderId: link.folder_id,
        folderName,
        fileName: link.file_name,
        expiresAt: link.expires_at,
      })
    } catch (error) {
      if (error instanceof FileLinkValidationError) {
        res.status(error.status).json({ error: error.message })
        return
      }
      const message = error instanceof Error ? error.message : 'Internal server error'
      console.error('[file-links] Error previewing file link:', redactValue({ message, query: req.query }))
      res.status(500).json({ error: message })
    }
  }
)

/** GET /api/file-links/open — Browser bridge page that deep-links into Obsidian. */
fileLinksRouter.get('/file-links/open', (req: Request, res: Response) => {
  const queryToken = req.query.token
  const token = typeof queryToken === 'string' ? queryToken.trim() : ''

  if (!token) {
    res
      .status(400)
      .type('html')
      .setHeader('Cache-Control', 'no-store')
      .setHeader('Referrer-Policy', 'no-referrer')
      .send(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>File link invalid</title><link rel="icon" href="' +
          FAVICON_DATA_URL +
          '"></head><body><p>File link is missing a token.</p></body></html>'
      )
    return
  }

  let link: FileShareLinkRow
  let folderName = 'Shared Folder'
  try {
    cleanupExpiredLinksIfNeeded()
    link = getValidatedFileLinkByToken(token)
    folderName = getFolderName(link.folder_id)

    writeAuditEvent(getDb(), {
      folderId: link.folder_id,
      eventType: 'file_link_open_preview',
      target: link.token_hash,
      metadata: {
        bridge: true,
        ip: req.ip,
      },
    })
  } catch (error) {
    if (error instanceof FileLinkValidationError) {
      res
        .status(error.status)
        .type('html')
        .setHeader('Cache-Control', 'no-store')
        .setHeader('Referrer-Policy', 'no-referrer')
        .send(renderFileLinkErrorPage(error.kind))
      return
    }

    const message = error instanceof Error ? error.message : 'Internal server error'
    console.error('[file-links] Error validating file link for open page:', redactValue({ message, query: req.query }))
    res.status(500).type('html').send('<!doctype html><html><body><p>Internal server error.</p></body></html>')
    return
  }

  const deepLink = `obsidian://teams-open-file?token=${encodeURIComponent(token)}`
  const deepLinkLiteral = JSON.stringify(deepLink)
  const escapedDeepLink = escapeHtml(deepLink)
  const escapedToken = escapeHtml(token)
  const escapedFileName = escapeHtml(link.file_name)
  const escapedFolderName = escapeHtml(folderName)

  res
    .status(200)
    .type('html')
    .setHeader('Cache-Control', 'no-store')
    .setHeader('Referrer-Policy', 'no-referrer')
    .send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Open shared file in Obsidian</title>
    <link rel="icon" href="${FAVICON_DATA_URL}">
    <style>
      :root {
        --bg: #f1eee2;
        --surface: #fbf8ef;
        --text-strong: #352e22;
        --text-soft: #615847;
        --line: #d5ccb5;
        --accent-0: #cc8600;
        --accent-soft: #e7ddc5;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        padding: 26px;
        display: grid;
        place-items: center;
        background: var(--bg);
        color: var(--text-strong);
        font-family: "Avenir Next", "Nunito Sans", "Segoe UI", sans-serif;
      }
      .card {
        width: min(760px, 100%);
        border-radius: 22px;
        border: 1px solid var(--line);
        background: var(--surface);
        box-shadow:
          0 24px 70px rgba(39, 30, 11, 0.08),
          0 2px 8px rgba(39, 30, 11, 0.06);
        padding: 28px 30px;
      }
      .eyebrow {
        margin-bottom: 10px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #786f5e;
      }
      h1 {
        margin: 0;
        font-size: clamp(34px, 4vw, 50px);
        line-height: 0.95;
      }
      p {
        margin: 14px 0 0;
        color: var(--text-soft);
        font-size: 18px;
        line-height: 1.45;
      }
      .actions {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        margin: 22px 0 20px;
      }
      a.button,
      button {
        border: 1px solid transparent;
        border-radius: 14px;
        padding: 14px 22px;
        font-size: 21px;
        line-height: 1;
        font-weight: 700;
        cursor: pointer;
        text-decoration: none;
      }
      a.button.primary {
        background: var(--accent-0);
        color: #fff;
        box-shadow: 0 12px 28px rgba(158, 100, 0, 0.25);
      }
      button {
        background: var(--accent-soft);
        color: var(--text-strong);
        border-color: #ddd3ba;
      }
      .label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.09em;
        color: #6e6453;
        font-weight: 700;
        margin-bottom: 8px;
      }
      .token-row {
        display: flex;
        align-items: stretch;
        gap: 10px;
      }
      input {
        width: auto;
        min-width: 0;
        flex: 1 1 auto;
        border: 2px solid #cfc3a8;
        border-radius: 14px;
        background: #fff;
        color: var(--text-strong);
        padding: 16px 18px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 14px;
      }
      button.token-copy-button {
        flex: 0 0 auto;
        min-width: 68px;
        border-radius: 10px;
        padding: 0 12px;
        font-size: 13px;
        font-weight: 700;
      }
      @media (max-width: 760px) {
        .card {
          padding: 22px 20px;
          border-radius: 16px;
        }
        h1 {
          font-size: clamp(28px, 9vw, 42px);
        }
        a.button,
        button {
          font-size: 18px;
          padding: 13px 18px;
        }
      }
      @media (max-width: 520px) {
        .actions > * {
          width: 100%;
          text-align: center;
          justify-content: center;
        }
      }
    </style>
  </head>
  <body>
    <article class="card">
      <div class="eyebrow">Collaborative Folders file link</div>
      <h1>Opening in Obsidian...</h1>
      <p><strong>${escapedFileName}</strong> from <strong>${escapedFolderName}</strong></p>
      <div class="actions">
        <a class="button primary" href="${escapedDeepLink}" id="open-obsidian">Open in Obsidian</a>
        <button type="button" id="copy-token">Copy token</button>
      </div>
      <div class="label">File link token</div>
      <div class="token-row">
        <input id="file-link-token" readonly value="${escapedToken}">
        <button type="button" id="copy-token-inline" class="token-copy-button">Copy</button>
      </div>
    </article>
    <script>
      const deepLink = ${deepLinkLiteral}
      const tokenInput = document.getElementById('file-link-token')
      const copyButtons = [document.getElementById('copy-token'), document.getElementById('copy-token-inline')]

      let autoLaunchTriggered = false
      const openDeepLink = () => {
        window.location.href = deepLink
      }

      const autoLaunchDeepLink = () => {
        if (autoLaunchTriggered) return
        autoLaunchTriggered = true
        openDeepLink()
      }

      window.setTimeout(autoLaunchDeepLink, 40)

      copyButtons.forEach((button) => {
        if (!button) return
        button.addEventListener('click', async () => {
          if (!tokenInput) return
          try {
            await navigator.clipboard.writeText(tokenInput.value)
          } catch {
            tokenInput.select()
          }
        })
      })
    </script>
  </body>
</html>`)
})

/** POST /api/folders/:id/file-links/resolve — Resolve token into file target for authorized folder members. */
fileLinksRouter.post(
  '/folders/:id/file-links/resolve',
  requireHttpAuth,
  requireFolderRole(['editor']),
  fileLinkResolveRateLimiter,
  (req: AuthenticatedRequest, res: Response<ResolveFileShareLinkResponse | { error: string }>) => {
    try {
      cleanupExpiredLinksIfNeeded()

      const actor = req.actor
      if (!actor) {
        res.status(401).json({ error: 'Missing actor context' })
        return
      }

      const folderId = req.params.id
      const body = (req.body || {}) as ResolveFileShareBody
      const token = body.token?.trim() || ''
      if (!token) {
        writeAuditEvent(getDb(), {
          folderId,
          actorClientId: actor.clientId,
          eventType: 'file_link_resolve_denied',
          metadata: { reason: 'missing_token' },
        })
        res.status(400).json({ error: 'Missing required field: token' })
        return
      }

      const tokenHash = tokenHashFromToken(token)
      let link: FileShareLinkRow
      try {
        link = getValidatedFileLinkByToken(token)
      } catch (error) {
        if (error instanceof FileLinkValidationError) {
          writeAuditEvent(getDb(), {
            folderId,
            actorClientId: actor.clientId,
            eventType: 'file_link_resolve_denied',
            target: tokenHash,
            metadata: { reason: error.kind },
          })
          res.status(error.status).json({ error: error.message })
          return
        }
        throw error
      }

      if (link.folder_id !== folderId) {
        writeAuditEvent(getDb(), {
          folderId,
          actorClientId: actor.clientId,
          eventType: 'file_link_resolve_denied',
          target: tokenHash,
          metadata: { reason: 'folder_mismatch', linkFolderId: link.folder_id },
        })
        res.status(404).json({ error: 'File link not found for this folder' })
        return
      }

      const db = getDb()
      db.prepare('UPDATE file_share_links SET open_count = open_count + 1 WHERE token_hash = ?').run(tokenHash)

      writeAuditEvent(db, {
        folderId,
        actorClientId: actor.clientId,
        eventType: 'file_link_resolve_success',
        target: tokenHash,
        metadata: {
          fileId: link.file_id,
          fileName: link.file_name,
          relativePath: link.relative_path,
        },
      })

      res.json({
        folderId: link.folder_id,
        fileId: link.file_id,
        relativePath: link.relative_path,
        fileName: link.file_name,
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Internal server error'
      console.error('[file-links] Error resolving file link:', redactValue({ message, body: req.body }))
      res.status(500).json({ error: message })
    }
  }
)
