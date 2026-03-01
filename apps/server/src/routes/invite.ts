/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import { Router, type Request, type Response } from 'express'
import crypto from 'crypto'
import { generateInviteToken, generateAccessToken } from '../hooks/auth.js'
import { getDb } from '../db/schema.js'
import { actorFromToken, extractBearerToken } from '../middleware/http-auth.js'
import { getMemberAuthRow, isTokenRevoked } from '../security/authz.js'
import { issueRefreshToken } from '../security/refresh-tokens.js'
import { writeAuditEvent } from '../security/audit.js'
import { createRateLimiter, consumeWindowedQuota } from '../security/rate-limit.js'
import { redactValue } from '../security/redaction.js'
import { isHostedModeEnabled } from '../config/hosted.js'
import {
  extractHostedSessionToken,
  resolveHostedSession,
  type HostedSessionActor,
} from '../security/hosted-sessions.js'
import {
  validateInviteCreateEntitlement,
  validateInviteRedeemEntitlement,
} from '../security/entitlements.js'

export const inviteRouter: ReturnType<typeof Router> = Router()

const DEFAULT_INVITE_EXPIRY_HOURS = Number(process.env.INVITE_DEFAULT_EXPIRY_HOURS || 24 * 7)
const MAX_INVITE_EXPIRY_HOURS = Number(process.env.INVITE_MAX_EXPIRY_HOURS || 24 * 30)
const MAX_INVITE_USES_LIMIT = Number(process.env.INVITE_MAX_USES_LIMIT || 100)
const INVITE_CREATE_MAX_PER_HOUR = Number(process.env.INVITE_CREATE_MAX_PER_HOUR || 100)
const INVITE_REDEEM_MAX_PER_HOUR = Number(process.env.INVITE_REDEEM_MAX_PER_HOUR || 200)
const BRAT_PLUGIN_URL = 'https://obsidian.md/plugins?id=brat'
const GITHUB_SOURCE_URL = 'https://github.com/abromberg/obsidian-collaborative-folders'
const OBSIDIAN_RELEASES_PR_URL = 'https://github.com/obsidianmd/obsidian-releases/pull/10628'
const FAVICON_DATA_URL =
  'data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270%200%20100%20100%27%3E%3Ctext y=%27.9em%27 font-size=%2790%27%3E%F0%9F%93%99%3C/text%3E%3C/svg%3E'

interface CreateInviteBody {
  folderId?: string
  folderName?: string
  role?: string
  ownerClientId?: string
  ownerDisplayName?: string
  expiresInHours?: number
  maxUses?: number
  inviteeLabel?: string
}

interface RedeemInviteBody {
  inviteToken?: string
  clientId?: string
  displayName?: string
  hostedSessionToken?: string
  deviceLabel?: string
  deviceFingerprint?: string
}

interface FolderRow {
  id: string
  name: string
  owner_client_id: string
  owner_account_id: string | null
}

interface MemberTokenRow {
  role: 'owner' | 'editor'
  token_version: number
  display_name: string
}

function existingMemberRedeemError(role: MemberTokenRow['role']): string {
  if (role === 'owner') return 'Folder owner cannot redeem invites for this folder'
  return 'Client is already a member of this folder'
}

class InviteRedeemError extends Error {
  readonly status: number
  readonly code?: string

  constructor(status: number, message: string, code?: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

interface InviteRow {
  token_hash: string
  folder_id: string
  role: 'editor'
  created_at: string
  consumed_at: string | null
  consumed_by: string | null
  created_by: string | null
  invitee_label: string | null
  expires_at: string | null
  max_uses: number
  use_count: number
  revoked_at: string | null
  revoked_by: string | null
}

type InviteValidationErrorKind = 'not_found' | 'revoked' | 'expired' | 'consumed'

interface InvitePreviewMetadata {
  invite: InviteRow
  folderName: string
  ownerDisplayName: string
}

class InviteValidationError extends Error {
  readonly status: number
  readonly kind: InviteValidationErrorKind

  constructor(kind: InviteValidationErrorKind) {
    const messageByKind: Record<InviteValidationErrorKind, string> = {
      not_found: 'Invite not found',
      revoked: 'Invite revoked',
      expired: 'Invite expired',
      consumed: 'Invite consumed',
    }
    const statusByKind: Record<InviteValidationErrorKind, number> = {
      not_found: 404,
      revoked: 410,
      expired: 410,
      consumed: 410,
    }
    super(messageByKind[kind])
    this.status = statusByKind[kind]
    this.kind = kind
  }
}

function renderInviteErrorPage(kind: InviteValidationErrorKind): string {
  const titleByKind: Record<InviteValidationErrorKind, string> = {
    not_found: 'Invite not found',
    expired: 'Invite expired',
    revoked: 'Invite revoked',
    consumed: 'Invite already used',
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
      .actions {
        margin-top: 20px;
      }
      button {
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
      <p>This invite is no longer valid. Ask the folder owner to send a new one.</p>
      <div class="actions">
        <button type="button" onclick="window.close(); history.back();">Back</button>
      </div>
    </article>
  </body>
</html>`
}

function getInvitePreviewMetadata(inviteToken: string): InvitePreviewMetadata {
  const db = getDb()
  const tokenHash = crypto.createHash('sha256').update(inviteToken).digest('hex')
  const invite = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(tokenHash) as InviteRow | undefined

  if (!invite) {
    throw new InviteValidationError('not_found')
  }
  if (invite.revoked_at) {
    throw new InviteValidationError('revoked')
  }
  if (invite.expires_at && new Date(invite.expires_at).getTime() <= Date.now()) {
    throw new InviteValidationError('expired')
  }
  if (invite.use_count >= invite.max_uses) {
    throw new InviteValidationError('consumed')
  }

  const folder = db
    .prepare('SELECT name, owner_client_id FROM folders WHERE id = ?')
    .get(invite.folder_id) as Pick<FolderRow, 'name' | 'owner_client_id'> | undefined
  if (!folder) {
    throw new InviteValidationError('not_found')
  }

  const owner = db
    .prepare('SELECT display_name FROM members WHERE folder_id = ? AND client_id = ?')
    .get(invite.folder_id, folder.owner_client_id) as Pick<MemberTokenRow, 'display_name'> | undefined

  return {
    invite,
    folderName: folder.name || 'Shared Folder',
    ownerDisplayName: owner?.display_name || 'Folder owner',
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
  const trustProxy = req.app.get('trust proxy')
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

function parseBoundedInt(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === 'number' ? Math.trunc(value) : Number(value)
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}

function resolveHostedActorForRequest(req: Request): HostedSessionActor | null {
  const tokenFromHeader = extractHostedSessionToken(req)
  if (!tokenFromHeader) return null
  const db = getDb()
  return resolveHostedSession(db, tokenFromHeader)
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

const inviteCreateRateLimiter = createRateLimiter({
  name: 'invite-create',
  windowMs: 60_000,
  maxRequests: Number(process.env.INVITE_CREATE_MAX_PER_MINUTE || 30),
  keyFn: (req) => {
    const body = (req.body || {}) as CreateInviteBody
    return `${req.ip}:${body.ownerClientId || 'unknown'}:${body.folderId || 'unknown'}`
  },
})

const inviteRedeemRateLimiter = createRateLimiter({
  name: 'invite-redeem',
  windowMs: 60_000,
  maxRequests: Number(process.env.INVITE_REDEEM_MAX_PER_MINUTE || 60),
  keyFn: (req) => {
    const body = (req.body || {}) as RedeemInviteBody
    return `${req.ip}:${body.clientId || 'unknown'}`
  },
})

const invitePreviewRateLimiter = createRateLimiter({
  name: 'invite-preview',
  windowMs: 60_000,
  maxRequests: Number(process.env.INVITE_PREVIEW_MAX_PER_MINUTE || 60),
  keyFn: (req) => `${req.ip}`,
})

/** GET /api/invite/preview — Read-only invite metadata without consuming the token. */
inviteRouter.get('/preview', invitePreviewRateLimiter, (req: Request, res: Response) => {
  try {
    const tokenQuery = req.query.token
    const inviteToken = typeof tokenQuery === 'string' ? tokenQuery.trim() : ''
    if (!inviteToken) {
      res.status(400).json({ error: 'Missing token' })
      return
    }

    const metadata = getInvitePreviewMetadata(inviteToken)
    res.json({
      folderName: metadata.folderName,
      ownerDisplayName: metadata.ownerDisplayName,
      expiresAt: metadata.invite.expires_at,
      remainingUses: Math.max(0, metadata.invite.max_uses - metadata.invite.use_count),
    })
  } catch (error) {
    if (error instanceof InviteValidationError) {
      res.status(error.status).json({ error: error.message })
      return
    }
    const message = error instanceof Error ? error.message : 'Internal server error'
    console.error('[invite] Error previewing invite:', redactValue({ message, query: req.query }))
    res.status(500).json({ error: message })
  }
})

/** GET /api/invite/redeem — Browser redirect page that deep-links into Obsidian */
inviteRouter.get('/redeem', (req: Request, res: Response) => {
  const tokenQuery = req.query.token
  const inviteToken = typeof tokenQuery === 'string' ? tokenQuery.trim() : ''

  if (!inviteToken) {
    res
      .status(400)
      .type('html')
      .setHeader('Cache-Control', 'no-store')
      .setHeader('Referrer-Policy', 'no-referrer')
      .send(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Invite link invalid</title><link rel="icon" href="' +
          FAVICON_DATA_URL +
          '"></head><body><p>Invite link is missing a token.</p></body></html>'
      )
    return
  }

  try {
    getInvitePreviewMetadata(inviteToken)
  } catch (error) {
    if (error instanceof InviteValidationError) {
      res
        .status(error.status)
        .type('html')
        .setHeader('Cache-Control', 'no-store')
        .setHeader('Referrer-Policy', 'no-referrer')
        .send(renderInviteErrorPage(error.kind))
      return
    }
    const message = error instanceof Error ? error.message : 'Internal server error'
    console.error('[invite] Error validating invite for redeem page:', redactValue({ message, query: req.query }))
    res.status(500).type('html').send('<!doctype html><html><body><p>Internal server error.</p></body></html>')
    return
  }

  const deepLink = `obsidian://teams-join?token=${encodeURIComponent(inviteToken)}`
  const escapedDeepLink = escapeHtml(deepLink)
  const escapedInviteToken = escapeHtml(inviteToken)
  const escapedBratPluginUrl = escapeHtml(BRAT_PLUGIN_URL)
  const escapedGithubSourceUrl = escapeHtml(GITHUB_SOURCE_URL)
  const deepLinkLiteral = JSON.stringify(deepLink)

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
    <title>Open in Obsidian</title>
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
      * {
        box-sizing: border-box;
      }
      body {
        font-family: "Avenir Next", "Nunito Sans", "Segoe UI", sans-serif;
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 26px;
        background: var(--bg);
        color: var(--text-strong);
      }
      .wrap {
        width: min(760px, 100%);
      }
      .card {
        position: relative;
        overflow: hidden;
        padding: 28px 30px;
        border-radius: 22px;
        border: 1px solid var(--line);
        background: var(--surface);
        box-shadow:
          0 24px 70px rgba(39, 30, 11, 0.08),
          0 2px 8px rgba(39, 30, 11, 0.06);
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
        font-size: clamp(34px, 4vw, 54px);
        line-height: 0.94;
        letter-spacing: -0.02em;
      }
      .status {
        margin: 14px 0 0;
        display: inline-flex;
        align-items: center;
        gap: 10px;
        color: var(--text-soft);
        font-size: 19px;
        font-weight: 500;
      }
      .status-dot {
        width: 10px;
        height: 10px;
        border-radius: 999px;
        background: var(--accent-0);
        box-shadow: 0 0 0 0 rgba(204, 134, 0, 0.45);
        animation: pulse 1.7s infinite;
      }
      @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(204, 134, 0, 0.45); }
        100% { box-shadow: 0 0 0 12px rgba(204, 134, 0, 0); }
      }
      .actions {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        margin: 24px 0 20px;
      }
      a.button,
      button {
        border: 1px solid transparent;
        border-radius: 14px;
        padding: 15px 24px;
        font-size: 24px;
        line-height: 1;
        font-weight: 700;
        cursor: pointer;
        text-decoration: none;
        transition: transform 120ms ease, box-shadow 120ms ease, filter 120ms ease;
      }
      a.button:hover,
      button:hover {
        transform: translateY(-1px);
        filter: brightness(1.02);
      }
      a.button:active,
      button:active {
        transform: translateY(0);
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
        width: 100%;
        border: 2px solid #cfc3a8;
        border-radius: 14px;
        background: #fff;
        color: var(--text-strong);
        padding: 16px 18px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 14px;
        line-height: 1.1;
      }
      .token-row input {
        width: auto;
        min-width: 0;
        flex: 1 1 auto;
      }
      button.token-copy-button {
        flex: 0 0 auto;
        min-width: 68px;
        border-radius: 10px;
        padding: 0 12px;
        font-size: 13px;
        font-weight: 700;
      }
      .hint {
        margin: 12px 0 0;
        color: #736a58;
        font-size: 16px;
      }
      .accent-link {
        color: #6b5530;
        font-weight: 700;
        text-decoration-color: #b6883a;
        text-decoration-thickness: 2px;
        text-underline-offset: 2px;
      }
      .accent-link:hover {
        color: #4f3f24;
      }
      .install-modal {
        width: min(640px, calc(100vw - 32px));
        max-height: calc(100dvh - 20px);
        border: 1px solid #d6ccb4;
        border-radius: 18px;
        padding: 0;
        background: var(--surface);
        color: var(--text-strong);
        box-shadow:
          0 30px 90px rgba(35, 26, 8, 0.3),
          0 2px 10px rgba(35, 26, 8, 0.12);
      }
      .install-modal::backdrop {
        background: rgba(53, 46, 34, 0.45);
        backdrop-filter: blur(2px);
      }
      .install-modal-inner {
        margin: 0;
        padding: 24px;
        max-height: calc(100dvh - 20px);
        overflow-y: auto;
      }
      .install-modal-title {
        margin: 0;
        font-size: clamp(26px, 4vw, 32px);
        line-height: 1.05;
        letter-spacing: -0.015em;
      }
      .install-modal-lead {
        margin: 10px 0 0;
        color: #5f5748;
        line-height: 1.55;
      }
      .install-steps {
        margin: 18px 0 0;
        padding-left: 22px;
        color: #4f4738;
        line-height: 1.55;
      }
      .install-steps li + li {
        margin-top: 9px;
      }
      .install-steps code,
      .install-note code {
        border: 1px solid #d9cfb8;
        border-radius: 8px;
        background: #f4eddb;
        padding: 1px 6px;
        font-size: 13px;
        font-family: "JetBrains Mono", "SFMono-Regular", "Menlo", "Monaco", "Cascadia Mono", "Consolas", "Liberation Mono", "Courier New", monospace;
      }
      .install-note {
        margin: 14px 0 0;
        padding: 12px 14px;
        border: 1px solid #ddd2ba;
        border-radius: 12px;
        background: #f5efdf;
        color: #5a513f;
        font-size: 14px;
        line-height: 1.55;
      }
      .install-modal-actions {
        margin-top: 18px;
        display: flex;
        justify-content: flex-end;
      }
      .install-modal-actions .button {
        font-size: 16px;
        padding: 10px 16px;
      }
      @media (max-width: 800px) {
        .card {
          padding: 22px 20px;
          border-radius: 16px;
        }
        h1 {
          font-size: clamp(29px, 10vw, 44px);
        }
        .status {
          font-size: 17px;
        }
        a.button,
        button {
          font-size: 18px;
          padding: 13px 18px;
        }
        input {
          font-size: 16px;
          padding: 12px 13px;
        }
        button.token-copy-button {
          min-width: 64px;
          padding: 0 10px;
          font-size: 12px;
        }
        .hint {
          font-size: 14px;
        }
      }
      @media (max-width: 520px) {
        .actions > * {
          width: 100%;
          justify-content: center;
          text-align: center;
        }
        .install-modal-inner {
          padding: 18px;
        }
        .install-modal-actions .button {
          width: 100%;
        }
      }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <div class="eyebrow">Collaborative Folders invite</div>
        <h1>Opening Obsidian...</h1>
        <p class="status"><span class="status-dot" aria-hidden="true"></span><span id="status-text">Trying to launch the app now.</span></p>
        <div class="actions">
          <a class="button primary" href="${escapedDeepLink}" id="open-obsidian">Open in Obsidian</a>
          <button type="button" id="install-plugin">Install plugin</button>
        </div>
        <dialog class="install-modal" id="install-modal" aria-labelledby="install-modal-title">
          <form method="dialog" class="install-modal-inner">
            <h2 class="install-modal-title" id="install-modal-title">Install With BRAT</h2>
            <p class="install-modal-lead">
              The valiant Obsidian plugin reviewing team is facing an onslaught of submissions. It may be weeks or months until they get to this one and add it to the real directory. Until then, you can install it with a helper plugin called BRAT.
            </p>
            <ol class="install-steps">
              <li>
                Install BRAT
                by going to <a class="accent-link" href="${escapedBratPluginUrl}" target="_blank" rel="noopener noreferrer">this link</a> or opening <code>Settings -> Community plugins</code> and searching for it.
                (Enable Community plugins first if needed.)
              </li>
              <li>Toggle BRAT on in your Community plugins list.</li>
              <li>Open BRAT settings and click <code>Add beta plugin</code>.</li>
              <li>Paste <code>${escapedGithubSourceUrl}</code> and click <code>Add</code>.</li>
              <li>
                Open <code>Collaborative Folders</code> settings, set your display name, then either keep
                <code>https://collaborativefolders.com</code> or set your own <code>Server URL</code>.
              </li>
            </ol>
            <p class="install-note">
              p.s. if you want Obsidian to prioritize this plugin maybe add a reaction or drop a polite comment on
              <a class="accent-link" href="${OBSIDIAN_RELEASES_PR_URL}" target="_blank" rel="noopener noreferrer">${OBSIDIAN_RELEASES_PR_URL}</a>
              ... or ping any friends who work there :)
            </p>
            <div class="install-modal-actions">
              <button class="button secondary" type="submit" value="close">Close</button>
            </div>
          </form>
        </dialog>
        <div class="label">Invite token</div>
        <div class="token-row">
          <input id="invite-token" readonly value="${escapedInviteToken}">
          <button type="button" id="copy-token" class="token-copy-button">Copy</button>
        </div>
        <p class="hint">If your browser blocks app links, copy the token and run "Join shared folder" in Obsidian.</p>
      </div>
    </div>
    <script>
      const deepLink = ${deepLinkLiteral}
      const tokenInput = document.getElementById('invite-token')
      const copyButton = document.getElementById('copy-token')
      const installButton = document.getElementById('install-plugin')
      const installModal = document.getElementById('install-modal')
      const statusTextEl = document.getElementById('status-text')

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

      if (installButton instanceof HTMLButtonElement && installModal instanceof HTMLDialogElement) {
        installButton.addEventListener('click', () => {
          if (!installModal.open) installModal.showModal()
        })

        installModal.addEventListener('click', (event) => {
          if (event.target === installModal && installModal.open) {
            installModal.close()
          }
        })
      }

      copyButton?.addEventListener('click', async () => {
        if (!tokenInput) return
        try {
          await navigator.clipboard.writeText(tokenInput.value)
          if (statusTextEl) statusTextEl.textContent = 'Invite token copied.'
        } catch {
          tokenInput.select()
          if (statusTextEl) statusTextEl.textContent = 'Select and copy the invite token manually.'
        }
      })
    </script>
  </body>
</html>`)
})

/** POST /api/invite — Generate an invite link for a folder */
inviteRouter.post('/', inviteCreateRateLimiter, (req: Request, res: Response) => {
  try {
    const {
      folderId,
      folderName,
      role: requestedRole,
      ownerClientId,
      ownerDisplayName,
      expiresInHours,
      maxUses,
      inviteeLabel,
    } = req.body as CreateInviteBody

    if (!folderId) {
      res.status(400).json({ error: 'Missing required field: folderId' })
      return
    }

    if (requestedRole && requestedRole !== 'editor') {
      res.status(400).json({ error: 'Only editor invites are supported' })
      return
    }

    const db = getDb()
    const role = 'editor'
    const hostedMode = isHostedModeEnabled()
    const hostedSessionToken = extractHostedSessionToken(req)
    const hostedActor = resolveHostedActorForRequest(req)
    if (hostedMode && hostedSessionToken && !hostedActor) {
      res.status(401).json({
        error: 'Hosted session is invalid or expired',
        code: 'hosted_session_required',
      })
      return
    }

    const existing = db
      .prepare('SELECT id, name, owner_client_id, owner_account_id FROM folders WHERE id = ?')
      .get(folderId) as FolderRow | undefined
    let resolvedFolderName = folderName?.trim() || 'Shared Folder'

    let resolvedOwnerClientId = ownerClientId?.trim()
    let resolvedOwnerDisplayName = ownerDisplayName?.trim() || 'Owner'
    let hostedOwnerAccountId = existing?.owner_account_id || null

    if (existing) {
      resolvedFolderName = existing.name || resolvedFolderName
      const bearer = extractBearerToken(req)
      if (!bearer) {
        res.status(401).json({ error: 'Missing bearer token for existing shared folder' })
        return
      }

      let actor
      try {
        actor = actorFromToken(bearer)
      } catch {
        res.status(401).json({ error: 'Invalid or expired access token' })
        return
      }

      if (actor.folderId !== folderId || actor.role !== 'owner') {
        res.status(403).json({ error: 'Only the folder owner can create invites' })
        return
      }

      const memberAuth = getMemberAuthRow(db, folderId, actor.clientId)
      if (!memberAuth || memberAuth.role !== 'owner') {
        res.status(403).json({ error: 'No active owner membership for this folder' })
        return
      }
      if (memberAuth.token_version !== actor.tokenVersion) {
        res.status(401).json({ error: 'Owner token has been superseded' })
        return
      }
      if (actor.jti && isTokenRevoked(db, actor.jti)) {
        res.status(401).json({ error: 'Access token has been revoked' })
        return
      }

      if (resolvedOwnerClientId && resolvedOwnerClientId !== actor.clientId) {
        res.status(403).json({ error: 'ownerClientId does not match authenticated owner' })
        return
      }

      if (existing.owner_client_id !== actor.clientId) {
        res.status(403).json({ error: 'Authenticated token does not match folder owner' })
        return
      }

      resolvedOwnerClientId = actor.clientId
      resolvedOwnerDisplayName = actor.displayName || resolvedOwnerDisplayName

      if (hostedMode && existing.owner_account_id) {
        if (!hostedActor) {
          res.status(401).json({
            error: 'Hosted account link is required for invite creation',
            code: 'hosted_session_required',
          })
          return
        }

        if (hostedActor.accountId !== existing.owner_account_id) {
          res.status(403).json({ error: 'Hosted owner account is required' })
          return
        }

        const inviteEntitlementViolation = validateInviteCreateEntitlement(db, existing.owner_account_id)
        if (inviteEntitlementViolation) {
          res.status(inviteEntitlementViolation.status).json({
            error: inviteEntitlementViolation.error,
            code: inviteEntitlementViolation.code,
          })
          return
        }
      }
    }

    // First share bootstrap: create folder + owner membership without bearer token.
    if (!existing) {
      if (!resolvedOwnerClientId) {
        res.status(400).json({ error: 'Missing required field: ownerClientId for initial share' })
        return
      }

      if (hostedMode) {
        if (!hostedActor) {
          res.status(401).json({
            error: 'Hosted account link is required before first share',
            code: 'hosted_session_required',
          })
          return
        }

        hostedOwnerAccountId = hostedActor.accountId
        const inviteEntitlementViolation = validateInviteCreateEntitlement(db, hostedOwnerAccountId)
        if (inviteEntitlementViolation) {
          res.status(inviteEntitlementViolation.status).json({
            error: inviteEntitlementViolation.error,
            code: inviteEntitlementViolation.code,
          })
          return
        }
      }

      resolvedFolderName = folderName?.trim() || 'Shared Folder'
      db.prepare('INSERT INTO folders (id, name, owner_client_id, owner_account_id) VALUES (?, ?, ?, ?)').run(
        folderId,
        resolvedFolderName,
        resolvedOwnerClientId,
        hostedOwnerAccountId
      )
      db.prepare(
        `
        INSERT OR IGNORE INTO members (
          folder_id, client_id, account_id, display_name, role, token_version
        ) VALUES (?, ?, ?, ?, ?, 0)
      `
      ).run(folderId, resolvedOwnerClientId, hostedActor?.accountId || null, resolvedOwnerDisplayName, 'owner')
    }

    if (!resolvedOwnerClientId) {
      res.status(400).json({ error: 'Unable to resolve owner identity for invite creation' })
      return
    }

    const inviteQuota = consumeWindowedQuota({
      name: 'invite-create-hourly',
      key: `${folderId}:${resolvedOwnerClientId}`,
      windowMs: 3_600_000,
      maxAmount: INVITE_CREATE_MAX_PER_HOUR,
      amount: 1,
    })
    if (!inviteQuota.allowed) {
      writeAuditEvent(db, {
        folderId,
        actorClientId: resolvedOwnerClientId,
        eventType: 'rate_limit_violation',
        target: 'invite-create-hourly',
        metadata: { retryAfterSeconds: inviteQuota.retryAfterSeconds },
      })
      res.setHeader('Retry-After', String(inviteQuota.retryAfterSeconds))
      res.status(429).json({
        error: 'Invite creation quota exceeded',
        retryAfterSeconds: inviteQuota.retryAfterSeconds,
      })
      return
    }

    const ownerMember = db
      .prepare('SELECT role, token_version, display_name FROM members WHERE folder_id = ? AND client_id = ?')
      .get(folderId, resolvedOwnerClientId) as MemberTokenRow | undefined

    if (!ownerMember || ownerMember.role !== 'owner') {
      res.status(403).json({ error: 'Only the folder owner can create invites' })
      return
    }

    const effectiveExpiryHours = parseBoundedInt(
      expiresInHours,
      DEFAULT_INVITE_EXPIRY_HOURS,
      1,
      MAX_INVITE_EXPIRY_HOURS
    )
    const effectiveMaxUses = parseBoundedInt(maxUses, 1, 1, MAX_INVITE_USES_LIMIT)
    const normalizedInviteeLabel = inviteeLabel?.trim() || null
    const inviteExpiresAt = new Date(Date.now() + effectiveExpiryHours * 3600_000).toISOString()

    const ownerAccessToken = generateAccessToken(
      resolvedOwnerClientId,
      ownerMember.display_name || resolvedOwnerDisplayName,
      folderId,
      'owner',
      ownerMember.token_version
    )
    const issuedOwnerRefresh = issueRefreshToken(db, {
      folderId,
      clientId: resolvedOwnerClientId,
      displayName: ownerMember.display_name || resolvedOwnerDisplayName,
      role: 'owner',
      tokenVersion: ownerMember.token_version,
    })

    const inviteToken = generateInviteToken(resolvedFolderName)
    const tokenHash = crypto.createHash('sha256').update(inviteToken).digest('hex')

    db.prepare(`
      INSERT INTO invites (
        token_hash, folder_id, role, created_by, invitee_label, expires_at, max_uses, use_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
      tokenHash,
      folderId,
      role,
      resolvedOwnerClientId,
      normalizedInviteeLabel,
      inviteExpiresAt,
      effectiveMaxUses
    )

    writeAuditEvent(db, {
      folderId,
      actorClientId: resolvedOwnerClientId,
      eventType: 'invite_create',
      target: tokenHash,
      metadata: {
        maxUses: effectiveMaxUses,
        expiresAt: inviteExpiresAt,
        inviteeLabel: normalizedInviteeLabel,
      },
    })

    const serverUrl = resolveHttpBaseUrl(req)
    const inviteUrl = `${serverUrl}/api/invite/redeem?token=${inviteToken}`

    res.json({
      inviteToken,
      inviteUrl,
      ownerAccessToken,
      ownerRefreshToken: issuedOwnerRefresh.refreshToken,
    })
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Internal server error'
    console.error('[invite] Error creating invite:', redactValue({ message, body: req.body }))
    res.status(500).json({ error: message })
  }
})

/** POST /api/invite/redeem — Exchange an invite token for access + refresh tokens */
inviteRouter.post('/redeem', inviteRedeemRateLimiter, (req: Request, res: Response) => {
  try {
    const { inviteToken, clientId, displayName, hostedSessionToken, deviceLabel, deviceFingerprint } =
      req.body as RedeemInviteBody

    if (!inviteToken || !clientId || !displayName) {
      res.status(400).json({ error: 'Missing required fields: inviteToken, clientId, displayName' })
      return
    }

    const db = getDb()
    const tokenHash = crypto.createHash('sha256').update(inviteToken).digest('hex')
    const invite = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(tokenHash) as InviteRow | undefined

    if (!invite) {
      res.status(404).json({ error: 'Invite not found' })
      return
    }

    const folder = db
      .prepare('SELECT id, name, owner_client_id, owner_account_id FROM folders WHERE id = ?')
      .get(invite.folder_id) as FolderRow | undefined
    if (!folder) {
      res.status(404).json({ error: 'Folder not found for invite' })
      return
    }

    const hostedMode = isHostedModeEnabled()
    const incomingHostedSession =
      hostedSessionToken?.trim() || extractHostedSessionToken(req) || null
    const hostedActor = incomingHostedSession
      ? resolveHostedSession(db, incomingHostedSession)
      : null
    if (incomingHostedSession && !hostedActor) {
      res.status(401).json({
        error: 'Hosted session is invalid or expired',
        code: 'hosted_session_required',
      })
      return
    }

    if (invite.revoked_at) {
      res.status(410).json({ error: 'Invite has been revoked' })
      return
    }

    if (invite.expires_at && new Date(invite.expires_at).getTime() <= Date.now()) {
      res.status(410).json({ error: 'Invite has expired' })
      return
    }

    const existingMember = db
      .prepare('SELECT role FROM members WHERE folder_id = ? AND client_id = ?')
      .get(invite.folder_id, clientId) as Pick<MemberTokenRow, 'role'> | undefined
    if (existingMember) {
      res.status(409).json({
        error: existingMemberRedeemError(existingMember.role),
        code: 'already_member',
      })
      return
    }

    if (invite.use_count >= invite.max_uses) {
      res.status(410).json({ error: 'Invite already consumed' })
      return
    }

    const redeemQuota = consumeWindowedQuota({
      name: 'invite-redeem-hourly',
      key: `${invite.folder_id}:${clientId}`,
      windowMs: 3_600_000,
      maxAmount: INVITE_REDEEM_MAX_PER_HOUR,
      amount: 1,
    })
    if (!redeemQuota.allowed) {
      writeAuditEvent(db, {
        folderId: invite.folder_id,
        actorClientId: clientId,
        eventType: 'rate_limit_violation',
        target: 'invite-redeem-hourly',
        metadata: { retryAfterSeconds: redeemQuota.retryAfterSeconds },
      })
      res.setHeader('Retry-After', String(redeemQuota.retryAfterSeconds))
      res.status(429).json({
        error: 'Invite redeem quota exceeded',
        retryAfterSeconds: redeemQuota.retryAfterSeconds,
      })
      return
    }

    let useCountAfterRedeem = invite.use_count + 1
    let hostedAccountIdForMember: string | null = null

    db.exec('BEGIN IMMEDIATE')
    try {
      const inviteForMutation = db
        .prepare('SELECT * FROM invites WHERE token_hash = ?')
        .get(tokenHash) as InviteRow | undefined
      if (!inviteForMutation) {
        throw new InviteRedeemError(404, 'Invite not found')
      }
      if (inviteForMutation.revoked_at) {
        throw new InviteRedeemError(410, 'Invite has been revoked')
      }
      if (inviteForMutation.expires_at && new Date(inviteForMutation.expires_at).getTime() <= Date.now()) {
        throw new InviteRedeemError(410, 'Invite has expired')
      }
      const existingMemberForMutation = db
        .prepare('SELECT role FROM members WHERE folder_id = ? AND client_id = ?')
        .get(inviteForMutation.folder_id, clientId) as Pick<MemberTokenRow, 'role'> | undefined
      if (existingMemberForMutation) {
        throw new InviteRedeemError(
          409,
          existingMemberRedeemError(existingMemberForMutation.role),
          'already_member'
        )
      }

      if (inviteForMutation.use_count >= inviteForMutation.max_uses) {
        throw new InviteRedeemError(410, 'Invite already consumed')
      }

      if (hostedMode && folder.owner_account_id) {
        if (!hostedActor) {
          throw new InviteRedeemError(
            401,
            'Hosted account link is required before redeeming this invite',
            'hosted_session_required'
          )
        }

        const ownerViolation = validateInviteCreateEntitlement(db, folder.owner_account_id)
        if (ownerViolation) {
          throw new InviteRedeemError(ownerViolation.status, ownerViolation.error, ownerViolation.code)
        }

        const inviteeViolation = validateInviteRedeemEntitlement(db, hostedActor.accountId)
        if (inviteeViolation) {
          throw new InviteRedeemError(
            inviteeViolation.status,
            inviteeViolation.error,
            inviteeViolation.code
          )
        }

        hostedAccountIdForMember = hostedActor.accountId
      }

      const consumeResult = db.prepare(`
        UPDATE invites
        SET use_count = use_count + 1,
            consumed_by = ?,
            consumed_at = CASE WHEN (use_count + 1) >= max_uses THEN datetime('now') ELSE consumed_at END
        WHERE token_hash = ?
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
          AND use_count < max_uses
      `).run(clientId, tokenHash)

      if (consumeResult.changes !== 1) {
        throw new InviteRedeemError(410, 'Invite is no longer valid')
      }

      useCountAfterRedeem = inviteForMutation.use_count + 1

      const insertMemberResult = db.prepare(`
        INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
        VALUES (?, ?, ?, ?, ?, 0)
        ON CONFLICT(folder_id, client_id) DO NOTHING
      `).run(
        inviteForMutation.folder_id,
        clientId,
        hostedAccountIdForMember,
        displayName,
        inviteForMutation.role
      )

      if (insertMemberResult.changes !== 1) {
        throw new InviteRedeemError(409, 'Client is already a member of this folder', 'already_member')
      }

      db.exec('COMMIT')
    } catch (error) {
      db.exec('ROLLBACK')
      throw error
    }

    const member = db
      .prepare('SELECT role, token_version, display_name FROM members WHERE folder_id = ? AND client_id = ?')
      .get(invite.folder_id, clientId) as MemberTokenRow | undefined
    if (!member) {
      res.status(500).json({ error: 'Failed to resolve member token state' })
      return
    }

    const accessToken = generateAccessToken(
      clientId,
      member.display_name,
      invite.folder_id,
      member.role,
      member.token_version
    )
    const issuedRefresh = issueRefreshToken(db, {
      folderId: invite.folder_id,
      clientId,
      displayName: member.display_name,
      role: member.role,
      tokenVersion: member.token_version,
    })

    writeAuditEvent(db, {
      folderId: invite.folder_id,
      actorClientId: clientId,
      eventType: 'invite_redeem',
      target: tokenHash,
      metadata: {
        deviceLabel: deviceLabel || null,
        deviceFingerprint: deviceFingerprint || null,
        useCountAfterRedeem,
        hostedAccountId: hostedAccountIdForMember,
      },
    })

    const serverUrl = resolveHttpBaseUrl(req)

    res.json({
      accessToken,
      refreshToken: issuedRefresh.refreshToken,
      folderId: invite.folder_id,
      folderName: folder?.name || 'Shared Folder',
      serverUrl,
    })
  } catch (err: unknown) {
    if (err instanceof InviteRedeemError) {
      res.status(err.status).json({
        error: err.message,
        ...(err.code ? { code: err.code } : {}),
      })
      return
    }
    const message = err instanceof Error ? err.message : 'Internal server error'
    console.error('[invite] Error redeeming invite:', redactValue({ message, body: req.body }))
    res.status(500).json({ error: message })
  }
})
