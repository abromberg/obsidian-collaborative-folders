/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import express from 'express'
import cors from 'cors'
import type { NextFunction, Request, Response } from 'express'
import { createServer } from 'http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { WebSocketServer } from 'ws'
import {
  BLOB_AAD_HEADER,
  BLOB_DIGEST_HEADER,
  BLOB_NONCE_HEADER,
  HOSTED_SESSION_HEADER,
  KEY_EPOCH_HEADER,
  PROTOCOL_HEADER,
  PROTOCOL_V2,
} from '@obsidian-teams/shared'
import { authRouter } from './routes/auth.js'
import { inviteRouter } from './routes/invite.js'
import { fileLinksRouter } from './routes/file-links.js'
import { foldersRouter } from './routes/folders.js'
import { blobsRouter } from './routes/blobs.js'
import { keysRouter } from './routes/keys.js'
import { wsRouter } from './routes/ws.js'
import { resetVerificationRouter } from './routes/reset-verification.js'
import { hostedAuthRouter } from './routes/hosted-auth.js'
import { hostedBillingRouter, hostedBillingWebhookHandler } from './routes/hosted-billing.js'
import { getDb, initDb } from './db/schema.js'
import { getSecurityMetrics } from './security/metrics.js'
import { EncryptedRelay } from './ws/encrypted-relay.js'
import { redactValue } from './security/redaction.js'
import { requireAdminToken } from './middleware/require-admin-token.js'
import {
  hostedMaxFileSizeBytes,
  hostedSeatPriceCents,
  hostedStorageCapBytes,
  isHostedBillingConfigured,
  isHostedModeEnabled,
} from './config/hosted.js'

const PORT = Number(process.env.PORT) || 1234
const HOSTED_MODE = isHostedModeEnabled()
const CORS_ALLOWED_ORIGINS = new Set(
  (process.env.CORS_ALLOWED_ORIGINS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
)
const ALWAYS_ALLOWED_ORIGINS = new Set([
  'app://obsidian.md',
  'null',
])
const PROTOCOL_GATE_ENABLED = true
const BRAT_PLUGIN_URL = 'https://obsidian.md/plugins?id=brat'
const GITHUB_SOURCE_URL = 'https://github.com/abromberg/obsidian-collaborative-folders'
const BRAT_INSTALL_REPO_URL = 'abromberg/obsidian-collaborative-folders-plugin'
const OBSIDIAN_RELEASES_PR_URL = 'https://github.com/obsidianmd/obsidian-releases/pull/10655'
const FAVICON_DATA_URL =
  'data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270%200%20100%20100%27%3E%3Ctext y=%27.9em%27 font-size=%2790%27%3E%F0%9F%93%99%3C/text%3E%3C/svg%3E'
const COPYRIGHT_YEAR = new Date().getFullYear()
const LEGAL_LAST_UPDATED = 'February 28, 2026'
const LEGAL_CONTACT_EMAIL = 'a@experimental.energy'
const LEGAL_CONTACT_EMAIL_HREF = `mailto:${LEGAL_CONTACT_EMAIL}`
const LEGAL_CONTACT_URL = `${GITHUB_SOURCE_URL}/issues`
const HOSTED_DEFAULT_SEAT_PRICE_CENTS = hostedSeatPriceCents()
const HOSTED_DEFAULT_STORAGE_CAP_BYTES = hostedStorageCapBytes()
const HOSTED_DEFAULT_MAX_FILE_SIZE_BYTES = hostedMaxFileSizeBytes()
const HOSTED_DEFAULT_SEAT_PRICE = formatUsdFromCents(HOSTED_DEFAULT_SEAT_PRICE_CENTS)
const HOSTED_DEFAULT_STORAGE_CAP = formatSizeLimit(HOSTED_DEFAULT_STORAGE_CAP_BYTES)
const HOSTED_DEFAULT_MAX_FILE_SIZE = formatSizeLimit(HOSTED_DEFAULT_MAX_FILE_SIZE_BYTES)
const SERVER_FILE_PATH = fileURLToPath(import.meta.url)
const SERVER_DIR_PATH = path.dirname(SERVER_FILE_PATH)
const DEMO_VIDEO_URL = '/media/collab_demo.mp4'
const DEFAULT_PUBLIC_HTTP_URL = 'https://collaborativefolders.com'
const SOCIAL_OG_IMAGE_PATH = '/media/collaborativefolders_og.png'
const SOCIAL_OG_IMAGE_WIDTH = '1200'
const SOCIAL_OG_IMAGE_HEIGHT = '630'

function formatUsdFromCents(cents: number): string {
  const dollars = Math.max(0, cents) / 100
  const hasFractionalCents = cents % 100 !== 0
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: hasFractionalCents ? 2 : 0,
    maximumFractionDigits: 2,
  }).format(dollars)
}

function formatSizeLimit(bytes: number): string {
  if (bytes <= 0) return '0B'
  const kibibyte = 1024
  const mebibyte = kibibyte * 1024
  const gibibyte = mebibyte * 1024

  if (bytes >= gibibyte) {
    const value = Number((bytes / gibibyte).toFixed(1)).toString()
    return `${value}GB`
  }
  if (bytes >= mebibyte) {
    const value = Number((bytes / mebibyte).toFixed(1)).toString()
    return `${value}MB`
  }
  if (bytes >= kibibyte) {
    const value = Number((bytes / kibibyte).toFixed(1)).toString()
    return `${value}KB`
  }
  return `${bytes}B`
}

function resolveTrustProxySetting(): boolean | number | string | string[] {
  const raw = process.env.TRUST_PROXY?.trim()
  if (!raw) return false
  if (raw === 'true') return true
  if (raw === 'false') return false

  const numeric = Number(raw)
  if (Number.isInteger(numeric) && numeric >= 0) {
    return numeric
  }

  const csv = raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
  if (csv.length > 1) return csv

  return raw
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

function resolvePublicHttpBaseUrl(req: Request): string {
  const configured = process.env.PUBLIC_HTTP_URL || process.env.SERVER_URL
  if (configured) return trimTrailingSlash(configured)

  const trustForwarded = shouldUseForwardedHeaders(req)
  const proto = (trustForwarded ? readForwarded(req, 'x-forwarded-proto') : null) || req.protocol || 'http'
  const host = (trustForwarded ? readForwarded(req, 'x-forwarded-host') : null) || req.get('host')
  if (!host) return DEFAULT_PUBLIC_HTTP_URL
  return `${proto}://${host}`
}

function escapeHtmlAttribute(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function looksLikeHtml(value: string): boolean {
  return /^\s*<!doctype html/i.test(value) || /^\s*<html/i.test(value)
}

function injectSocialImageMetaTags(html: string, req: Request): string {
  if (!looksLikeHtml(html)) return html
  if (/property=["']og:image["']/i.test(html) || /name=["']twitter:image["']/i.test(html)) return html

  const baseUrl = resolvePublicHttpBaseUrl(req)
  const ogImageUrl = `${baseUrl}${SOCIAL_OG_IMAGE_PATH}`
  const escapedOgImageUrl = escapeHtmlAttribute(ogImageUrl)

  const socialMeta = `
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="Obsidian Collaborative Folders">
    <meta property="og:image" content="${escapedOgImageUrl}">
    <meta property="og:image:width" content="${SOCIAL_OG_IMAGE_WIDTH}">
    <meta property="og:image:height" content="${SOCIAL_OG_IMAGE_HEIGHT}">
    <meta property="og:image:type" content="image/png">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:image" content="${escapedOgImageUrl}">`

  if (/<head\b[^>]*>/i.test(html)) {
    return html.replace(/<head\b([^>]*)>/i, `<head$1>${socialMeta}`)
  }

  return html.replace(/<html\b([^>]*)>/i, `<html$1><head>${socialMeta}</head>`)
}

function requireV2HttpProtocol(req: Request, res: Response, next: NextFunction): void {
  // CORS preflight should not require application protocol headers.
  if (req.method === 'OPTIONS') {
    next()
    return
  }

  const isPublicInviteRedeemPath = req.path === '/invite/redeem' || req.path === '/invite/redeem/'
  const isPublicFileLinkOpenPath = req.path === '/file-links/open' || req.path === '/file-links/open/'
  const isPublicFileLinkPreviewPath = req.path === '/file-links/preview' || req.path === '/file-links/preview/'
  const isHostedBillingReturnPath = req.path === '/hosted/billing/return' || req.path === '/hosted/billing/return/'
  if (
    (req.method === 'GET' || req.method === 'HEAD')
    && (
      isPublicInviteRedeemPath
      || isPublicFileLinkOpenPath
      || isPublicFileLinkPreviewPath
      || isHostedBillingReturnPath
    )
  ) {
    next()
    return
  }

  if (req.path === '/reset-verification' || req.path.startsWith('/reset-verification/')) {
    next()
    return
  }

  const protocol = req.header(PROTOCOL_HEADER)?.trim()
  if (protocol === PROTOCOL_V2) {
    next()
    return
  }

  res.status(426).json({
    error: 'Protocol v2 required',
    requiredProtocol: PROTOCOL_V2,
    requiredHeader: PROTOCOL_HEADER,
  })
}

function resolveUpgradeProtocolVersion(request: Request | { url?: string; headers: Record<string, string | string[] | undefined> }): string | null {
  const headerValue = request.headers[PROTOCOL_HEADER]
  const headerProtocol =
    typeof headerValue === 'string'
      ? headerValue.trim()
      : Array.isArray(headerValue)
        ? headerValue[0]?.trim()
        : null

  const parsed = new URL(request.url || '/', 'http://localhost')
  const queryProtocol = parsed.searchParams.get('protocol')?.trim()

  return queryProtocol || headerProtocol || null
}

function renderLegalPage(options: {
  title: string
  summary: string
  bodyHtml: string
}): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${options.title} - Obsidian Collaborative Folders</title>
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
        margin: 0;
        min-height: 100vh;
        padding: 26px;
        background:
          radial-gradient(circle at 10% 14%, rgba(204, 134, 0, 0.11) 0, rgba(204, 134, 0, 0) 30%),
          radial-gradient(circle at 84% 88%, rgba(118, 93, 49, 0.12) 0, rgba(118, 93, 49, 0) 32%),
          var(--bg);
        color: var(--text-strong);
        font-family: "Avenir Next", "Nunito Sans", "Segoe UI", sans-serif;
      }
      .wrap {
        width: min(900px, 100%);
        margin: 0 auto;
      }
      .card {
        border: 1px solid var(--line);
        border-radius: 22px;
        background: var(--surface);
        box-shadow:
          0 24px 70px rgba(39, 30, 11, 0.08),
          0 2px 8px rgba(39, 30, 11, 0.06);
        padding: 30px;
      }
      .top {
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: center;
        gap: 10px 16px;
        margin-bottom: 24px;
      }
      .nav {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }
      .nav a,
      .back-link {
        display: inline-flex;
        align-items: center;
        border: 1px solid #ddd3ba;
        border-radius: 999px;
        padding: 7px 12px;
        background: #f4edd9;
        color: #5f533f;
        text-decoration: none;
        font-size: 14px;
        font-weight: 700;
        letter-spacing: 0.01em;
        transition: transform 120ms ease, filter 120ms ease, box-shadow 120ms ease;
      }
      .nav a:hover,
      .back-link:hover {
        transform: translateY(-1px);
        filter: brightness(1.02);
        box-shadow: 0 6px 14px rgba(51, 41, 19, 0.09);
      }
      .nav a:active,
      .back-link:active {
        transform: translateY(0);
      }
      h1 {
        margin: 0 0 4px;
        font-size: clamp(32px, 4vw, 52px);
        line-height: 0.98;
        letter-spacing: -0.02em;
      }
      .summary {
        margin: 0;
        color: var(--text-soft);
        font-size: clamp(16px, 2vw, 20px);
        line-height: 1.45;
        max-width: 55ch;
      }
      .updated {
        margin: 10px 0 0;
        font-size: 14px;
        color: #746a58;
      }
      .content {
        margin-top: 24px;
      }
      .content section + section {
        margin-top: 16px;
      }
      .content h2 {
        margin: 0;
        font-size: 18px;
        line-height: 1.3;
      }
      .content p {
        margin: 8px 0 0;
        color: #5d5341;
        line-height: 1.58;
      }
      .content ul {
        margin: 8px 0 0 20px;
        color: #5d5341;
        line-height: 1.58;
      }
      .accent-link,
      .content a,
      .footer a {
        color: #6b5530;
        font-weight: 700;
        text-decoration-color: #b6883a;
        text-decoration-thickness: 2px;
        text-underline-offset: 2px;
      }
      .accent-link:hover,
      .content a:hover,
      .footer a:hover {
        color: #4f3f24;
      }
      .footer {
        margin-top: 24px;
        padding-top: 16px;
        border-top: 1px solid #ddd2ba;
      }
      .copyright {
        margin: 8px 0 0;
        color: #7b705d;
        font-size: 13px;
      }
      @media (max-width: 960px) {
        body {
          padding: 18px;
        }
      }
      @media (max-width: 800px) {
        .card {
          border-radius: 16px;
          padding: 22px 20px;
        }
      }
      @media (max-width: 640px) {
        body {
          padding: 12px;
        }
        .top {
          margin-bottom: 18px;
        }
        h1 {
          font-size: clamp(28px, 10vw, 40px);
          line-height: 1;
        }
        .summary {
          font-size: 16px;
        }
        .content {
          margin-top: 18px;
        }
      }
      @media (max-width: 520px) {
        body {
          padding: 10px;
        }
        .card {
          border-radius: 14px;
          padding: 18px 14px;
        }
        .top {
          display: grid;
          gap: 8px;
        }
        .back-link {
          width: 100%;
          justify-content: center;
        }
        .nav {
          width: 100%;
        }
        .nav a {
          flex: 1 1 0;
          justify-content: center;
        }
        .content h2 {
          font-size: 17px;
        }
        .content p,
        .content ul {
          font-size: 15px;
          line-height: 1.52;
        }
      }
    </style>
  </head>
  <body>
    <main class="wrap">
      <section class="card">
        <div class="top">
          <a class="back-link" href="/">&larr; Back to home</a>
          <nav class="nav" aria-label="Legal links">
            <a href="/privacy">Privacy</a>
            <a href="/terms">Terms</a>
          </nav>
        </div>
        <h1>${options.title}</h1>
        <p class="summary">${options.summary}</p>
        <p class="updated">Last updated: ${LEGAL_LAST_UPDATED}</p>
        <div class="content">
          ${options.bodyHtml}
        </div>
        <footer class="footer">
          <p>
            Questions about this page? Email
            <a href="${LEGAL_CONTACT_EMAIL_HREF}">${LEGAL_CONTACT_EMAIL}</a>
            or
            <a href="${LEGAL_CONTACT_URL}" target="_blank" rel="noopener noreferrer">open an issue on GitHub</a>.
          </p>
          <p class="copyright">
            Copyright © ${COPYRIGHT_YEAR} Experimental LLC. Developed by
            <a class="accent-link" href="https://andybromberg.com" target="_blank" rel="noopener noreferrer">Andy Bromberg</a>.
          </p>
        </footer>
      </section>
    </main>
  </body>
</html>`
}

initDb()

const app = express()
app.set('trust proxy', resolveTrustProxySetting())
app.use(
  cors({
    exposedHeaders: [
      KEY_EPOCH_HEADER,
      BLOB_NONCE_HEADER,
      BLOB_AAD_HEADER,
      BLOB_DIGEST_HEADER,
      PROTOCOL_HEADER,
      HOSTED_SESSION_HEADER,
    ],
    origin(origin, callback) {
      if (!origin) {
        callback(null, true)
        return
      }

      if (ALWAYS_ALLOWED_ORIGINS.has(origin)) {
        callback(null, true)
        return
      }

      // Default-open CORS when no explicit allowlist is configured.
      if (CORS_ALLOWED_ORIGINS.size === 0) {
        callback(null, true)
        return
      }

      if (CORS_ALLOWED_ORIGINS.has('*')) {
        callback(null, true)
        return
      }

      callback(null, CORS_ALLOWED_ORIGINS.has(origin))
    },
  })
)

if (HOSTED_MODE) {
  app.post(
    '/api/hosted/billing/webhook',
    express.raw({ type: 'application/json' }),
    hostedBillingWebhookHandler
  )
}

app.use(express.json())
app.use((req: Request, res: Response, next: NextFunction) => {
  const originalSend = res.send.bind(res)

  res.send = ((body: unknown): Response => {
    const contentType = String(res.getHeader('Content-Type') || '')
    const shouldAttemptHtmlMetaInjection = typeof body === 'string' || Buffer.isBuffer(body)
    if (shouldAttemptHtmlMetaInjection) {
      const htmlBody = typeof body === 'string' ? body : body.toString('utf8')
      if (contentType.includes('text/html') || looksLikeHtml(htmlBody)) {
        const updatedHtml = injectSocialImageMetaTags(htmlBody, req)
        return originalSend(updatedHtml)
      }
    }

    return originalSend(body as never)
  }) as typeof res.send

  next()
})
app.use(
  '/media',
  express.static(path.resolve(SERVER_DIR_PATH, '../media'), {
    maxAge: '7d',
  })
)
app.use('/api', requireV2HttpProtocol)

app.use('/api/auth', authRouter)
app.use('/api/invite', inviteRouter)
app.use('/api', fileLinksRouter)
app.use('/api/folders', foldersRouter)
app.use('/api/folders', blobsRouter)
app.use('/api/folders', keysRouter)
app.use('/api/folders', wsRouter)
app.use('/api', resetVerificationRouter)

if (HOSTED_MODE) {
  app.use('/api/hosted/auth', hostedAuthRouter)
  app.use('/api/hosted/billing', hostedBillingRouter)
}

app.get('/', (_req, res) => {
  res
    .status(200)
    .type('html')
    .send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Obsidian Collaborative Folders</title>
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
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: start center;
        padding: 26px;
        background:
          radial-gradient(circle at 8% 18%, rgba(204, 134, 0, 0.12) 0, rgba(204, 134, 0, 0) 30%),
          radial-gradient(circle at 92% 82%, rgba(118, 93, 49, 0.12) 0, rgba(118, 93, 49, 0) 34%),
          var(--bg);
        color: var(--text-strong);
        font-family: "Avenir Next", "Nunito Sans", "Segoe UI", sans-serif;
      }
      .wrap {
        width: min(860px, 100%);
      }
      .card {
        border: 1px solid var(--line);
        border-radius: 22px;
        background: var(--surface);
        box-shadow:
          0 24px 70px rgba(39, 30, 11, 0.08),
          0 2px 8px rgba(39, 30, 11, 0.06);
        padding: 30px;
      }
      .eyebrow {
        margin: 0 0 10px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #786f5e;
      }
      h1 {
        margin: 0;
        font-size: clamp(34px, 5vw, 56px);
        line-height: 0.95;
        letter-spacing: -0.02em;
      }
      .lead-row {
        margin-top: 14px;
        display: flex;
        justify-content: flex-start;
        align-items: flex-start;
        gap: 5px;
      }
      .lead-copy {
        width: min(50ch, 100%);
        flex: 0 0 auto;
        max-width: 50ch;
      }
      .agent-note {
        display: inline-block;
        position: relative;
        width: fit-content;
        margin: 3px 0 0;
        flex: 0 0 auto;
      }
      .agent-sticker {
        list-style: none;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        border: 1px solid #d5b980;
        border-radius: 12px;
        padding: 7px 12px;
        background: linear-gradient(145deg, #f8ebca 0%, #f3e0b7 100%);
        color: #5a431a;
        font-size: 13px;
        font-weight: 800;
        letter-spacing: 0.01em;
        box-shadow:
          0 8px 16px rgba(119, 85, 22, 0.14),
          0 1px 0 rgba(255, 248, 225, 0.76) inset;
        transform: rotate(8.5deg);
        transform-origin: 22% 44%;
        transition: transform 120ms ease, box-shadow 120ms ease, filter 120ms ease;
        animation: agent-sticker-float 3.5s ease-in-out infinite;
        user-select: none;
      }
      .agent-sticker-icon {
        width: 14px;
        height: 14px;
        flex: 0 0 auto;
        stroke: currentColor;
        fill: none;
        stroke-width: 1.8;
        stroke-linecap: round;
        stroke-linejoin: round;
        opacity: 0.92;
      }
      .agent-note:hover .agent-sticker,
      .agent-note[open] .agent-sticker {
        transform: translateY(-1px) rotate(7deg);
        box-shadow:
          0 10px 18px rgba(119, 85, 22, 0.18),
          0 1px 0 rgba(255, 248, 225, 0.8) inset;
        filter: brightness(1.015);
        animation: agent-sticker-wobble 240ms ease-out 1;
      }
      .agent-sticker:active {
        transform: translateY(0) rotate(7.8deg);
      }
      .agent-sticker:focus-visible {
        outline: 2px solid rgba(126, 87, 15, 0.42);
        outline-offset: 2px;
      }
      .agent-sticker::-webkit-details-marker {
        display: none;
      }
      @keyframes agent-sticker-wobble {
        0% {
          transform: translateY(-1px) rotate(7deg);
        }
        30% {
          transform: translateY(-1px) rotate(8.9deg);
        }
        60% {
          transform: translateY(-1px) rotate(6.2deg);
        }
        82% {
          transform: translateY(-1px) rotate(8deg);
        }
        100% {
          transform: translateY(-1px) rotate(7deg);
        }
      }
      @keyframes agent-sticker-float {
        0%, 100% { transform: rotate(8.5deg); }
        50% { transform: rotate(7.5deg) translateY(-1px); }
      }
      .agent-popup {
        position: absolute;
        left: 0;
        top: calc(100% + 7px);
        width: min(34ch, calc(100vw - 72px));
        margin: 0;
        padding: 11px 13px;
        border: 1px solid #ddd2ba;
        border-radius: 14px;
        background: #fbf8ef;
        color: #5f5441;
        font-family: "JetBrains Mono", "SFMono-Regular", "Menlo", "Monaco", "Cascadia Mono", "Consolas", "Liberation Mono", "Courier New", monospace;
        font-size: 14px;
        line-height: 1.45;
        box-shadow:
          0 18px 40px rgba(39, 30, 11, 0.12),
          0 2px 6px rgba(39, 30, 11, 0.06);
        z-index: 2;
      }
      .agent-popup::before {
        content: '';
        position: absolute;
        top: -6px;
        left: 19px;
        width: 12px;
        height: 12px;
        background: #fbf8ef;
        border-left: 1px solid #ddd2ba;
        border-top: 1px solid #ddd2ba;
        transform: rotate(45deg);
      }
      .agent-note[open] > .agent-popup {
        animation: agent-popup-enter 300ms cubic-bezier(0.22, 1, 0.36, 1);
      }
      @keyframes agent-popup-enter {
        from {
          opacity: 0;
          transform: translateY(8px) scale(0.95);
        }
        60% {
          opacity: 1;
          transform: translateY(-1px) scale(1.005);
        }
        to {
          transform: translateY(0) scale(1);
        }
      }
      .lead {
        margin: 0;
        color: var(--text-soft);
        font-size: clamp(17px, 2.2vw, 22px);
        line-height: 1.45;
      }
      .lead + .lead {
        margin-top: 14px;
      }
      .actions {
        margin-top: 22px;
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
      }
      .button {
        appearance: none;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        text-decoration: none;
        border: 1px solid transparent;
        border-radius: 14px;
        padding: 15px 22px;
        font-size: 20px;
        font-weight: 700;
        line-height: 1;
        font-family: inherit;
        cursor: pointer;
        transition: transform 120ms ease, box-shadow 120ms ease, filter 120ms ease;
      }
      .button:hover {
        transform: translateY(-1px);
        filter: brightness(1.02);
      }
      .button:active {
        transform: translateY(0);
      }
      .button:focus-visible {
        outline: 2px solid rgba(117, 81, 22, 0.38);
        outline-offset: 2px;
      }
      .button.primary {
        background: var(--accent-0);
        color: #fff;
        box-shadow: 0 12px 28px rgba(158, 100, 0, 0.25);
      }
      .button.secondary {
        background: var(--accent-soft);
        color: var(--text-strong);
        border-color: #ddd3ba;
      }
      .button-icon {
        width: 18px;
        height: 18px;
        fill: currentColor;
        flex: 0 0 auto;
      }
      .grid {
        margin-top: 26px;
        display: grid;
        gap: 12px;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      }
      .demo {
        margin-top: 24px;
        position: relative;
      }
      .demo-agent-note {
        position: absolute;
        right: 8px;
        top: -14px;
        z-index: 3;
      }
      .demo-agent-note .agent-popup {
        left: -74px;
        right: auto;
      }
      .demo-agent-note .agent-popup::before {
        left: 84px;
        right: auto;
      }
      .demo-title {
        margin: 0;
        font-size: 13px;
        color: #6e6554;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 700;
      }
      .demo-frame {
        margin-top: 10px;
        border: 1px solid #ddd2ba;
        border-radius: 16px;
        background: #121212;
        aspect-ratio: 16 / 9;
        overflow: hidden;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.65);
      }
      .demo-video {
        display: block;
        width: 100%;
        height: 100%;
        object-fit: cover;
        background: #121212;
      }
      .tile {
        border: 1px solid #e0d7c0;
        border-radius: 14px;
        padding: 14px;
        background: #fff;
      }
      .tile-title {
        margin: 0;
        font-size: 14px;
        font-weight: 700;
        letter-spacing: 0.03em;
        text-transform: uppercase;
        color: #6d634f;
      }
      .tile p {
        margin: 6px 0 0;
        color: #5f5748;
        line-height: 1.45;
      }
      .meta {
        margin-top: 18px;
        border: 1px solid #ddd2ba;
        border-radius: 12px;
        padding: 14px 15px;
        background: #f5efdf;
        color: #5f5441;
        font-size: 14px;
        line-height: 1.56;
      }
      .legal-links {
        margin-top: 14px;
        display: flex;
        gap: 14px;
        flex-wrap: wrap;
      }
      .legal-links a {
        color: #6d634f;
        text-decoration: underline;
        text-underline-offset: 3px;
      }
      .accent-link {
        color: #6b5530;
        font-weight: 700;
        text-decoration-color: #b6883a;
        text-decoration-thickness: 2px;
        text-underline-offset: 2px;
      }
      .obsidian-link {
        display: inline-flex;
        align-items: baseline;
        gap: 0.2em;
        vertical-align: baseline;
      }
      .obsidian-logo {
        width: 0.9em;
        height: 0.9em;
        flex: 0 0 auto;
      }
      .accent-link:hover {
        color: #4f3f24;
      }
      .copyright {
        margin: 10px 0 0;
        color: #7b705d;
        font-size: 13px;
      }
      .install-modal {
        width: min(640px, calc(100vw - 32px));
        max-height: calc(100dvh - 20px);
        border: 1px solid #d6ccb4;
        border-radius: 18px;
        padding: 0;
        background: #fbf8ef;
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
      @media (max-width: 920px) {
        body {
          padding: 18px;
        }
        .card {
          border-radius: 16px;
          padding: 22px 20px;
        }
        .lead-row {
          display: block;
        }
        .agent-note {
          display: none;
        }
        .button {
          font-size: 17px;
          padding: 13px 16px;
        }
      }
      @media (max-width: 640px) {
        body {
          padding: 10px;
        }
        .card {
          border-radius: 14px;
          padding: 18px 14px;
        }
        h1 {
          font-size: clamp(30px, 11vw, 42px);
          line-height: 0.98;
        }
        .lead {
          font-size: 16px;
          line-height: 1.5;
        }
        .actions {
          margin-top: 18px;
          gap: 10px;
        }
        .button {
          font-size: 16px;
          padding: 12px 14px;
        }
        .grid {
          margin-top: 20px;
          grid-template-columns: 1fr;
        }
        .demo {
          margin-top: 20px;
        }
        .meta {
          margin-top: 14px;
          padding: 12px;
        }
        .legal-links {
          gap: 10px 12px;
        }
        .actions .button {
          width: 100%;
          text-align: center;
        }
      }
      @media (max-width: 520px) {
        .actions .button {
          width: 100%;
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
    <main class="wrap">
      <section class="card">
        <p class="eyebrow">Obsidian Collaborative Folders</p>
        <h1>Multiplayer folders & notes in Obsidian.</h1>
        <div class="lead-row">
          <div class="lead-copy">
            <p class="lead">
              Real-time, end-to-end encrypted sharing. Everything you love about Google Docs, but in your lovely local <a class="accent-link obsidian-link" href="https://obsidian.md/?ref=collaborativefolders" target="_blank" rel="noopener noreferrer"><img class="obsidian-logo" src="https://obsidian.md/images/obsidian-logo-gradient.svg" alt="" aria-hidden="true" loading="lazy" decoding="async" /><span>Obsidian</span></a>.
            </p>
            <p class="lead">
              Use our <a class="accent-link" href="/pricing">hosted service</a> or easily deploy the MIT-licensed stack yourself.
            </p>
          </div>
        </div>

        <div class="actions">
          <button class="button primary" type="button" id="install-plugin">Install plugin</button>
          <a class="button secondary" href="${GITHUB_SOURCE_URL}" target="_blank" rel="noopener noreferrer">
            <svg class="button-icon" viewBox="0 0 16 16" aria-hidden="true">
              <path d="M8 0C3.58 0 0 3.58 0 8a8.01 8.01 0 0 0 5.47 7.59c.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49C4 14.09 3.48 12.81 3.32 12.32c-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.5-1.07-1.78-.2-3.64-.89-3.64-3.96 0-.88.31-1.6.82-2.17-.08-.2-.36-1.02.08-2.12 0 0 .67-.22 2.2.82a7.52 7.52 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.57.82 1.29.82 2.17 0 3.08-1.87 3.76-3.65 3.96.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.19 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path>
            </svg>
            <span>View source</span>
          </a>
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
                by going to <a class="accent-link" href="${BRAT_PLUGIN_URL}" target="_blank" rel="noopener noreferrer">this link</a> or opening <code>Settings -> Community plugins</code> and searching for it.
                (Enable Community plugins first if needed.)
              </li>
              <li>Toggle BRAT on in your Community plugins list.</li>
              <li>Open BRAT settings and click <code>Add beta plugin</code>.</li>
              <li>Paste <code>${BRAT_INSTALL_REPO_URL}</code> and click <code>Add</code>.</li>
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

        <section class="demo" aria-label="Video demo">
          <details class="agent-note demo-agent-note">
            <summary class="agent-sticker">
              <svg class="agent-sticker-icon" viewBox="0 0 16 16" aria-hidden="true">
                <rect x="2.5" y="4.5" width="11" height="8" rx="3"></rect>
                <path d="M8 2.5v2"></path>
                <circle cx="6" cy="8.5" r="0.8" fill="currentColor" stroke="none"></circle>
                <circle cx="10" cy="8.5" r="0.8" fill="currentColor" stroke="none"></circle>
              </svg>
              <span>Agent-friendly, too!</span>
            </summary>
            <p class="agent-popup">
              Use Claude Code, Codex, or any other agent to edit notes in your vault. As long as Obsidian is open, the agent's edits sync in realtime for everyone.
            </p>
          </details>
          <div class="demo-frame">
            <video class="demo-video" controls preload="metadata" playsinline src="${DEMO_VIDEO_URL}">
              <a href="${DEMO_VIDEO_URL}">Watch the product walkthrough video</a>.
            </video>
          </div>
        </section>

        <div class="grid">
          <article class="tile">
            <h2 class="tile-title">Collaborate Live</h2>
            <p>See edits and cursors instantly so your team can write, review, and plan together without merge friction.</p>
          </article>
          <article class="tile">
            <h2 class="tile-title">Keep Notes Private</h2>
            <p>End-to-end encryption means your notes are only visible to you and the people you share them with.</p>
          </article>
          <article class="tile">
            <h2 class="tile-title">Agent-friendly</h2>
            <p>As long as Obsidian is open, updates you or an agent make will sync in realtime - so invite Claude Code right in.</p>
          </article>
          <article class="tile">
            <h2 class="tile-title">Images &amp; Attachments</h2>
            <p>Images and other attachments are pulled into the folder, encrypted, and synced too — everyone sees the same note.</p>
          </article>
          <article class="tile">
            <h2 class="tile-title">Deeplink to files</h2>
            <p>Share a link to a specific file in a shared folder. Anyone shared on the folder can open it into their Obsidian app.</p>
          </article>
          <article class="tile">
            <h2 class="tile-title">MIT-licensed</h2>
            <p>The whole stack is fully MIT-licensed. Use the server & plugin however you want. Contributions welcome!</p>
          </article>
        </div>

        <p class="meta">
          Warning: This project is beta software under active development and may include bugs, breaking changes, data leakage, or data-loss risks. Use at your own risk, verify before relying on synchronized content, and keep independent backups of important vaults. This is a community plugin maintained by Experimental LLC and is not affiliated with Obsidian.
        </p>
        <div class="legal-links" aria-label="Legal links">
          <a href="/pricing">Pricing</a>
          <a href="/privacy">Privacy Policy</a>
          <a href="/terms">Terms of Service</a>
        </div>
        <p class="copyright">
          Copyright © ${COPYRIGHT_YEAR} Experimental LLC. Developed by
          <a class="accent-link" href="https://andybromberg.com" target="_blank" rel="noopener noreferrer">Andy Bromberg</a>.
        </p>
      </section>
    </main>
    <script>
      (() => {
        const agentNote = document.querySelector('.agent-note')
        if (agentNote instanceof HTMLDetailsElement) {
          document.addEventListener('pointerdown', (event) => {
            if (!agentNote.open) return
            const target = event.target
            if (target instanceof Node && agentNote.contains(target)) return
            agentNote.removeAttribute('open')
          })
        }

        const installButton = document.getElementById('install-plugin')
        const installModal = document.getElementById('install-modal')
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

        document.addEventListener('keydown', (event) => {
          if (event.key === 'Escape' && agentNote instanceof HTMLDetailsElement) {
            agentNote.removeAttribute('open')
          }
        })
      })()
    </script>
  </body>
</html>`)
})

app.get('/pricing', (_req, res) => {
  res
    .status(200)
    .type('html')
    .send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Pricing - Obsidian Collaborative Folders</title>
    <link rel="icon" href="${FAVICON_DATA_URL}">
    <style>
      :root {
        --bg: #f1eee2;
        --surface: #fbf8ef;
        --text-strong: #352e22;
        --text-soft: #615847;
        --line: #d5ccb5;
        --accent-0: #cc8600;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        min-height: 100vh;
        padding: 26px;
        background: var(--bg);
        color: var(--text-strong);
        font-family: "Avenir Next", "Nunito Sans", "Segoe UI", sans-serif;
      }
      .wrap {
        width: min(940px, 100%);
        margin: 0 auto;
      }
      .card {
        border: 1px solid var(--line);
        border-radius: 22px;
        background: var(--surface);
        box-shadow:
          0 24px 70px rgba(39, 30, 11, 0.08),
          0 2px 8px rgba(39, 30, 11, 0.06);
        padding: 30px;
      }
      .top {
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: center;
        gap: 10px 16px;
      }
      .nav {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }
      .nav a,
      .back-link {
        display: inline-flex;
        align-items: center;
        border: 1px solid #ddd3ba;
        border-radius: 999px;
        padding: 7px 12px;
        background: #f4edd9;
        color: #5f533f;
        text-decoration: none;
        font-size: 14px;
        font-weight: 700;
        letter-spacing: 0.01em;
        transition: transform 120ms ease, filter 120ms ease, box-shadow 120ms ease;
      }
      .nav a:hover,
      .back-link:hover {
        transform: translateY(-1px);
        filter: brightness(1.02);
        box-shadow: 0 6px 14px rgba(51, 41, 19, 0.09);
      }
      h1 {
        margin: 18px 0 0;
        font-size: clamp(34px, 5vw, 54px);
        line-height: 0.96;
        letter-spacing: -0.02em;
      }
      .summary {
        margin: 12px 0 0;
        color: var(--text-soft);
        font-size: clamp(17px, 2.1vw, 22px);
        line-height: 1.45;
        max-width: 54ch;
      }
      .plans {
        margin-top: 24px;
        display: grid;
        gap: 12px;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      }
      .plan {
        border: 1px solid #e0d7c0;
        border-radius: 14px;
        padding: 16px;
        background: #fff;
      }
      .plan h2 {
        margin: 0;
        font-size: 14px;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: #6d634f;
      }
      .badge {
        display: inline-flex;
        align-items: center;
        border: 1px solid #d8c298;
        border-radius: 999px;
        padding: 5px 10px;
        background: #f3e9d3;
        color: #6f5830;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.07em;
        text-transform: uppercase;
      }
      .plan-hosted {
        border-color: #d8c298;
        background: #f8f2e4;
      }
      .price {
        margin: 8px 0 0;
        font-size: clamp(36px, 5vw, 50px);
        line-height: 0.9;
        letter-spacing: -0.02em;
      }
      .price span {
        display: block;
        margin-top: 6px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #706651;
      }
      .plan-note {
        margin: 10px 0 0;
        color: #5f5748;
        line-height: 1.45;
      }
      .features {
        margin: 10px 0 0;
        padding-left: 18px;
        color: #5a5040;
      }
      .features li {
        line-height: 1.42;
      }
      .features li + li {
        margin-top: 5px;
      }
      .actions {
        margin-top: 14px;
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }
      .button {
        appearance: none;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 1px solid transparent;
        border-radius: 12px;
        padding: 10px 14px;
        text-decoration: none;
        font-size: 14px;
        font-weight: 700;
        line-height: 1;
        font-family: inherit;
        cursor: pointer;
        transition: transform 120ms ease, filter 120ms ease, box-shadow 120ms ease;
      }
      .button:hover {
        transform: translateY(-1px);
        filter: brightness(1.02);
      }
      .button:focus-visible {
        outline: 2px solid rgba(117, 81, 22, 0.38);
        outline-offset: 2px;
      }
      .button.primary {
        background: var(--accent-0);
        color: #fff;
        box-shadow: 0 10px 20px rgba(149, 94, 0, 0.22);
      }
      .button.secondary {
        background: #f5efdf;
        border-color: #ddd2ba;
        color: #5f5441;
      }
      .meta {
        margin-top: 16px;
        border: 1px solid #ddd2ba;
        border-radius: 12px;
        padding: 14px 15px;
        background: #f5efdf;
        color: #5f5441;
        font-size: 14px;
        line-height: 1.56;
      }
      .meta a {
        color: #6b5530;
        font-weight: 700;
        text-decoration-color: #b6883a;
        text-decoration-thickness: 2px;
        text-underline-offset: 2px;
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
        body {
          padding: 18px;
        }
        .card {
          border-radius: 16px;
          padding: 22px 20px;
        }
      }
      @media (max-width: 640px) {
        body {
          padding: 10px;
        }
        .card {
          border-radius: 14px;
          padding: 18px 14px;
        }
        .top {
          display: grid;
          gap: 8px;
        }
        .back-link {
          width: 100%;
          justify-content: center;
        }
        .nav {
          width: 100%;
        }
        .nav a {
          flex: 1 1 0;
          justify-content: center;
        }
        h1 {
          margin-top: 12px;
          font-size: clamp(30px, 11vw, 42px);
        }
        .summary {
          margin-top: 10px;
          font-size: 16px;
        }
        .plans {
          margin-top: 18px;
          grid-template-columns: 1fr;
        }
        .price {
          font-size: clamp(32px, 12vw, 44px);
        }
      }
      @media (max-width: 520px) {
        .actions .button {
          width: 100%;
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
    <main class="wrap">
      <section class="card">
        <div class="top">
          <a class="back-link" href="/">&larr; Back to home</a>
          <nav class="nav" aria-label="Page links">
            <a href="/privacy">Privacy</a>
            <a href="/terms">Terms</a>
          </nav>
        </div>

        <h1>Pricing</h1>
        <p class="summary">
          Self-host Collaborative Folders for free, or use our managed hosting at ${HOSTED_DEFAULT_SEAT_PRICE} per month.
        </p>

        <section class="plans" aria-label="Pricing plans">
          <article class="plan">
            <h2>Self-host</h2>
            <p class="price">$0<span>No subscription fee</span></p>
            <p class="plan-note">Run the MIT-licensed stack on your own infrastructure.</p>
            <ul class="features">
              <li>No subscription required, you control everything.</li>
              <li>Same collaboration protocol and experience.</li>
              <li>Easy deployment process.</li>
            </ul>
            <div class="actions">
              <a class="button secondary" href="${GITHUB_SOURCE_URL}" target="_blank" rel="noopener noreferrer">View source</a>
            </div>
          </article>

          <article class="plan plan-hosted">
            <h2>Managed for you</h2>
            <p class="price">${HOSTED_DEFAULT_SEAT_PRICE}<span>Per user each month</span></p>
            <p class="plan-note">End-to-end encrypted (we can't read your notes).</p>
            <ul class="features">
              <li>You don't have to lift a finger.</li>
              <li>${HOSTED_DEFAULT_STORAGE_CAP} storage cap across owned shared folders.</li>
              <li>${HOSTED_DEFAULT_MAX_FILE_SIZE} maximum upload size per file.</li>
            </ul>
            <div class="actions">
              <button class="button primary" type="button" id="pricing-install-plugin">Install plugin</button>
            </div>
          </article>
        </section>
        <dialog class="install-modal" id="pricing-install-modal" aria-labelledby="pricing-install-modal-title">
          <form method="dialog" class="install-modal-inner">
            <h2 class="install-modal-title" id="pricing-install-modal-title">Install With BRAT</h2>
            <p class="install-modal-lead">
              The valiant Obsidian plugin reviewing team is facing an onslaught of submissions. It may be weeks or months until they get to this one and add it to the real directory. Until then, you can install it with a helper plugin called BRAT.
            </p>
            <ol class="install-steps">
              <li>
                Install BRAT
                by going to <a class="accent-link" href="${BRAT_PLUGIN_URL}" target="_blank" rel="noopener noreferrer">this link</a> or opening <code>Settings -> Community plugins</code> and searching for it.
                (Enable Community plugins first if needed.)
              </li>
              <li>Toggle BRAT on in your Community plugins list.</li>
              <li>Open BRAT settings and click <code>Add beta plugin</code>.</li>
              <li>Paste <code>${BRAT_INSTALL_REPO_URL}</code> and click <code>Add</code>.</li>
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

        <p class="meta">
          Terms may change. See
          <a href="/privacy">Privacy Policy</a>
          and
          <a href="/terms">Terms of Service</a>.
        </p>
      </section>
    </main>
    <script>
      (() => {
        const installButton = document.getElementById('pricing-install-plugin')
        const installModal = document.getElementById('pricing-install-modal')
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
      })()
    </script>
  </body>
</html>`)
})
app.get('/privacy', (_req, res) => {
  res
    .status(200)
    .type('html')
    .send(
      renderLegalPage({
        title: 'Privacy Policy',
        summary: 'How Obsidian Collaborative Folders handles information for the website, hosted collaboration service, and plugin workflows.',
        bodyHtml: `
          <section>
            <h2>1. Scope</h2>
            <p>
              This policy applies to the Obsidian Collaborative Folders website and hosted service operated by Experimental LLC in the United States. If you self-host the server, you are responsible for your own privacy practices, notices, and legal compliance for that deployment.
            </p>
          </section>
          <section>
            <h2>2. Contact and Controller</h2>
            <p>
              Experimental LLC is the data controller for the hosted service described in this policy. For privacy requests, email
              <a href="${LEGAL_CONTACT_EMAIL_HREF}">${LEGAL_CONTACT_EMAIL}</a>
              or
              <a href="${LEGAL_CONTACT_URL}" target="_blank" rel="noopener noreferrer">open an issue on GitHub</a>.
            </p>
          </section>
          <section>
            <h2>3. Information We Process</h2>
            <p>Depending on how you use the product, we may process:</p>
            <ul>
              <li>Identifiers and account data, such as email address, display name, account ID, and client ID.</li>
              <li>Collaboration metadata, such as folder IDs, shared folder display names, membership state, invite tokens, and synchronization state metadata.</li>
              <li>Document routing metadata, including room identifiers that may contain relative file paths within a shared folder.</li>
              <li>Billing and subscription records, such as Stripe customer/subscription IDs, plan, status, and billing period dates.</li>
              <li>Operational and security logs, such as IP address, request timing, user agent, and error events.</li>
              <li>Support and communications content you send to us.</li>
            </ul>
          </section>
          <section>
            <h2>4. Encrypted Content</h2>
            <p>
              The collaboration system is designed for end-to-end encrypted note content. Note bodies and attachment payloads are encrypted client-side before relay or storage by the hosted service. We still process limited non-content metadata required for routing, authorization, abuse prevention, and service reliability.
            </p>
            <p>
              End-to-end encryption does not hide all metadata from the server. For example, the hosted service can see folder IDs, shared folder display names used in invite flows, and document room identifiers that can include relative file paths (for example, <code>notes/meeting.md</code>). The hosted service does not require or receive your full local vault filesystem path.
            </p>
          </section>
          <section>
            <h2>5. How We Use Information</h2>
            <p>
              We use information to provide and secure the service, authenticate users, manage subscriptions, enforce hosted account and storage entitlements, prevent fraud and abuse, troubleshoot incidents, meet legal obligations, and improve product reliability.
            </p>
          </section>
          <section>
            <h2>6. Sharing of Information</h2>
            <p>
              We do not sell personal information. We may disclose information to service providers that process data on our behalf (for example hosting, storage, logging, and billing processors such as Stripe), when required by law, or in connection with a merger, financing, acquisition, dissolution, or sale of assets.
            </p>
          </section>
          <section>
            <h2>7. Data Retention</h2>
            <p>
              We retain data only as long as needed for service operation, subscription management, security, dispute handling, and legal obligations. Retention periods vary by data type. Security logs may be retained for a limited period for abuse prevention. Self-hosted operators control retention for their own deployments.
            </p>
          </section>
          <section>
            <h2>8. Your Choices</h2>
            <p>
              You may request access, correction, deletion, or export of account-level hosted data by contacting us at the link above. We may need to verify your identity before completing a request. For self-hosted deployments, data access and deletion are controlled by the deployment owner.
            </p>
          </section>
          <section>
            <h2>9. California Privacy Disclosures</h2>
            <p>
              California residents may have rights under applicable California privacy laws, including rights to know, delete, and correct certain personal information, and to limit certain uses of sensitive personal information where required by law. We do not sell personal information and do not share personal information for cross-context behavioral advertising as those terms are defined under California law.
            </p>
            <p>
              To submit a California privacy request, email
              <a href="${LEGAL_CONTACT_EMAIL_HREF}">${LEGAL_CONTACT_EMAIL}</a>
              or use the issue link above. We will confirm receipt and respond within timeframes required by law.
            </p>
          </section>
          <section>
            <h2>10. Cookies and Do Not Track</h2>
            <p>
              We may use cookies or similar technologies that are necessary for authentication, security, fraud prevention, load balancing, or basic service operation. We do not permit third-party behavioral advertising on the service. The service is not currently designed to respond to browser "Do Not Track" signals because no common industry standard is fully implemented.
            </p>
          </section>
          <section>
            <h2>11. Children&apos;s Privacy</h2>
            <p>
              The hosted service is not directed to children under 13, and we do not knowingly collect personal information from children under 13. If you believe a child under 13 provided personal information, contact us so we can investigate and delete it as appropriate.
            </p>
          </section>
          <section>
            <h2>12. Data Security</h2>
            <p>
              We use administrative, technical, and organizational safeguards designed to protect data, including access controls, logging, encryption in transit, and end-to-end encrypted note content. No method of transmission or storage is completely secure, and we cannot guarantee absolute security.
            </p>
          </section>
          <section>
            <h2>13. U.S.-Only Service</h2>
            <p>
              The hosted service is intended for users in the United States. We do not market the hosted service to EU or UK users and do not offer region-specific terms for non-U.S. jurisdictions at this time.
            </p>
          </section>
          <section>
            <h2>14. Policy Changes</h2>
            <p>
              We may update this policy over time. Material changes will be reflected by updating the date at the top of this page.
            </p>
          </section>
        `,
      })
    )
})

app.get('/terms', (_req, res) => {
  res
    .status(200)
    .type('html')
    .send(
      renderLegalPage({
        title: 'Terms of Service',
        summary: 'Rules and responsibilities for using Obsidian Collaborative Folders and related hosted services.',
        bodyHtml: `
          <section>
            <h2>1. Acceptance of Terms</h2>
            <p>
              By accessing or using this service, you agree to these Terms. If you do not agree, do not use the service.
            </p>
          </section>
          <section>
            <h2>2. Eligibility and U.S.-Only Service</h2>
            <p>
              You must be legally able to enter a binding contract to use the hosted service. The hosted service is intended for users in the United States.
            </p>
          </section>
          <section>
            <h2>3. Service Description</h2>
            <p>
              Obsidian Collaborative Folders provides real-time shared folder collaboration for Obsidian, including invite flows, synchronization, and related hosted infrastructure.
            </p>
          </section>
          <section>
            <h2>4. Beta Software Notice</h2>
            <p>
              The service is in beta and may contain defects or breaking changes. You are responsible for maintaining backups of important data.
            </p>
          </section>
          <section>
            <h2>5. Accounts and Security Responsibilities</h2>
            <p>
              You are responsible for safeguarding your credentials and for activity performed through your account or device. Notify us promptly if you suspect unauthorized access.
            </p>
          </section>
          <section>
            <h2>6. Billing, Subscriptions, and Renewal</h2>
            <p>
              Paid hosted plans are billed in advance on a recurring basis through Stripe. By subscribing, you authorize recurring charges for your selected plan until cancellation.
            </p>
            <p>
              As of ${LEGAL_LAST_UPDATED}, default hosted pricing is ${HOSTED_DEFAULT_SEAT_PRICE} per subscribed user per month, with no free tier. Hosted plans include hard entitlement limits (default ${HOSTED_DEFAULT_STORAGE_CAP} owner storage and ${HOSTED_DEFAULT_MAX_FILE_SIZE} max upload size) that may change prospectively with notice.
            </p>
          </section>
          <section>
            <h2>7. Cancellation and Refunds</h2>
            <p>
              You may cancel your subscription at any time. After cancellation, your subscription remains active through the end of the current paid billing period and then does not renew.
            </p>
            <p>
              If hosted subscription status becomes inactive after that period, hosted collaboration access may be suspended or revoked, including automated collaborator offboarding and pending invite revocation, while local vault copies remain on user devices.
            </p>
            <p>
              Payments are non-refundable except where required by law.
            </p>
          </section>
          <section>
            <h2>8. Acceptable Use</h2>
            <p>You agree not to misuse the service, including:</p>
            <ul>
              <li>Attempting unauthorized access to systems, folders, or other users.</li>
              <li>Disrupting service reliability, security, or availability.</li>
              <li>Using the service for unlawful activity.</li>
            </ul>
          </section>
          <section>
            <h2>9. User Content</h2>
            <p>
              You retain ownership of your content. You grant us a limited license to host, process, transmit, and store content and metadata only as needed to provide, secure, and maintain the service.
            </p>
          </section>
          <section>
            <h2>10. Privacy</h2>
            <p>
              Your use of the service is also governed by the <a href="/privacy">Privacy Policy</a>.
            </p>
          </section>
          <section>
            <h2>11. Intellectual Property</h2>
            <p>
              You retain ownership of your content. The codebase is open source under the project license, while trademarks and branding remain owned by their respective holders.
            </p>
          </section>
          <section>
            <h2>12. Service Availability and Changes</h2>
            <p>
              We may change, suspend, or discontinue all or part of the hosted service, including features, limits, and integrations, to operate the service safely and effectively.
            </p>
          </section>
          <section>
            <h2>13. Warranty Disclaimer</h2>
            <p>
              The service is provided on an "as is" and "as available" basis, without warranties of any kind to the fullest extent permitted by law.
            </p>
          </section>
          <section>
            <h2>14. Limitation of Liability</h2>
            <p>
              To the fullest extent permitted by law, Experimental LLC is not liable for indirect, incidental, special, consequential, or punitive damages, or for loss of data, profits, or goodwill.
            </p>
            <p>
              To the fullest extent permitted by law, our aggregate liability for claims arising from the hosted service will not exceed the greater of (a) amounts you paid us for the hosted service in the 12 months before the event giving rise to the claim, or (b) USD $100.
            </p>
          </section>
          <section>
            <h2>15. Indemnification</h2>
            <p>
              You agree to indemnify and hold harmless Experimental LLC from claims, losses, and expenses (including reasonable attorneys&apos; fees) arising from your misuse of the service, your violation of these Terms, or your violation of applicable law.
            </p>
          </section>
          <section>
            <h2>16. Governing Law and Venue</h2>
            <p>
              These Terms are governed by the laws of the State of Texas, without regard to conflict-of-law principles. Any dispute arising from these Terms or the hosted service must be resolved in state or federal courts located in Texas, and you consent to that venue and jurisdiction.
            </p>
          </section>
          <section>
            <h2>17. Termination</h2>
            <p>
              You may stop using the service at any time. We may suspend or terminate access for violations of these Terms, legal requirements, or security risk.
            </p>
          </section>
          <section>
            <h2>18. Changes to Terms</h2>
            <p>
              We may modify these Terms from time to time. Material changes will be reflected by updating the date at the top of this page. Continued use after changes means you accept the updated Terms.
            </p>
          </section>
          <section>
            <h2>19. Contact</h2>
            <p>
              For legal or billing questions, email
              <a href="${LEGAL_CONTACT_EMAIL_HREF}">${LEGAL_CONTACT_EMAIL}</a>
              or
              <a href="${LEGAL_CONTACT_URL}" target="_blank" rel="noopener noreferrer">open an issue on GitHub</a>.
            </p>
          </section>
        `,
      })
    )
})

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.2.0', protocolGateEnabled: PROTOCOL_GATE_ENABLED })
})

app.get('/health/security', (req, res) => {
  if (!requireAdminToken(req, res)) return
  res.json({
    status: 'ok',
    metrics: getSecurityMetrics(),
  })
})

app.get('/health/hosted', (req, res) => {
  if (!requireAdminToken(req, res)) return
  if (!HOSTED_MODE) {
    res.status(404).json({
      status: 'disabled',
      hostedMode: false,
      message: 'Hosted mode is disabled',
    })
    return
  }

  const db = getDb()
  const accountSummary = db
    .prepare(
      `
      SELECT
        COUNT(*) AS total_accounts,
        SUM(CASE WHEN subscription_status IN ('active', 'trialing') THEN 1 ELSE 0 END) AS subscribed_accounts
      FROM hosted_account_billing
    `
    )
    .get() as { total_accounts: number; subscribed_accounts: number | null } | undefined

  const webhookSummary = db
    .prepare(
      `
      SELECT
        COUNT(*) AS received_events,
        SUM(CASE WHEN processed_at IS NULL THEN 1 ELSE 0 END) AS pending_events,
        SUM(CASE WHEN processing_error IS NOT NULL THEN 1 ELSE 0 END) AS errored_events
      FROM hosted_billing_events
    `
    )
    .get() as
    | {
        received_events: number
        pending_events: number | null
        errored_events: number | null
      }
    | undefined

  res.json({
    status: 'ok',
    hostedMode: HOSTED_MODE,
    billingConfigured: isHostedBillingConfigured(),
    accounts: {
      total: Number(accountSummary?.total_accounts || 0),
      subscribed: Number(accountSummary?.subscribed_accounts || 0),
    },
    webhooks: {
      received: Number(webhookSummary?.received_events || 0),
      pending: Number(webhookSummary?.pending_events || 0),
      errored: Number(webhookSummary?.errored_events || 0),
    },
  })
})

const httpServer = createServer(app)
const wsServer = new WebSocketServer({ noServer: true })
const encryptedRelay = new EncryptedRelay()
encryptedRelay.attach(wsServer)

httpServer.on('upgrade', (request, socket, head) => {
  try {
    const url = new URL(request.url || '/', 'http://localhost')
    if (url.pathname !== '/ws') {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }

    const protocol = resolveUpgradeProtocolVersion(
      request as Request | { url?: string; headers: Record<string, string | string[] | undefined> }
    )
    if (protocol !== PROTOCOL_V2) {
      socket.write('HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }

    wsServer.handleUpgrade(request, socket, head, (ws) => {
      wsServer.emit('connection', ws, request)
    })
  } catch (error: unknown) {
    if (error instanceof Error && error.message) {
      console.error('[ws:upgrade]', redactValue(error.message))
    }
    socket.destroy()
  }
})

httpServer.listen(PORT, '0.0.0.0', () => {
  console.debug(`[server] HTTP + encrypted relay WebSocket server running on port ${PORT}`)
})
