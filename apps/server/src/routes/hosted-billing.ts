/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import crypto from 'crypto'
import { Router, type Request, type Response } from 'express'
import type { HostedCheckoutSessionResponse, HostedPortalSessionResponse } from '@obsidian-teams/shared'
import { getDb } from '../db/schema.js'
import {
  hostedBaseUrl,
  hostedMaxFileSizeBytes,
  hostedSeatPriceCents,
  hostedStorageCapBytes,
  hostedStripeSecretKey,
  hostedStripeWebhookSecret,
} from '../config/hosted.js'
import { revokeToken } from '../security/authz.js'
import { writeAuditEvent } from '../security/audit.js'
import { recomputeAccountUsage } from '../security/entitlements.js'
import { extractHostedSessionToken, resolveHostedSession } from '../security/hosted-sessions.js'
import { revokeRefreshTokensForMember } from '../security/refresh-tokens.js'
import { revokeMemberSessions } from '../security/session-registry.js'

export const hostedBillingRouter: ReturnType<typeof Router> = Router()

const STRIPE_API_BASE = 'https://api.stripe.com'
const WEBHOOK_TOLERANCE_SECONDS = Number(process.env.STRIPE_WEBHOOK_TOLERANCE_SECONDS || 300)
const COLLABORATION_ALLOWED_STATUSES = new Set(['active', 'trialing'])
const ACTIVE_SUBSCRIPTION_STATUSES = new Set(['active', 'trialing'])
const NON_TERMINAL_NON_ACTIVE_SUBSCRIPTION_STATUSES = new Set(['past_due', 'unpaid', 'incomplete', 'paused'])
const TERMINAL_SUBSCRIPTION_STATUSES = new Set(['canceled', 'incomplete_expired'])
const BILLING_SYSTEM_ACTOR = 'system:billing'

interface CheckoutBody {
  successUrl?: string
  cancelUrl?: string
}

interface PortalBody {
  returnUrl?: string
}

interface AccountBillingRow {
  account_id: string
  stripe_customer_id: string | null
  subscription_status: string
}

interface AccountProfileRow {
  email_norm: string
}

interface StripeSessionResponse {
  id: string
  url?: string
  customer?: string
  subscription?: string
  payment_status?: string
}

interface StripeSubscriptionObject {
  id: string
  customer?: string
  status?: string
  current_period_end?: number
  cancel_at_period_end?: boolean
  metadata?: Record<string, string>
  items?: {
    data?: Array<{
      id?: string
    }>
  }
}

interface StripeSubscriptionListResponse {
  data?: Array<{
    id?: string
    status?: string
  }>
}

interface StripeEvent {
  id: string
  type: string
  data: {
    object: Record<string, unknown>
  }
}

interface AccountBillingStatusRow {
  subscription_status: string | null
}

interface AccountEditorMemberRow {
  folder_id: string
  client_id: string
}

type BillingReturnStatus = 'success' | 'cancel' | 'return'

const BILLING_RETURN_STATUSES = new Set<BillingReturnStatus>(['success', 'cancel', 'return'])

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function normalizeHostedBaseUrl(value: string): string {
  return value.replace(/\/+$/, '')
}

function resolveBillingReturnStatus(input: unknown): BillingReturnStatus {
  const normalized = typeof input === 'string' ? input.trim().toLowerCase() : ''
  if (BILLING_RETURN_STATUSES.has(normalized as BillingReturnStatus)) {
    return normalized as BillingReturnStatus
  }
  return 'return'
}

function buildBillingReturnUrl(status: BillingReturnStatus): string {
  const baseUrl = normalizeHostedBaseUrl(hostedBaseUrl())
  return `${baseUrl}/api/hosted/billing/return?status=${encodeURIComponent(status)}`
}

function billingReturnContent(status: BillingReturnStatus): { eyebrow: string; heading: string; body: string } {
  if (status === 'success') {
    return {
      eyebrow: 'Checkout complete',
      heading: 'Opening Obsidian...',
      body: 'Your payment succeeded. We are taking you back to Obsidian to finish setup.',
    }
  }

  if (status === 'cancel') {
    return {
      eyebrow: 'Checkout canceled',
      heading: 'Returning to Obsidian...',
      body: 'No changes were made. Open Obsidian to continue whenever you are ready.',
    }
  }

  return {
    eyebrow: 'Billing updated',
    heading: 'Returning to Obsidian...',
    body: 'Your billing session is complete. Open Obsidian to keep collaborating.',
  }
}

function renderBillingReturnPage(status: BillingReturnStatus): string {
  const deepLink = `obsidian://teams-billing?status=${encodeURIComponent(status)}`
  const escapedDeepLink = escapeHtml(deepLink)
  const deepLinkLiteral = JSON.stringify(deepLink)
  const content = billingReturnContent(status)

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(content.eyebrow)}</title>
    <meta http-equiv="refresh" content="0;url=${escapedDeepLink}">
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
        width: min(720px, 100%);
      }
      .card {
        padding: 28px 30px;
        border-radius: 22px;
        border: 1px solid var(--line);
        background: var(--surface);
        box-shadow:
          0 24px 70px rgba(39, 30, 11, 0.08),
          0 2px 8px rgba(39, 30, 11, 0.06);
      }
      .eyebrow {
        margin: 0 0 12px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #786f5e;
      }
      h1 {
        margin: 0;
        font-size: clamp(34px, 5vw, 54px);
        line-height: 0.94;
        letter-spacing: -0.02em;
      }
      p {
        margin: 16px 0 0;
        font-size: 18px;
        line-height: 1.5;
        color: var(--text-soft);
      }
      .actions {
        margin-top: 22px;
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
      }
      a.button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 1px solid transparent;
        border-radius: 14px;
        padding: 13px 20px;
        font-size: 18px;
        line-height: 1;
        font-weight: 700;
        text-decoration: none;
        transition: transform 120ms ease, box-shadow 120ms ease, filter 120ms ease;
      }
      a.button:hover {
        transform: translateY(-1px);
        filter: brightness(1.02);
      }
      a.button.primary {
        background: var(--accent-0);
        color: #fff;
        box-shadow: 0 12px 28px rgba(158, 100, 0, 0.25);
      }
      a.button.secondary {
        background: var(--accent-soft);
        color: var(--text-strong);
        border-color: #ddd3ba;
      }
      @media (max-width: 640px) {
        .card {
          padding: 22px 20px;
          border-radius: 16px;
        }
        h1 {
          font-size: clamp(30px, 10vw, 44px);
        }
        p {
          font-size: 16px;
        }
        a.button {
          width: 100%;
          text-align: center;
        }
      }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <p class="eyebrow">${escapeHtml(content.eyebrow)}</p>
        <h1>${escapeHtml(content.heading)}</h1>
        <p>${escapeHtml(content.body)}</p>
        <div class="actions">
          <a class="button primary" href="${escapedDeepLink}" id="open-obsidian">Open Obsidian</a>
          <a class="button secondary" href="/">Back to home</a>
        </div>
      </div>
    </div>
    <script>
      const deepLink = ${deepLinkLiteral}
      window.setTimeout(() => {
        window.location.href = deepLink
      }, 40)
    </script>
  </body>
</html>`
}

function toIsoFromEpoch(seconds: number | undefined): string | null {
  if (!seconds || !Number.isFinite(seconds)) return null
  return new Date(Math.trunc(seconds) * 1000).toISOString()
}

function formBody(entries: Record<string, string | number | boolean | undefined | null>): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined || value === null) continue
    params.set(key, String(value))
  }
  return params.toString()
}

function resolveSessionActor(req: Request, res: Response) {
  const db = getDb()
  const sessionToken = extractHostedSessionToken(req)
  if (!sessionToken) {
    res.status(401).json({
      error: 'Hosted session token required',
      code: 'hosted_session_required',
    })
    return null
  }

  const actor = resolveHostedSession(db, sessionToken)
  if (!actor) {
    res.status(401).json({
      error: 'Hosted session is invalid or expired',
      code: 'hosted_session_required',
    })
    return null
  }

  return actor
}

function requireStripeSecret(res: Response): string | null {
  const secret = hostedStripeSecretKey()
  if (!secret) {
    res.status(503).json({ error: 'Hosted billing is not configured' })
    return null
  }
  return secret
}

function ensureAccountBillingRow(db: ReturnType<typeof getDb>, accountId: string): void {
  db.prepare(
    `
    INSERT INTO hosted_account_billing (
      account_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES (?, 'inactive', ?, ?, ?, datetime('now'))
    ON CONFLICT(account_id) DO NOTHING
  `
  ).run(accountId, hostedSeatPriceCents(), hostedStorageCapBytes(), hostedMaxFileSizeBytes())
}

function resolveBillingAccount(db: ReturnType<typeof getDb>, accountId: string): AccountBillingRow {
  ensureAccountBillingRow(db, accountId)
  const row = db
    .prepare(
      `
      SELECT
        account_id,
        stripe_customer_id,
        COALESCE(subscription_status, 'inactive') AS subscription_status
      FROM hosted_account_billing
      WHERE account_id = ?
      LIMIT 1
    `
    )
    .get(accountId) as AccountBillingRow | undefined

  if (!row) {
    throw new Error('Failed to resolve hosted account billing row')
  }

  return row
}

async function stripePost(
  path: string,
  body: string,
  options: {
    stripeSecret: string
    idempotencyKey?: string
  }
): Promise<{ status: number; payload: unknown }> {
  const response = await globalThis.fetch(`${STRIPE_API_BASE}${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${options.stripeSecret}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(options.idempotencyKey ? { 'Idempotency-Key': options.idempotencyKey } : {}),
    },
    body,
  })

  const payload = await response.json().catch(() => ({}))
  return { status: response.status, payload }
}

async function stripeGet(
  path: string,
  options: {
    stripeSecret: string
  }
): Promise<{ status: number; payload: unknown }> {
  const response = await globalThis.fetch(`${STRIPE_API_BASE}${path}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${options.stripeSecret}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  })

  const payload = await response.json().catch(() => ({}))
  return { status: response.status, payload }
}

function readStripeErrorMessage(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null
  const error = (payload as { error?: unknown }).error
  if (!error || typeof error !== 'object') return null
  const message = (error as { message?: unknown }).message
  return typeof message === 'string' && message.trim() ? message : null
}

function readStripeSession(payload: unknown): StripeSessionResponse | null {
  if (!payload || typeof payload !== 'object') return null
  return payload as StripeSessionResponse
}

function parseStripeSignature(signatureHeader: string): { timestamp: number; signatures: string[] } | null {
  const parts = signatureHeader
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)

  let timestamp = 0
  const signatures: string[] = []

  for (const part of parts) {
    const [key, value] = part.split('=', 2)
    if (!key || !value) continue
    if (key === 't') {
      timestamp = Number(value)
      continue
    }
    if (key === 'v1') signatures.push(value)
  }

  if (!Number.isFinite(timestamp) || timestamp <= 0 || signatures.length === 0) {
    return null
  }

  return { timestamp, signatures }
}

function safeEqualHex(a: string, b: string): boolean {
  try {
    const left = Buffer.from(a, 'hex')
    const right = Buffer.from(b, 'hex')
    if (left.length !== right.length) return false
    return crypto.timingSafeEqual(left, right)
  } catch {
    return false
  }
}

function verifyStripeWebhookSignature(rawBody: Buffer, signatureHeader: string, secret: string): boolean {
  const parsed = parseStripeSignature(signatureHeader)
  if (!parsed) return false

  const ageSeconds = Math.abs(Math.floor(Date.now() / 1000) - parsed.timestamp)
  if (ageSeconds > WEBHOOK_TOLERANCE_SECONDS) return false

  const signedPayload = `${parsed.timestamp}.${rawBody.toString('utf8')}`
  const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex')

  return parsed.signatures.some((candidate) => safeEqualHex(candidate, expected))
}

function findAccountIdFromStripeData(db: ReturnType<typeof getDb>, object: Record<string, unknown>): string | null {
  const metadata =
    object.metadata && typeof object.metadata === 'object'
      ? (object.metadata as Record<string, unknown>)
      : null

  const metadataAccount = typeof metadata?.account_id === 'string' ? metadata.account_id : null
  if (metadataAccount) return metadataAccount

  const clientReferenceId = typeof object.client_reference_id === 'string' ? object.client_reference_id : null
  if (clientReferenceId) return clientReferenceId

  const objectKind = typeof object.object === 'string' ? object.object : ''
  const subscriptionId =
    typeof object.subscription === 'string'
      ? object.subscription
      : typeof object.id === 'string' && objectKind.includes('subscription')
        ? object.id
        : null

  if (subscriptionId) {
    const row = db
      .prepare('SELECT account_id FROM hosted_account_billing WHERE stripe_subscription_id = ? LIMIT 1')
      .get(subscriptionId) as { account_id: string } | undefined
    if (row?.account_id) return row.account_id
  }

  const customerId = typeof object.customer === 'string' ? object.customer : null
  if (customerId) {
    const row = db
      .prepare('SELECT account_id FROM hosted_account_billing WHERE stripe_customer_id = ? LIMIT 1')
      .get(customerId) as { account_id: string } | undefined
    if (row?.account_id) return row.account_id
  }

  return null
}

function applyCheckoutSessionCompleted(
  db: ReturnType<typeof getDb>,
  accountId: string,
  session: StripeSessionResponse
): void {
  ensureAccountBillingRow(db, accountId)
  db.prepare(
    `
    UPDATE hosted_account_billing
    SET stripe_customer_id = COALESCE(?, stripe_customer_id),
        stripe_subscription_id = COALESCE(?, stripe_subscription_id),
        subscription_status = CASE
          WHEN ? = 'paid' THEN 'active'
          ELSE subscription_status
        END,
        updated_at = datetime('now')
    WHERE account_id = ?
  `
  ).run(
    typeof session.customer === 'string' ? session.customer : null,
    typeof session.subscription === 'string' ? session.subscription : null,
    session.payment_status || null,
    accountId
  )
}

function applySubscriptionUpdate(
  db: ReturnType<typeof getDb>,
  accountId: string,
  subscription: StripeSubscriptionObject
): void {
  ensureAccountBillingRow(db, accountId)

  const firstItem = subscription.items?.data?.[0]
  db.prepare(
    `
    UPDATE hosted_account_billing
    SET stripe_customer_id = COALESCE(?, stripe_customer_id),
        stripe_subscription_id = COALESCE(?, stripe_subscription_id),
        stripe_subscription_item_id = COALESCE(?, stripe_subscription_item_id),
        subscription_status = COALESCE(?, subscription_status),
        current_period_end = COALESCE(?, current_period_end),
        cancel_at_period_end = ?,
        updated_at = datetime('now')
    WHERE account_id = ?
  `
  ).run(
    typeof subscription.customer === 'string' ? subscription.customer : null,
    subscription.id || null,
    firstItem?.id || null,
    subscription.status || null,
    toIsoFromEpoch(subscription.current_period_end),
    subscription.cancel_at_period_end ? 1 : 0,
    accountId
  )
}

function applyInvoiceStatus(
  db: ReturnType<typeof getDb>,
  subscriptionId: string,
  status: 'active' | 'past_due'
): string | null {
  const row = db
    .prepare('SELECT account_id FROM hosted_account_billing WHERE stripe_subscription_id = ? LIMIT 1')
    .get(subscriptionId) as { account_id: string } | undefined
  if (!row?.account_id) return null

  db.prepare(
    `
    UPDATE hosted_account_billing
    SET subscription_status = ?,
        updated_at = datetime('now')
    WHERE account_id = ?
  `
  ).run(status, row.account_id)

  return row.account_id
}

function normalizeSubscriptionStatus(value: string | null | undefined): string {
  const normalized = (value || '').trim().toLowerCase()
  return normalized || 'inactive'
}

function loadAccountSubscriptionStatus(db: ReturnType<typeof getDb>, accountId: string): string {
  const row = db
    .prepare(
      `
      SELECT subscription_status
      FROM hosted_account_billing
      WHERE account_id = ?
      LIMIT 1
    `
    )
    .get(accountId) as AccountBillingStatusRow | undefined
  return normalizeSubscriptionStatus(row?.subscription_status)
}

function resolveCheckoutBlock(status: string): {
  code: 'subscription_already_active' | 'subscription_requires_portal'
  error: string
} | null {
  const normalized = normalizeSubscriptionStatus(status)
  if (ACTIVE_SUBSCRIPTION_STATUSES.has(normalized)) {
    return {
      code: 'subscription_already_active',
      error: 'Subscription already exists. Open billing portal to manage it.',
    }
  }
  if (NON_TERMINAL_NON_ACTIVE_SUBSCRIPTION_STATUSES.has(normalized)) {
    return {
      code: 'subscription_requires_portal',
      error: 'Subscription requires billing portal action before creating a new checkout.',
    }
  }
  return null
}

function readStripeSubscriptionStatuses(payload: unknown): string[] {
  if (!payload || typeof payload !== 'object') return []
  const subscriptions = (payload as StripeSubscriptionListResponse).data
  if (!Array.isArray(subscriptions)) return []
  return subscriptions
    .map((item) => normalizeSubscriptionStatus(item.status))
    .filter((status) => !TERMINAL_SUBSCRIPTION_STATUSES.has(status))
}

async function findBlockingStripeStatus(
  stripeSecret: string,
  customerId: string
): Promise<string | null> {
  const path = `/v1/subscriptions?customer=${encodeURIComponent(customerId)}&status=all&limit=20`
  const stripe = await stripeGet(path, { stripeSecret })
  if (stripe.status < 200 || stripe.status >= 300) {
    const message = readStripeErrorMessage(stripe.payload) || `Stripe subscription check failed (${stripe.status})`
    throw new Error(message)
  }

  const nonTerminalStatuses = readStripeSubscriptionStatuses(stripe.payload)
  return nonTerminalStatuses[0] || null
}

function revokeEditorAccessForAccount(
  db: ReturnType<typeof getDb>,
  accountId: string,
  subscriptionStatus: string
): void {
  const members = db
    .prepare(
      `
      SELECT m.folder_id, m.client_id
      FROM members m
      WHERE m.account_id = ?
        AND m.role = 'editor'
    `
    )
    .all(accountId) as AccountEditorMemberRow[]

  let revokedRefreshTokens = 0
  let revokedAccessTokens = 0
  let closedWsSessions = 0

  for (const member of members) {
    revokedRefreshTokens += revokeRefreshTokensForMember(
      db,
      member.folder_id,
      member.client_id,
      'subscription_inactive'
    )
    const sessionRevocation = revokeMemberSessions(
      member.folder_id,
      member.client_id,
      'subscription-inactive'
    )
    closedWsSessions += sessionRevocation.closedCount
    revokedAccessTokens += sessionRevocation.revokedJtis.length

    for (const jti of sessionRevocation.revokedJtis) {
      revokeToken(db, {
        jti,
        folderId: member.folder_id,
        clientId: member.client_id,
        reason: 'subscription_inactive',
      })
    }
  }

  const removedMembers = db.prepare(
    `
    DELETE FROM members
    WHERE account_id = ?
      AND role = 'editor'
  `
  ).run(accountId)

  if (
    removedMembers.changes > 0 ||
    revokedRefreshTokens > 0 ||
    revokedAccessTokens > 0 ||
    closedWsSessions > 0
  ) {
    writeAuditEvent(db, {
      eventType: 'account_editor_collaboration_revoked',
      target: accountId,
      metadata: {
        subscriptionStatus,
        removedMembers: removedMembers.changes,
        revokedRefreshTokens,
        revokedAccessTokens,
        closedWsSessions,
      },
    })
  }
}

function revokeOwnedFolderCollaborators(
  db: ReturnType<typeof getDb>,
  accountId: string,
  subscriptionStatus: string
): void {
  const members = db
    .prepare(
      `
      SELECT m.folder_id, m.client_id
      FROM members m
      JOIN folders f ON f.id = m.folder_id
      WHERE f.owner_account_id = ?
        AND m.role = 'editor'
    `
    )
    .all(accountId) as AccountEditorMemberRow[]

  let revokedRefreshTokens = 0
  let revokedAccessTokens = 0
  let closedWsSessions = 0

  for (const member of members) {
    revokedRefreshTokens += revokeRefreshTokensForMember(
      db,
      member.folder_id,
      member.client_id,
      'subscription_inactive'
    )
    const sessionRevocation = revokeMemberSessions(
      member.folder_id,
      member.client_id,
      'subscription-inactive'
    )
    closedWsSessions += sessionRevocation.closedCount
    revokedAccessTokens += sessionRevocation.revokedJtis.length

    for (const jti of sessionRevocation.revokedJtis) {
      revokeToken(db, {
        jti,
        folderId: member.folder_id,
        clientId: member.client_id,
        reason: 'subscription_inactive',
      })
    }
  }

  const removedMembers = db.prepare(
    `
    DELETE FROM members
    WHERE role = 'editor'
      AND folder_id IN (
        SELECT id
        FROM folders
        WHERE owner_account_id = ?
      )
  `
  ).run(accountId)

  const revokedInvites = db.prepare(
    `
    UPDATE invites
    SET revoked_at = COALESCE(revoked_at, datetime('now')),
        revoked_by = COALESCE(revoked_by, ?)
    WHERE folder_id IN (
      SELECT id
      FROM folders
      WHERE owner_account_id = ?
    )
      AND revoked_at IS NULL
      AND (consumed_at IS NULL OR use_count < max_uses)
      AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
  `
  ).run(BILLING_SYSTEM_ACTOR, accountId)

  recomputeAccountUsage(db, accountId)

  if (
    removedMembers.changes > 0 ||
    revokedInvites.changes > 0 ||
    revokedRefreshTokens > 0 ||
    revokedAccessTokens > 0 ||
    closedWsSessions > 0
  ) {
    writeAuditEvent(db, {
      eventType: 'account_owner_collaboration_revoked',
      target: accountId,
      metadata: {
        subscriptionStatus,
        removedMembers: removedMembers.changes,
        revokedInvites: revokedInvites.changes,
        revokedRefreshTokens,
        revokedAccessTokens,
        closedWsSessions,
      },
    })
  }
}

function applyAccountBillingSideEffects(
  db: ReturnType<typeof getDb>,
  accountId: string
): void {
  const status = loadAccountSubscriptionStatus(db, accountId)
  if (COLLABORATION_ALLOWED_STATUSES.has(status)) return
  revokeEditorAccessForAccount(db, accountId, status)
  revokeOwnedFolderCollaborators(db, accountId, status)
}

function processStripeEvent(db: ReturnType<typeof getDb>, event: StripeEvent): { accountId: string | null } {
  const object = event.data.object || {}
  const accountId = findAccountIdFromStripeData(db, object)

  if (event.type === 'checkout.session.completed' && accountId) {
    applyCheckoutSessionCompleted(db, accountId, object as unknown as StripeSessionResponse)
    applyAccountBillingSideEffects(db, accountId)
    return { accountId }
  }

  if (
    (event.type === 'customer.subscription.created' ||
      event.type === 'customer.subscription.updated' ||
      event.type === 'customer.subscription.deleted') &&
    accountId
  ) {
    applySubscriptionUpdate(db, accountId, object as unknown as StripeSubscriptionObject)
    applyAccountBillingSideEffects(db, accountId)
    return { accountId }
  }

  if (event.type === 'invoice.payment_failed') {
    const invoiceSubscription = typeof object.subscription === 'string' ? object.subscription : null
    if (invoiceSubscription) {
      const updatedAccountId = applyInvoiceStatus(db, invoiceSubscription, 'past_due')
      if (updatedAccountId) {
        applyAccountBillingSideEffects(db, updatedAccountId)
      }
      return { accountId: updatedAccountId }
    }
  }

  if (event.type === 'invoice.paid') {
    const invoiceSubscription = typeof object.subscription === 'string' ? object.subscription : null
    if (invoiceSubscription) {
      const updatedAccountId = applyInvoiceStatus(db, invoiceSubscription, 'active')
      if (updatedAccountId) {
        applyAccountBillingSideEffects(db, updatedAccountId)
      }
      return { accountId: updatedAccountId }
    }
  }

  return { accountId }
}

/** GET /api/hosted/billing/return — browser bridge that deep-links users back into Obsidian. */
hostedBillingRouter.get('/return', (req: Request, res: Response) => {
  const status = resolveBillingReturnStatus(req.query.status)
  res
    .status(200)
    .type('html')
    .setHeader('Cache-Control', 'no-store')
    .setHeader('Referrer-Policy', 'no-referrer')
    .send(renderBillingReturnPage(status))
})

/** POST /api/hosted/billing/checkout-session — create Stripe checkout session for account. */
export async function handleCheckoutSession(
  req: Request<Record<string, never>, unknown, CheckoutBody>,
  res: Response<HostedCheckoutSessionResponse | { error: string; code?: string }>
): Promise<void> {
  const actor = resolveSessionActor(req, res)
  if (!actor) return

  const stripeSecret = requireStripeSecret(res)
  if (!stripeSecret) return

  const db = getDb()
  const access = resolveBillingAccount(db, actor.accountId)
  const localBlock = resolveCheckoutBlock(access.subscription_status)
  if (localBlock) {
    res.status(409).json(localBlock)
    return
  }

  if (access.stripe_customer_id) {
    try {
      const stripeBlockingStatus = await findBlockingStripeStatus(stripeSecret, access.stripe_customer_id)
      if (stripeBlockingStatus) {
        const stripeBlock = resolveCheckoutBlock(stripeBlockingStatus) || {
          code: 'subscription_requires_portal' as const,
          error: 'Subscription requires billing portal action before creating a new checkout.',
        }
        res.status(409).json(stripeBlock)
        return
      }
    } catch (error: unknown) {
      const message = error instanceof Error && error.message
        ? error.message
        : 'Failed to verify Stripe subscription state'
      res.status(502).json({ error: message })
      return
    }
  }

  const accountProfile = db
    .prepare(
      `
      SELECT email_norm
      FROM hosted_accounts
      WHERE id = ?
      LIMIT 1
    `
    )
    .get(actor.accountId) as AccountProfileRow | undefined
  const checkoutCustomerEmail = access.stripe_customer_id ? undefined : accountProfile?.email_norm || undefined

  const successUrl = req.body.successUrl?.trim() || buildBillingReturnUrl('success')
  const cancelUrl = req.body.cancelUrl?.trim() || buildBillingReturnUrl('cancel')

  const body = formBody({
    mode: 'subscription',
    success_url: successUrl,
    cancel_url: cancelUrl,
    client_reference_id: actor.accountId,
    'metadata[account_id]': actor.accountId,
    'line_items[0][quantity]': 1,
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][unit_amount]': hostedSeatPriceCents(),
    'line_items[0][price_data][product_data][name]': 'Collaborative Folders Subscription',
    'line_items[0][price_data][recurring][interval]': 'month',
    customer: access.stripe_customer_id,
    customer_email: checkoutCustomerEmail,
  })

  const idempotencyKey = `checkout:${actor.accountId}:${Date.now()}:${crypto.randomUUID()}`

  const stripe = await stripePost('/v1/checkout/sessions', body, {
    stripeSecret,
    idempotencyKey,
  })

  if (stripe.status < 200 || stripe.status >= 300) {
    const message = readStripeErrorMessage(stripe.payload) || `Stripe checkout request failed (${stripe.status})`
    res.status(502).json({ error: message })
    return
  }

  const payload = readStripeSession(stripe.payload)
  if (!payload?.id || !payload.url) {
    res.status(502).json({ error: 'Stripe checkout response missing id/url' })
    return
  }

  res.status(201).json({
    checkoutSessionId: payload.id,
    checkoutUrl: payload.url,
  })
}

hostedBillingRouter.post(
  '/checkout-session',
  (
    req: Request<Record<string, never>, unknown, CheckoutBody>,
    res: Response<HostedCheckoutSessionResponse | { error: string; code?: string }>
  ) => {
    void handleCheckoutSession(req, res).catch((error: unknown) => {
      const message = error instanceof Error && error.message
        ? error.message
        : 'Failed to create hosted checkout session'
      res.status(500).json({ error: message })
    })
  }
)

/** POST /api/hosted/billing/portal-session — create Stripe billing portal session for account. */
async function handlePortalSession(
  req: Request<Record<string, never>, unknown, PortalBody>,
  res: Response<HostedPortalSessionResponse | { error: string }>
): Promise<void> {
  const actor = resolveSessionActor(req, res)
  if (!actor) return

  const stripeSecret = requireStripeSecret(res)
  if (!stripeSecret) return

  const db = getDb()
  const access = resolveBillingAccount(db, actor.accountId)

  if (!access.stripe_customer_id) {
    res.status(409).json({ error: 'Account has no Stripe customer yet. Complete checkout first.' })
    return
  }

  const returnUrl = req.body.returnUrl?.trim() || buildBillingReturnUrl('return')
  const body = formBody({
    customer: access.stripe_customer_id,
    return_url: returnUrl,
  })

  const idempotencyKey = crypto
    .createHash('sha256')
    .update(`portal:${actor.accountId}:${Date.now()}`)
    .digest('hex')

  const stripe = await stripePost('/v1/billing_portal/sessions', body, {
    stripeSecret,
    idempotencyKey,
  })

  if (stripe.status < 200 || stripe.status >= 300) {
    const message = readStripeErrorMessage(stripe.payload) || `Stripe portal request failed (${stripe.status})`
    res.status(502).json({ error: message })
    return
  }

  const portalPayload = stripe.payload as { url?: unknown }
  const portalUrl = typeof portalPayload.url === 'string' ? portalPayload.url : null
  if (!portalUrl) {
    res.status(502).json({ error: 'Stripe portal response missing url' })
    return
  }

  res.status(201).json({ portalUrl })
}

hostedBillingRouter.post(
  '/portal-session',
  (
    req: Request<Record<string, never>, unknown, PortalBody>,
    res: Response<HostedPortalSessionResponse | { error: string }>
  ) => {
    void handlePortalSession(req, res).catch((error: unknown) => {
      const message = error instanceof Error && error.message
        ? error.message
        : 'Failed to create hosted billing portal session'
      res.status(500).json({ error: message })
    })
  }
)

/** POST /api/hosted/billing/webhook — Stripe webhook endpoint (raw body + signature verification). */
export function hostedBillingWebhookHandler(req: Request, res: Response): void {
  const webhookSecret = hostedStripeWebhookSecret()
  if (!webhookSecret) {
    res.status(503).json({ error: 'Stripe webhook secret is not configured' })
    return
  }

  const signatureHeader = req.header('stripe-signature')?.trim()
  if (!signatureHeader) {
    res.status(400).json({ error: 'Missing Stripe-Signature header' })
    return
  }

  if (!Buffer.isBuffer(req.body)) {
    res.status(400).json({ error: 'Webhook requires raw request body' })
    return
  }

  if (!verifyStripeWebhookSignature(req.body, signatureHeader, webhookSecret)) {
    res.status(400).json({ error: 'Invalid Stripe webhook signature' })
    return
  }

  let event: StripeEvent
  try {
    event = JSON.parse(req.body.toString('utf8')) as StripeEvent
  } catch {
    res.status(400).json({ error: 'Invalid JSON payload' })
    return
  }

  if (!event.id || !event.type || !event.data?.object) {
    res.status(400).json({ error: 'Invalid Stripe event envelope' })
    return
  }

  const db = getDb()
  const rawPayload = req.body.toString('utf8')
  const existing = db
    .prepare(
      `
      SELECT stripe_event_id, processed_at
      FROM hosted_billing_events
      WHERE stripe_event_id = ?
      LIMIT 1
    `
    )
    .get(event.id) as { stripe_event_id: string; processed_at: string | null } | undefined

  if (!existing) {
    db.prepare(
      `
      INSERT INTO hosted_billing_events (
        stripe_event_id,
        account_id,
        event_type,
        payload_json,
        received_at
      ) VALUES (?, NULL, ?, ?, datetime('now'))
    `
    ).run(event.id, event.type, rawPayload)
  } else if (existing.processed_at) {
    res.status(200).json({ received: true, duplicate: true })
    return
  }

  try {
    db.exec('BEGIN IMMEDIATE')
    const result = processStripeEvent(db, event)

    db.prepare(
      `
      UPDATE hosted_billing_events
      SET account_id = COALESCE(?, account_id),
          processed_at = datetime('now'),
          processing_error = NULL
      WHERE stripe_event_id = ?
    `
    ).run(result.accountId, event.id)

    db.exec('COMMIT')
  } catch (error) {
    db.exec('ROLLBACK')
    const message = error instanceof Error ? error.message : 'Webhook processing failed'
    db.prepare(
      `
      UPDATE hosted_billing_events
      SET processing_error = ?,
          processed_at = NULL
      WHERE stripe_event_id = ?
    `
    ).run(message, event.id)
    res.status(500).json({ error: message })
    return
  }

  res.status(200).json({ received: true })
}
