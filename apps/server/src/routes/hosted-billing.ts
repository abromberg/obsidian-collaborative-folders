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
): Promise<{ status: number; payload: any }> {
  const response = await fetch(`${STRIPE_API_BASE}${path}`, {
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

  const subscriptionId =
    typeof object.subscription === 'string'
      ? object.subscription
      : typeof object.id === 'string' && String(object.object || '').includes('subscription')
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

/** POST /api/hosted/billing/checkout-session — create Stripe checkout session for account. */
hostedBillingRouter.post(
  '/checkout-session',
  async (
    req: Request<any, any, CheckoutBody>,
    res: Response<HostedCheckoutSessionResponse | { error: string }>
  ) => {
    const actor = resolveSessionActor(req, res)
    if (!actor) return

    const stripeSecret = requireStripeSecret(res)
    if (!stripeSecret) return

    const db = getDb()
    const access = resolveBillingAccount(db, actor.accountId)

    const baseUrl = hostedBaseUrl()
    const successUrl = req.body.successUrl?.trim() || `${baseUrl}/?billing=success`
    const cancelUrl = req.body.cancelUrl?.trim() || `${baseUrl}/?billing=cancel`

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
    })

    const idempotencyKey = crypto
      .createHash('sha256')
      .update(`checkout:${actor.accountId}`)
      .digest('hex')

    const stripe = await stripePost('/v1/checkout/sessions', body, {
      stripeSecret,
      idempotencyKey,
    })

    if (stripe.status < 200 || stripe.status >= 300) {
      const message =
        typeof stripe.payload?.error?.message === 'string'
          ? stripe.payload.error.message
          : `Stripe checkout request failed (${stripe.status})`
      res.status(502).json({ error: message })
      return
    }

    const payload = stripe.payload as StripeSessionResponse
    if (!payload.id || !payload.url) {
      res.status(502).json({ error: 'Stripe checkout response missing id/url' })
      return
    }

    res.status(201).json({
      checkoutSessionId: payload.id,
      checkoutUrl: payload.url,
    })
  }
)

/** POST /api/hosted/billing/portal-session — create Stripe billing portal session for account. */
hostedBillingRouter.post(
  '/portal-session',
  async (req: Request<any, any, PortalBody>, res: Response<HostedPortalSessionResponse | { error: string }>) => {
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

    const returnUrl = req.body.returnUrl?.trim() || `${hostedBaseUrl()}/?billing=return`
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
      const message =
        typeof stripe.payload?.error?.message === 'string'
          ? stripe.payload.error.message
          : `Stripe portal request failed (${stripe.status})`
      res.status(502).json({ error: message })
      return
    }

    const portalUrl = typeof stripe.payload?.url === 'string' ? stripe.payload.url : null
    if (!portalUrl) {
      res.status(502).json({ error: 'Stripe portal response missing url' })
      return
    }

    res.status(201).json({ portalUrl })
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
