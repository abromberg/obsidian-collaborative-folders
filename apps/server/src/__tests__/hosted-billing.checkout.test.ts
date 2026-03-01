import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'
import { HOSTED_SESSION_HEADER } from '@obsidian-teams/shared'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-hosted-checkout-guard-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.HOSTED_MODE = 'true'
process.env.STRIPE_SECRET_KEY = 'sk_test_checkout_guard'
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { issueHostedSession } = await import('../security/hosted-sessions.js')
const { handleCheckoutSession } = await import('../routes/hosted-billing.js')

initDb()
const db = getDb()

function resetDb(): void {
  db.exec(`
    DELETE FROM audit_events;
    DELETE FROM revoked_tokens;
    DELETE FROM refresh_tokens;
    DELETE FROM invites;
    DELETE FROM members;
    DELETE FROM folders;
    DELETE FROM hosted_billing_events;
    DELETE FROM hosted_account_usage;
    DELETE FROM hosted_account_billing;
    DELETE FROM hosted_account_sessions;
    DELETE FROM hosted_accounts;
  `)
}

function seedHostedAccount(accountId: string, email: string): string {
  db.prepare(
    `
    INSERT INTO hosted_accounts (id, email_norm, display_name, status, created_at, updated_at)
    VALUES (?, ?, ?, 'active', datetime('now'), datetime('now'))
  `
  ).run(accountId, email, 'Owner')

  return issueHostedSession(db, accountId).sessionToken
}

function createMockRequest(hostedSessionToken: string, body: Record<string, unknown> = {}) {
  const headers: Record<string, string> = {
    [HOSTED_SESSION_HEADER.toLowerCase()]: hostedSessionToken,
  }
  return {
    body,
    headers,
    header(name: string) {
      return headers[name.toLowerCase()] || null
    },
  }
}

function createMockResponse() {
  return {
    statusCode: 200,
    body: null as unknown,
    status(code: number) {
      this.statusCode = code
      return this
    },
    json(payload: unknown) {
      this.body = payload
      return this
    },
  }
}

test('checkout session returns 409 when local status is active', async () => {
  resetDb()
  const originalFetch = globalThis.fetch
  let fetchCalls = 0

  globalThis.fetch = (async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({}), { status: 200 })
  }) as typeof fetch

  try {
    const accountId = 'acct-active'
    const sessionToken = seedHostedAccount(accountId, 'active@example.com')
    db.prepare(
      `
      INSERT INTO hosted_account_billing (
        account_id,
        subscription_status,
        price_cents,
        storage_cap_bytes,
        max_file_size_bytes,
        updated_at
      ) VALUES (?, 'active', 900, 3221225472, 26214400, datetime('now'))
    `
    ).run(accountId)

    const req = createMockRequest(sessionToken)
    const res = createMockResponse()
    await handleCheckoutSession(req as any, res as any)

    assert.equal(res.statusCode, 409)
    assert.deepEqual(res.body, {
      code: 'subscription_already_active',
      error: 'Subscription already exists. Open billing portal to manage it.',
    })
    assert.equal(fetchCalls, 0)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('checkout session returns 409 when Stripe precheck finds non-terminal subscription', async () => {
  resetDb()
  const originalFetch = globalThis.fetch
  const calls: Array<{ url: string; init?: RequestInit }> = []

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    if (String(url).includes('/v1/subscriptions?')) {
      return new Response(
        JSON.stringify({
          data: [{ id: 'sub_1', status: 'past_due' }],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    }
    return new Response(
      JSON.stringify({
        id: 'cs_should_not_exist',
        url: 'https://checkout.stripe.test/should-not-be-used',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  try {
    const accountId = 'acct-stale'
    const sessionToken = seedHostedAccount(accountId, 'stale@example.com')
    db.prepare(
      `
      INSERT INTO hosted_account_billing (
        account_id,
        stripe_customer_id,
        subscription_status,
        price_cents,
        storage_cap_bytes,
        max_file_size_bytes,
        updated_at
      ) VALUES (?, ?, 'inactive', 900, 3221225472, 26214400, datetime('now'))
    `
    ).run(accountId, 'cus_stale_1')

    const req = createMockRequest(sessionToken)
    const res = createMockResponse()
    await handleCheckoutSession(req as any, res as any)

    assert.equal(res.statusCode, 409)
    assert.deepEqual(res.body, {
      code: 'subscription_requires_portal',
      error: 'Subscription requires billing portal action before creating a new checkout.',
    })
    assert.equal(calls.length, 1)
    assert.match(calls[0].url, /\/v1\/subscriptions\?customer=cus_stale_1/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('checkout session uses per-attempt idempotency key', async () => {
  resetDb()
  const originalFetch = globalThis.fetch
  const checkoutIdempotencyKeys: string[] = []

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const headers = init?.headers as Record<string, string> | undefined
    if (String(url).includes('/v1/checkout/sessions') && headers?.['Idempotency-Key']) {
      checkoutIdempotencyKeys.push(headers['Idempotency-Key'])
    }
    return new Response(
      JSON.stringify({
        id: `cs_${checkoutIdempotencyKeys.length || 1}`,
        url: `https://checkout.stripe.test/session-${checkoutIdempotencyKeys.length || 1}`,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  try {
    const accountId = 'acct-fresh'
    const sessionToken = seedHostedAccount(accountId, 'fresh@example.com')
    db.prepare(
      `
      INSERT INTO hosted_account_billing (
        account_id,
        subscription_status,
        price_cents,
        storage_cap_bytes,
        max_file_size_bytes,
        updated_at
      ) VALUES (?, 'inactive', 900, 3221225472, 26214400, datetime('now'))
    `
    ).run(accountId)

    const firstReq = createMockRequest(sessionToken)
    const firstRes = createMockResponse()
    await handleCheckoutSession(firstReq as any, firstRes as any)

    const secondReq = createMockRequest(sessionToken)
    const secondRes = createMockResponse()
    await handleCheckoutSession(secondReq as any, secondRes as any)

    assert.equal(firstRes.statusCode, 201)
    assert.equal(secondRes.statusCode, 201)
    assert.equal(checkoutIdempotencyKeys.length, 2)
    assert.notEqual(checkoutIdempotencyKeys[0], checkoutIdempotencyKeys[1])
    assert.match(checkoutIdempotencyKeys[0], /^checkout:acct-fresh:/)
    assert.match(checkoutIdempotencyKeys[1], /^checkout:acct-fresh:/)
  } finally {
    globalThis.fetch = originalFetch
  }
})
