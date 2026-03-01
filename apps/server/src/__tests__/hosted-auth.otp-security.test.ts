import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-hosted-auth-otp-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.HOSTED_MODE = 'true'
process.env.SUPABASE_URL = 'https://supabase.example.com'
process.env.SUPABASE_ANON_KEY = 'supabase-anon-key'
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { hostedAuthRouter, handleHostedOtpStart, handleHostedOtpVerify } = await import('../routes/hosted-auth.js')

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

function createMockRequest(body: Record<string, unknown>) {
  const headers: Record<string, string> = {}
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

test('otp start rejects invalid email without calling Supabase', async () => {
  resetDb()
  const originalFetch = globalThis.fetch
  let fetchCalls = 0

  globalThis.fetch = (async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({}), { status: 200 })
  }) as typeof fetch

  try {
    const req = createMockRequest({ email: '' })
    const res = createMockResponse()
    await handleHostedOtpStart(req as any, res as any)

    assert.equal(res.statusCode, 400)
    assert.deepEqual(res.body, { error: 'Valid email is required' })
    assert.equal(fetchCalls, 0)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('legacy email-only session creation route is removed', () => {
  const hasLegacySessionRoute = hostedAuthRouter.stack.some((layer: any) => {
    return layer.route?.path === '/session' && layer.route?.methods?.post
  })
  assert.equal(hasLegacySessionRoute, false)
})

test('otp verify creates hosted account session for Supabase-verified email', async () => {
  resetDb()
  const originalFetch = globalThis.fetch
  const calls: Array<{ url: string; init?: RequestInit }> = []

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(
      JSON.stringify({
        user: {
          email: 'owner@example.com',
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  try {
    const req = createMockRequest({
      email: 'owner@example.com',
      code: '123456',
      displayName: 'Owner',
    })
    const res = createMockResponse()
    await handleHostedOtpVerify(req as any, res as any)

    assert.equal(res.statusCode, 200)
    const body = res.body as {
      account: { email: string; displayName: string }
      sessionToken: string
      expiresAt: string
    }
    assert.equal(body.account.email, 'owner@example.com')
    assert.equal(body.account.displayName, 'Owner')
    assert.ok(body.sessionToken)
    assert.ok(body.expiresAt)

    assert.equal(calls.length, 1)
    assert.equal(calls[0].url, 'https://supabase.example.com/auth/v1/verify')

    const account = db
      .prepare('SELECT id, email_norm, display_name FROM hosted_accounts WHERE email_norm = ? LIMIT 1')
      .get('owner@example.com') as
      | {
          id: string
          email_norm: string
          display_name: string | null
        }
      | undefined
    assert.ok(account?.id)
    assert.equal(account?.display_name, 'Owner')
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('otp verify rejects expired or invalid codes', async () => {
  resetDb()
  const originalFetch = globalThis.fetch

  globalThis.fetch = (async () => {
    return new Response(
      JSON.stringify({
        error_description: 'Token has expired or is invalid',
      }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  try {
    const req = createMockRequest({
      email: 'owner@example.com',
      code: '000000',
    })
    const res = createMockResponse()
    await handleHostedOtpVerify(req as any, res as any)

    assert.equal(res.statusCode, 401)
    assert.deepEqual(res.body, {
      error: 'Token has expired or is invalid',
      code: 'hosted_otp_invalid',
    })
  } finally {
    globalThis.fetch = originalFetch
  }
})
