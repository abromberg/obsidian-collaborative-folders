import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'
import crypto from 'crypto'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-hosted-webhook-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.HOSTED_MODE = 'true'
process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_secret'
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { hostedBillingWebhookHandler } = await import('../routes/hosted-billing.js')

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

function signStripePayload(payload: string, secret: string): string {
  const timestamp = Math.floor(Date.now() / 1000)
  const signed = `${timestamp}.${payload}`
  const signature = crypto.createHmac('sha256', secret).update(signed).digest('hex')
  return `t=${timestamp},v1=${signature}`
}

function createMockRequest(payload: string, signature: string) {
  const headers: Record<string, string> = {
    'stripe-signature': signature,
  }
  return {
    body: Buffer.from(payload, 'utf8'),
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

test('webhook verifies signature, updates account billing state, and is idempotent on replay', () => {
  resetDb()

  db.prepare(
    `
    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES (?, ?, ?, 'active')
  `
  ).run('acct-owner', 'owner@example.com', 'Owner')

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
  ).run('acct-owner')

  const event = {
    id: 'evt_checkout_completed_1',
    type: 'checkout.session.completed',
    data: {
      object: {
        id: 'cs_test_1',
        object: 'checkout.session',
        customer: 'cus_test_1',
        subscription: 'sub_test_1',
        payment_status: 'paid',
        metadata: {
          account_id: 'acct-owner',
        },
      },
    },
  }

  const payload = JSON.stringify(event)
  const signature = signStripePayload(payload, process.env.STRIPE_WEBHOOK_SECRET!)

  const req = createMockRequest(payload, signature)
  const res = createMockResponse()
  hostedBillingWebhookHandler(req as any, res as any)

  assert.equal(res.statusCode, 200)
  assert.deepEqual(res.body, { received: true })

  const billing = db
    .prepare(
      `
      SELECT stripe_customer_id, stripe_subscription_id, subscription_status
      FROM hosted_account_billing
      WHERE account_id = ?
      LIMIT 1
    `
    )
    .get('acct-owner') as {
    stripe_customer_id: string | null
    stripe_subscription_id: string | null
    subscription_status: string
  }

  assert.equal(billing.stripe_customer_id, 'cus_test_1')
  assert.equal(billing.stripe_subscription_id, 'sub_test_1')
  assert.equal(billing.subscription_status, 'active')

  const replayRes = createMockResponse()
  hostedBillingWebhookHandler(req as any, replayRes as any)
  assert.equal(replayRes.statusCode, 200)
  assert.deepEqual(replayRes.body, { received: true, duplicate: true })

  const events = db
    .prepare('SELECT stripe_event_id, processed_at FROM hosted_billing_events WHERE stripe_event_id = ?')
    .all(event.id) as Array<{ stripe_event_id: string; processed_at: string | null }>
  assert.equal(events.length, 1)
  assert.ok(events[0].processed_at)
})

test('owner subscription cancellation revokes editor access and active invites on owned folders', () => {
  resetDb()

  db.prepare(
    `
    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES (?, ?, ?, 'active')
  `
  ).run('acct-owner', 'owner@example.com', 'Owner')

  db.prepare(
    `
    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES (?, ?, ?, 'active')
  `
  ).run('acct-collab', 'collab@example.com', 'Collaborator')

  db.prepare(
    `
    INSERT INTO hosted_account_billing (
      account_id,
      stripe_customer_id,
      stripe_subscription_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES (?, ?, ?, 'active', 900, 3221225472, 26214400, datetime('now'))
  `
  ).run('acct-owner', 'cus_owner', 'sub_owner')

  db.prepare(
    `
    INSERT INTO hosted_account_billing (
      account_id,
      stripe_customer_id,
      stripe_subscription_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES (?, ?, ?, 'active', 900, 3221225472, 26214400, datetime('now'))
  `
  ).run('acct-collab', 'cus_collab', 'sub_collab')

  db.prepare('INSERT INTO folders (id, name, owner_client_id, owner_account_id) VALUES (?, ?, ?, ?)').run(
    'folder-1',
    'Shared Folder',
    'owner-client',
    'acct-owner'
  )

  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, 'owner', 0)
  `
  ).run('folder-1', 'owner-client', 'acct-owner', 'Owner')

  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, 'editor', 0)
  `
  ).run('folder-1', 'collab-client', 'acct-collab', 'Collaborator')

  db.prepare(
    `
    INSERT INTO invites (token_hash, folder_id, role, expires_at, max_uses, use_count)
    VALUES (?, ?, 'editor', ?, 1, 0)
  `
  ).run(
    crypto.createHash('sha256').update('invite-token-owner').digest('hex'),
    'folder-1',
    new Date(Date.now() + 3600_000).toISOString()
  )

  const event = {
    id: 'evt_subscription_deleted_owner',
    type: 'customer.subscription.deleted',
    data: {
      object: {
        id: 'sub_owner',
        object: 'subscription',
        status: 'canceled',
        customer: 'cus_owner',
        metadata: {
          account_id: 'acct-owner',
        },
      },
    },
  }

  const payload = JSON.stringify(event)
  const signature = signStripePayload(payload, process.env.STRIPE_WEBHOOK_SECRET!)

  const req = createMockRequest(payload, signature)
  const res = createMockResponse()
  hostedBillingWebhookHandler(req as any, res as any)

  assert.equal(res.statusCode, 200)
  assert.deepEqual(res.body, { received: true })

  const remainingMembers = db
    .prepare('SELECT client_id, role FROM members WHERE folder_id = ? ORDER BY role DESC, client_id ASC')
    .all('folder-1') as Array<{ client_id: string; role: 'owner' | 'editor' }>
  assert.deepEqual(remainingMembers, [{ client_id: 'owner-client', role: 'owner' }])

  const invite = db
    .prepare('SELECT revoked_at, revoked_by FROM invites WHERE folder_id = ? LIMIT 1')
    .get('folder-1') as { revoked_at: string | null; revoked_by: string | null } | undefined
  assert.ok(invite?.revoked_at)
  assert.equal(invite?.revoked_by, 'system:billing')
})

test('editor subscription cancellation revokes that account from collaborator roles', () => {
  resetDb()

  db.prepare(
    `
    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES (?, ?, ?, 'active')
  `
  ).run('acct-owner', 'owner@example.com', 'Owner')

  db.prepare(
    `
    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES (?, ?, ?, 'active')
  `
  ).run('acct-editor', 'editor@example.com', 'Editor')

  db.prepare(
    `
    INSERT INTO hosted_account_billing (
      account_id,
      stripe_customer_id,
      stripe_subscription_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES (?, ?, ?, 'active', 900, 3221225472, 26214400, datetime('now'))
  `
  ).run('acct-owner', 'cus_owner', 'sub_owner')

  db.prepare(
    `
    INSERT INTO hosted_account_billing (
      account_id,
      stripe_customer_id,
      stripe_subscription_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES (?, ?, ?, 'active', 900, 3221225472, 26214400, datetime('now'))
  `
  ).run('acct-editor', 'cus_editor', 'sub_editor')

  db.prepare('INSERT INTO folders (id, name, owner_client_id, owner_account_id) VALUES (?, ?, ?, ?)').run(
    'folder-2',
    'Shared Folder 2',
    'owner-client',
    'acct-owner'
  )

  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, 'owner', 0)
  `
  ).run('folder-2', 'owner-client', 'acct-owner', 'Owner')

  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, 'editor', 0)
  `
  ).run('folder-2', 'editor-client', 'acct-editor', 'Editor')

  const event = {
    id: 'evt_subscription_deleted_editor',
    type: 'customer.subscription.deleted',
    data: {
      object: {
        id: 'sub_editor',
        object: 'subscription',
        status: 'canceled',
        customer: 'cus_editor',
        metadata: {
          account_id: 'acct-editor',
        },
      },
    },
  }

  const payload = JSON.stringify(event)
  const signature = signStripePayload(payload, process.env.STRIPE_WEBHOOK_SECRET!)

  const req = createMockRequest(payload, signature)
  const res = createMockResponse()
  hostedBillingWebhookHandler(req as any, res as any)

  assert.equal(res.statusCode, 200)
  assert.deepEqual(res.body, { received: true })

  const remainingMembers = db
    .prepare('SELECT client_id, role FROM members WHERE folder_id = ? ORDER BY role DESC, client_id ASC')
    .all('folder-2') as Array<{ client_id: string; role: 'owner' | 'editor' }>
  assert.deepEqual(remainingMembers, [{ client_id: 'owner-client', role: 'owner' }])
})

test('webhook rejects invalid signatures', () => {
  resetDb()

  const event = {
    id: 'evt_bad_signature',
    type: 'invoice.paid',
    data: { object: { id: 'in_1' } },
  }
  const payload = JSON.stringify(event)
  const badSignature = signStripePayload(payload, 'wrong_secret')

  const req = createMockRequest(payload, badSignature)
  const res = createMockResponse()
  hostedBillingWebhookHandler(req as any, res as any)

  assert.equal(res.statusCode, 400)
  assert.deepEqual(res.body, { error: 'Invalid Stripe webhook signature' })
})
