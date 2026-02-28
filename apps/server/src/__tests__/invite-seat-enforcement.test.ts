import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'
import crypto from 'crypto'
import type { Router } from 'express'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-invite-entitlement-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.HOSTED_MODE = 'true'
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { inviteRouter } = await import('../routes/invite.js')
const { issueHostedSession } = await import('../security/hosted-sessions.js')

initDb()
const db = getDb()

function resetDb(): void {
  db.exec(`
    DELETE FROM hosted_account_sessions;
    DELETE FROM hosted_account_usage;
    DELETE FROM hosted_account_billing;
    DELETE FROM hosted_billing_events;
    DELETE FROM hosted_accounts;
    DELETE FROM members;
    DELETE FROM invites;
    DELETE FROM folders;
  `)
}

function createMockResponse() {
  return {
    statusCode: 200,
    body: null as unknown,
    headers: {} as Record<string, string>,
    status(code: number) {
      this.statusCode = code
      return this
    },
    json(payload: unknown) {
      this.body = payload
      return this
    },
    setHeader(name: string, value: string) {
      this.headers[name] = value
    },
  }
}

function routeHandlers(router: Router, pathTemplate: string, method: 'post') {
  const layer = (router as any).stack.find(
    (candidate: any) => candidate.route?.path === pathTemplate && candidate.route?.methods?.[method]
  )
  if (!layer) {
    throw new Error(`Unable to locate route ${method.toUpperCase()} ${pathTemplate}`)
  }
  return layer.route.stack.map((routeLayer: any) => routeLayer.handle) as Array<
    (req: any, res: any, next: (error?: unknown) => void) => unknown
  >
}

async function invokeChain(
  handlers: Array<(req: any, res: any, next: (error?: unknown) => void) => unknown>,
  req: any,
  res: any
): Promise<void> {
  for (const handler of handlers) {
    const nextCalled = await new Promise<boolean>((resolve, reject) => {
      let settled = false
      const next = (error?: unknown) => {
        if (settled) return
        settled = true
        if (error) {
          reject(error)
          return
        }
        resolve(true)
      }

      try {
        Promise.resolve(handler(req, res, next))
          .then(() => {
            if (settled) return
            settled = true
            resolve(false)
          })
          .catch(reject)
      } catch (error) {
        reject(error)
      }
    })

    if (!nextCalled) return
  }
}

function seedInviteScenario(input: {
  folderId: string
  ownerAccountId: string
  ownerStatus: string
  inviteeAccountId: string
  inviteeStatus: string
  tokenValue: string
}): string {
  db.prepare(
    `
    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES (?, ?, ?, 'active')
  `
  ).run(input.ownerAccountId, `${input.ownerAccountId}@example.com`, 'Owner')

  db.prepare(
    `
    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES (?, ?, ?, 'active')
  `
  ).run(input.inviteeAccountId, `${input.inviteeAccountId}@example.com`, 'Collaborator')

  db.prepare(
    `
    INSERT INTO hosted_account_billing (
      account_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES (?, ?, 900, 3221225472, 26214400, datetime('now'))
  `
  ).run(input.ownerAccountId, input.ownerStatus)

  db.prepare(
    `
    INSERT INTO hosted_account_billing (
      account_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES (?, ?, 900, 3221225472, 26214400, datetime('now'))
  `
  ).run(input.inviteeAccountId, input.inviteeStatus)

  db.prepare(
    'INSERT INTO folders (id, name, owner_client_id, owner_account_id) VALUES (?, ?, ?, ?)'
  ).run(input.folderId, 'Shared Folder', 'owner-client', input.ownerAccountId)

  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, 'owner', 0)
  `
  ).run(input.folderId, 'owner-client', input.ownerAccountId, 'Owner')

  const tokenHash = crypto.createHash('sha256').update(input.tokenValue).digest('hex')
  db.prepare(
    `
    INSERT INTO invites (token_hash, folder_id, role, max_uses, use_count, expires_at)
    VALUES (?, ?, 'editor', 1, 0, ?)
  `
  ).run(tokenHash, input.folderId, new Date(Date.now() + 3600_000).toISOString())

  return tokenHash
}

const inviteRedeemHandlers = routeHandlers(inviteRouter as unknown as Router, '/redeem', 'post')

test('hosted invite redemption fails when invitee subscription is not active', async () => {
  resetDb()

  seedInviteScenario({
    folderId: 'folder-1',
    ownerAccountId: 'acct-owner-1',
    ownerStatus: 'active',
    inviteeAccountId: 'acct-invitee-1',
    inviteeStatus: 'canceled',
    tokenValue: 'invite-token-1',
  })

  const session = issueHostedSession(db, 'acct-invitee-1')
  const headers: Record<string, string> = {}

  const req = {
    ip: '127.0.0.1',
    headers,
    header(name: string) {
      const key = name.toLowerCase()
      return (headers[key] || null) as string | null
    },
    body: {
      inviteToken: 'invite-token-1',
      clientId: 'invitee-client-1',
      displayName: 'Invitee One',
      hostedSessionToken: session.sessionToken,
    },
  }

  const res = createMockResponse()
  await invokeChain(inviteRedeemHandlers, req, res)

  assert.equal(res.statusCode, 402)
  assert.deepEqual(res.body, {
    error: 'Subscription is not active for invite redemption',
    code: 'subscription_inactive',
  })
})

test('hosted invite redemption fails when owner subscription is not active', async () => {
  resetDb()

  seedInviteScenario({
    folderId: 'folder-2',
    ownerAccountId: 'acct-owner-2',
    ownerStatus: 'canceled',
    inviteeAccountId: 'acct-invitee-2',
    inviteeStatus: 'active',
    tokenValue: 'invite-token-2',
  })

  const session = issueHostedSession(db, 'acct-invitee-2')
  const headers: Record<string, string> = {}

  const req = {
    ip: '127.0.0.1',
    headers,
    header(name: string) {
      const key = name.toLowerCase()
      return (headers[key] || null) as string | null
    },
    body: {
      inviteToken: 'invite-token-2',
      clientId: 'invitee-client-2',
      displayName: 'Invitee Two',
      hostedSessionToken: session.sessionToken,
    },
  }

  const res = createMockResponse()
  await invokeChain(inviteRedeemHandlers, req, res)

  assert.equal(res.statusCode, 402)
  assert.deepEqual(res.body, {
    error: 'Subscription is not active for hosted collaboration',
    code: 'subscription_inactive',
  })
})

test('existing owner cannot redeem invite and does not consume it', async () => {
  resetDb()

  const tokenHash = seedInviteScenario({
    folderId: 'folder-3',
    ownerAccountId: 'acct-owner-3',
    ownerStatus: 'active',
    inviteeAccountId: 'acct-invitee-3',
    inviteeStatus: 'active',
    tokenValue: 'invite-token-3',
  })

  const session = issueHostedSession(db, 'acct-owner-3')
  const headers: Record<string, string> = {}

  const req = {
    ip: '127.0.0.1',
    headers,
    header(name: string) {
      const key = name.toLowerCase()
      return (headers[key] || null) as string | null
    },
    body: {
      inviteToken: 'invite-token-3',
      clientId: 'owner-client',
      displayName: 'Owner (Changed)',
      hostedSessionToken: session.sessionToken,
    },
  }

  const res = createMockResponse()
  await invokeChain(inviteRedeemHandlers, req, res)

  assert.equal(res.statusCode, 409)
  assert.deepEqual(res.body, {
    error: 'Folder owner cannot redeem invites for this folder',
    code: 'already_member',
  })

  const inviteUsage = db.prepare('SELECT use_count FROM invites WHERE token_hash = ?').get(tokenHash) as
    | { use_count: number }
    | undefined
  assert.equal(inviteUsage?.use_count, 0)

  const ownerMember = db
    .prepare('SELECT role, display_name FROM members WHERE folder_id = ? AND client_id = ?')
    .get('folder-3', 'owner-client') as { role: string; display_name: string } | undefined
  assert.equal(ownerMember?.role, 'owner')
  assert.equal(ownerMember?.display_name, 'Owner')
})

test('existing editor cannot redeem invite and does not consume it', async () => {
  resetDb()

  const tokenHash = seedInviteScenario({
    folderId: 'folder-4',
    ownerAccountId: 'acct-owner-4',
    ownerStatus: 'active',
    inviteeAccountId: 'acct-invitee-4',
    inviteeStatus: 'active',
    tokenValue: 'invite-token-4',
  })

  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, 'editor', 0)
  `
  ).run('folder-4', 'editor-client', 'acct-invitee-4', 'Existing Editor')

  const session = issueHostedSession(db, 'acct-invitee-4')
  const headers: Record<string, string> = {}

  const req = {
    ip: '127.0.0.1',
    headers,
    header(name: string) {
      const key = name.toLowerCase()
      return (headers[key] || null) as string | null
    },
    body: {
      inviteToken: 'invite-token-4',
      clientId: 'editor-client',
      displayName: 'Editor (Changed)',
      hostedSessionToken: session.sessionToken,
    },
  }

  const res = createMockResponse()
  await invokeChain(inviteRedeemHandlers, req, res)

  assert.equal(res.statusCode, 409)
  assert.deepEqual(res.body, {
    error: 'Client is already a member of this folder',
    code: 'already_member',
  })

  const inviteUsage = db.prepare('SELECT use_count FROM invites WHERE token_hash = ?').get(tokenHash) as
    | { use_count: number }
    | undefined
  assert.equal(inviteUsage?.use_count, 0)

  const editorMember = db
    .prepare('SELECT role, display_name FROM members WHERE folder_id = ? AND client_id = ?')
    .get('folder-4', 'editor-client') as { role: string; display_name: string } | undefined
  assert.equal(editorMember?.role, 'editor')
  assert.equal(editorMember?.display_name, 'Existing Editor')
})
