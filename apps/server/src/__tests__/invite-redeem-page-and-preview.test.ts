import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'
import crypto from 'crypto'
import type { Router } from 'express'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-invite-page-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.HOSTED_MODE = 'false'
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { inviteRouter } = await import('../routes/invite.js')

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
    typeValue: '' as string,
    status(code: number) {
      this.statusCode = code
      return this
    },
    type(value: string) {
      this.typeValue = value
      return this
    },
    setHeader(name: string, value: string) {
      this.headers[name] = value
      return this
    },
    json(payload: unknown) {
      this.body = payload
      return this
    },
    send(payload: unknown) {
      this.body = payload
      return this
    },
  }
}

function routeHandlers(router: Router, pathTemplate: string, method: 'get') {
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

function seedInvite(input: {
  token: string
  folderId?: string
  folderName?: string
  ownerClientId?: string
  revokedAt?: string | null
  expiresAt?: string | null
  maxUses?: number
  useCount?: number
}): string {
  const folderId =
    input.folderId || `folder-${crypto.createHash('sha1').update(input.token).digest('hex').slice(0, 10)}`
  const folderName = input.folderName || 'Shared Folder'
  const ownerClientId = input.ownerClientId || 'owner-client'
  db.prepare('INSERT INTO folders (id, name, owner_client_id, owner_account_id) VALUES (?, ?, ?, NULL)').run(
    folderId,
    folderName,
    ownerClientId
  )
  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, NULL, ?, 'owner', 0)
  `
  ).run(folderId, ownerClientId, 'Owner')

  const tokenHash = crypto.createHash('sha256').update(input.token).digest('hex')
  db.prepare(
    `
    INSERT INTO invites (
      token_hash, folder_id, role, created_by, invitee_label, expires_at, max_uses, use_count, revoked_at
    ) VALUES (?, ?, 'editor', ?, NULL, ?, ?, ?, ?)
  `
  ).run(
    tokenHash,
    folderId,
    ownerClientId,
    input.expiresAt ?? new Date(Date.now() + 3600_000).toISOString(),
    input.maxUses ?? 1,
    input.useCount ?? 0,
    input.revokedAt ?? null
  )
  return tokenHash
}

const redeemHandlers = routeHandlers(inviteRouter as unknown as Router, '/redeem', 'get')
const previewHandlers = routeHandlers(inviteRouter as unknown as Router, '/preview', 'get')

test('GET /invite/redeem renders deep-link page for valid invite token', async () => {
  resetDb()
  seedInvite({ token: 'valid-token-1', folderName: 'Project Atlas' })

  const headers: Record<string, string> = {}
  const req = {
    ip: '127.0.0.1',
    query: { token: 'valid-token-1' },
    headers,
    app: { get: () => false },
    protocol: 'https',
    get(name: string) {
      if (name.toLowerCase() === 'host') return 'teams.example.com'
      return null
    },
  }

  const res = createMockResponse()
  await invokeChain(redeemHandlers, req, res)

  const html = String(res.body || '')
  assert.equal(res.statusCode, 200)
  assert.match(html, /Opening Obsidian/i)
  assert.match(html, /How to install/i)
  assert.match(html, /requires BRAT/i)
  assert.match(
    html,
    /https:\/\/github\.com\/abromberg\/obsidian-collaborative-folders#installing-before-obsidian-community-approval/
  )
})

test('GET /invite/redeem shows error page for expired invite and does not deep-link', async () => {
  resetDb()
  seedInvite({
    token: 'expired-token-1',
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  })

  const req = {
    ip: '127.0.0.1',
    query: { token: 'expired-token-1' },
    headers: {},
    app: { get: () => false },
    protocol: 'https',
    get() {
      return 'teams.example.com'
    },
  }

  const res = createMockResponse()
  await invokeChain(redeemHandlers, req, res)

  const html = String(res.body || '')
  assert.equal(res.statusCode, 410)
  assert.match(html, /Invite expired/i)
  assert.doesNotMatch(html, /obsidian:\/\/teams-join/i)
})

test('GET /invite/preview returns metadata without consuming invite token', async () => {
  resetDb()
  const tokenHash = seedInvite({
    token: 'preview-token-1',
    folderName: 'Roadmap',
    maxUses: 3,
    useCount: 1,
  })

  const req = {
    ip: '127.0.0.1',
    query: { token: 'preview-token-1' },
    headers: {},
    app: { get: () => false },
    protocol: 'https',
    get() {
      return 'teams.example.com'
    },
  }

  const res = createMockResponse()
  await invokeChain(previewHandlers, req, res)

  assert.equal(res.statusCode, 200)
  const payload = res.body as {
    folderName: string
    ownerDisplayName: string
    expiresAt: string | null
    remainingUses: number
  }
  assert.equal(payload.folderName, 'Roadmap')
  assert.equal(payload.ownerDisplayName, 'Owner')
  assert.equal(typeof payload.expiresAt, 'string')
  assert.equal(payload.remainingUses, 2)

  const inviteUsage = db.prepare('SELECT use_count FROM invites WHERE token_hash = ?').get(tokenHash) as
    | { use_count: number }
    | undefined
  assert.equal(inviteUsage?.use_count, 1)
})

test('GET /invite/preview returns lifecycle errors for consumed and revoked tokens', async () => {
  resetDb()
  seedInvite({ token: 'consumed-token', maxUses: 1, useCount: 1 })
  seedInvite({ token: 'revoked-token', revokedAt: new Date().toISOString() })

  const consumedReq = {
    ip: '127.0.0.1',
    query: { token: 'consumed-token' },
    headers: {},
    app: { get: () => false },
    protocol: 'https',
    get() {
      return 'teams.example.com'
    },
  }
  const consumedRes = createMockResponse()
  await invokeChain(previewHandlers, consumedReq, consumedRes)
  assert.equal(consumedRes.statusCode, 410)
  assert.deepEqual(consumedRes.body, { error: 'Invite consumed' })

  const revokedReq = {
    ...consumedReq,
    query: { token: 'revoked-token' },
  }
  const revokedRes = createMockResponse()
  await invokeChain(previewHandlers, revokedReq, revokedRes)
  assert.equal(revokedRes.statusCode, 410)
  assert.deepEqual(revokedRes.body, { error: 'Invite revoked' })
})
