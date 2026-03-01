import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'
import crypto from 'crypto'
import type { Router } from 'express'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-file-links-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.HOSTED_MODE = 'false'
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { fileLinksRouter } = await import('../routes/file-links.js')
const { generateAccessToken } = await import('../hooks/auth.js')

initDb()
const db = getDb()

function resetDb(): void {
  db.exec(`
    DELETE FROM audit_events;
    DELETE FROM file_share_links;
    DELETE FROM members;
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

function routeHandlers(router: Router, pathTemplate: string, method: 'get' | 'post') {
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

function seedFolderMembers(folderId = 'folder-1'): void {
  db.prepare('INSERT INTO folders (id, name, owner_client_id) VALUES (?, ?, ?)').run(folderId, 'Roadmap', 'owner-1')
  db.prepare(
    `
      INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
      VALUES (?, ?, NULL, ?, ?, ?)
    `
  ).run(folderId, 'owner-1', 'Owner', 'owner', 0)
  db.prepare(
    `
      INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
      VALUES (?, ?, NULL, ?, ?, ?)
    `
  ).run(folderId, 'editor-1', 'Editor', 'editor', 0)
}

function seedFileLink(input: {
  token: string
  folderId?: string
  fileId?: string | null
  relativePath?: string
  fileName?: string
  createdBy?: string
  expiresAt?: string
  revokedAt?: string | null
  revokedBy?: string | null
}): string {
  const tokenHash = crypto.createHash('sha256').update(input.token).digest('hex')
  db.prepare(
    `
      INSERT INTO file_share_links (
        token_hash, folder_id, file_id, relative_path, file_name, created_by, expires_at, revoked_at, revoked_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  ).run(
    tokenHash,
    input.folderId || 'folder-1',
    input.fileId || null,
    input.relativePath || 'notes/plan.md',
    input.fileName || 'plan.md',
    input.createdBy || 'editor-1',
    input.expiresAt || new Date(Date.now() + 3600_000).toISOString(),
    input.revokedAt || null,
    input.revokedBy || null
  )
  return tokenHash
}

const createHandlers = routeHandlers(fileLinksRouter as unknown as Router, '/folders/:id/file-links', 'post')
const previewHandlers = routeHandlers(fileLinksRouter as unknown as Router, '/file-links/preview', 'get')
const openHandlers = routeHandlers(fileLinksRouter as unknown as Router, '/file-links/open', 'get')
const resolveHandlers = routeHandlers(fileLinksRouter as unknown as Router, '/folders/:id/file-links/resolve', 'post')

test('POST /folders/:id/file-links allows editor and stores only token hash', async () => {
  resetDb()
  seedFolderMembers('folder-1')

  const accessToken = generateAccessToken('editor-1', 'Editor', 'folder-1', 'editor', 0)
  const req = {
    ip: '127.0.0.1',
    params: { id: 'folder-1' },
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
    body: {
      fileId: 'file-123',
      relativePath: 'notes/plan.md',
      fileName: 'plan.md',
    },
    app: { get: () => false },
    protocol: 'https',
    get(name: string) {
      if (name.toLowerCase() === 'host') return 'teams.example.com'
      return null
    },
  }

  const res = createMockResponse()
  await invokeChain(createHandlers, req, res)

  assert.equal(res.statusCode, 201)
  const payload = res.body as { shareToken: string; shareUrl: string; expiresAt: string }
  assert.match(payload.shareToken, /^file-[a-f0-9]{40}$/)
  assert.match(payload.shareUrl, /\/api\/file-links\/open\?token=/)
  assert.equal(typeof payload.expiresAt, 'string')

  const stored = db
    .prepare('SELECT * FROM file_share_links WHERE folder_id = ?')
    .get('folder-1') as
    | {
        token_hash: string
        file_id: string | null
        relative_path: string
        file_name: string
      }
    | undefined
  assert.ok(stored)
  assert.notEqual(stored?.token_hash, payload.shareToken)
  assert.equal(stored?.file_id, 'file-123')
  assert.equal(stored?.relative_path, 'notes/plan.md')
  assert.equal(stored?.file_name, 'plan.md')

  const event = db
    .prepare('SELECT event_type FROM audit_events WHERE event_type = ? LIMIT 1')
    .get('file_link_create') as { event_type: string } | undefined
  assert.equal(event?.event_type, 'file_link_create')
})

test('GET /file-links/preview returns only non-sensitive metadata', async () => {
  resetDb()
  seedFolderMembers('folder-1')
  const token = 'preview-file-token'
  seedFileLink({
    token,
    folderId: 'folder-1',
    relativePath: 'private/roadmap.md',
    fileName: 'roadmap.md',
  })

  const req = {
    ip: '127.0.0.1',
    query: { token },
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
    folderId: string
    folderName: string
    fileName: string
    expiresAt: string
    relativePath?: string
  }
  assert.equal(payload.folderId, 'folder-1')
  assert.equal(payload.folderName, 'Roadmap')
  assert.equal(payload.fileName, 'roadmap.md')
  assert.equal(typeof payload.expiresAt, 'string')
  assert.equal(payload.relativePath, undefined)
})

test('GET /file-links/open renders teams-open-file deep-link and handles expired tokens', async () => {
  resetDb()
  seedFolderMembers('folder-1')
  seedFileLink({
    token: 'open-valid-token',
    folderId: 'folder-1',
    fileName: 'meeting-notes.md',
  })

  const validReq = {
    ip: '127.0.0.1',
    query: { token: 'open-valid-token' },
    headers: {},
    app: { get: () => false },
    protocol: 'https',
    get() {
      return 'teams.example.com'
    },
  }
  const validRes = createMockResponse()
  await invokeChain(openHandlers, validReq, validRes)

  const html = String(validRes.body || '')
  assert.equal(validRes.statusCode, 200)
  assert.match(html, /obsidian:\/\/teams-open-file\?token=/)
  assert.match(html, /meeting-notes\.md/)

  seedFileLink({
    token: 'open-expired-token',
    folderId: 'folder-1',
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  })
  const expiredReq = {
    ...validReq,
    query: { token: 'open-expired-token' },
  }
  const expiredRes = createMockResponse()
  await invokeChain(openHandlers, expiredReq, expiredRes)
  assert.equal(expiredRes.statusCode, 410)
  assert.doesNotMatch(String(expiredRes.body || ''), /obsidian:\/\/teams-open-file\?token=/)
})

test('preview and resolve return invalid/revoked lifecycle errors', async () => {
  resetDb()
  seedFolderMembers('folder-1')
  seedFileLink({
    token: 'revoked-file-token',
    folderId: 'folder-1',
    revokedAt: new Date().toISOString(),
    revokedBy: 'owner-1',
  })

  const baseReq = {
    ip: '127.0.0.1',
    headers: {},
    app: { get: () => false },
    protocol: 'https',
    get() {
      return 'teams.example.com'
    },
  }

  const invalidPreviewRes = createMockResponse()
  await invokeChain(previewHandlers, { ...baseReq, query: { token: 'missing-file-token' } }, invalidPreviewRes)
  assert.equal(invalidPreviewRes.statusCode, 404)
  assert.deepEqual(invalidPreviewRes.body, { error: 'File link not found' })

  const revokedPreviewRes = createMockResponse()
  await invokeChain(previewHandlers, { ...baseReq, query: { token: 'revoked-file-token' } }, revokedPreviewRes)
  assert.equal(revokedPreviewRes.statusCode, 410)
  assert.deepEqual(revokedPreviewRes.body, { error: 'File link revoked' })

  const accessToken = generateAccessToken('editor-1', 'Editor', 'folder-1', 'editor', 0)
  const invalidResolveRes = createMockResponse()
  await invokeChain(
    resolveHandlers,
    {
      ip: '127.0.0.1',
      params: { id: 'folder-1' },
      headers: { authorization: `Bearer ${accessToken}` },
      body: { token: 'missing-file-token' },
    },
    invalidResolveRes
  )
  assert.equal(invalidResolveRes.statusCode, 404)
  assert.deepEqual(invalidResolveRes.body, { error: 'File link not found' })
})

test('POST /folders/:id/file-links/resolve returns path for member and increments open_count', async () => {
  resetDb()
  seedFolderMembers('folder-1')
  const token = 'resolve-success-token'
  const tokenHash = seedFileLink({
    token,
    folderId: 'folder-1',
    fileId: 'file-abc',
    relativePath: 'notes/today.md',
    fileName: 'today.md',
  })

  const accessToken = generateAccessToken('editor-1', 'Editor', 'folder-1', 'editor', 0)
  const req = {
    ip: '127.0.0.1',
    params: { id: 'folder-1' },
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
    body: { token },
  }

  const res = createMockResponse()
  await invokeChain(resolveHandlers, req, res)

  assert.equal(res.statusCode, 200)
  assert.deepEqual(res.body, {
    folderId: 'folder-1',
    fileId: 'file-abc',
    relativePath: 'notes/today.md',
    fileName: 'today.md',
  })

  const row = db.prepare('SELECT open_count FROM file_share_links WHERE token_hash = ?').get(tokenHash) as
    | { open_count: number }
    | undefined
  assert.equal(row?.open_count, 1)

  const event = db
    .prepare('SELECT event_type FROM audit_events WHERE event_type = ? LIMIT 1')
    .get('file_link_resolve_success') as { event_type: string } | undefined
  assert.equal(event?.event_type, 'file_link_resolve_success')
})

test('POST /folders/:id/file-links/resolve denies non-members and folder mismatch without path disclosure', async () => {
  resetDb()
  seedFolderMembers('folder-1')
  seedFolderMembers('folder-2')

  const token = 'resolve-denied-token'
  seedFileLink({
    token,
    folderId: 'folder-1',
    fileId: 'file-nope',
    relativePath: 'secret/path.md',
    fileName: 'path.md',
  })

  const intruderToken = generateAccessToken('intruder-1', 'Intruder', 'folder-1', 'editor', 0)
  const nonMemberReq = {
    ip: '127.0.0.1',
    params: { id: 'folder-1' },
    headers: {
      authorization: `Bearer ${intruderToken}`,
    },
    body: { token },
  }
  const nonMemberRes = createMockResponse()
  await invokeChain(resolveHandlers, nonMemberReq, nonMemberRes)
  assert.equal(nonMemberRes.statusCode, 403)
  assert.equal((nonMemberRes.body as any).relativePath, undefined)

  const folderTwoToken = generateAccessToken('editor-1', 'Editor', 'folder-2', 'editor', 0)
  const mismatchReq = {
    ip: '127.0.0.1',
    params: { id: 'folder-2' },
    headers: {
      authorization: `Bearer ${folderTwoToken}`,
    },
    body: { token },
  }
  const mismatchRes = createMockResponse()
  await invokeChain(resolveHandlers, mismatchReq, mismatchRes)
  assert.equal(mismatchRes.statusCode, 404)
  assert.equal((mismatchRes.body as any).relativePath, undefined)

  const deniedEvent = db
    .prepare('SELECT event_type FROM audit_events WHERE event_type = ? LIMIT 1')
    .get('file_link_resolve_denied') as { event_type: string } | undefined
  assert.equal(deniedEvent?.event_type, 'file_link_resolve_denied')
})
