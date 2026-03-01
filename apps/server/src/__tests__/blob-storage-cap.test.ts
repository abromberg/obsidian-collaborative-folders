import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'
import { EventEmitter } from 'events'
import type { Router } from 'express'
import { KEY_EPOCH_HEADER, BLOB_NONCE_HEADER, BLOB_DIGEST_HEADER } from '@obsidian-teams/shared'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-blob-cap-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.HOSTED_MODE = 'true'
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { blobsRouter } = await import('../routes/blobs.js')
const { generateAccessToken } = await import('../hooks/auth.js')

initDb()
const db = getDb()

function resetDb(): void {
  db.exec(`
    DELETE FROM hosted_account_sessions;
    DELETE FROM hosted_account_usage;
    DELETE FROM hosted_account_billing;
    DELETE FROM hosted_accounts;
    DELETE FROM encrypted_blobs;
    DELETE FROM folder_key_epochs;
    DELETE FROM members;
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

function routeHandlers(router: Router, pathTemplate: string, method: 'put') {
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

class MockUploadRequest extends EventEmitter {
  headers: Record<string, string>
  params: { id: string; hash: string }
  ip = '127.0.0.1'
  actor: unknown
  body: unknown
  private payload: Buffer
  private started = false
  private terminated = false

  constructor(input: {
    headers: Record<string, string>
    folderId: string
    hash: string
    payload: Buffer
  }) {
    super()
    this.headers = input.headers
    this.params = { id: input.folderId, hash: input.hash }
    this.payload = input.payload
  }

  header(name: string): string | undefined {
    return this.headers[name.toLowerCase()]
  }

  override on(event: string, listener: (...args: any[]) => void): this {
    const result = super.on(event, listener)
    if (!this.started && event === 'end') {
      this.started = true
      queueMicrotask(() => {
        if (this.terminated) return
        this.emit('data', this.payload)
        if (this.terminated) return
        this.emit('end')
      })
    }
    return result
  }

  destroy(): void {
    this.terminated = true
  }
}

const uploadHandlers = routeHandlers(blobsRouter as unknown as Router, '/:id/blobs/:hash', 'put')

test('hosted blob uploads are denied when owner storage cap would be exceeded', async () => {
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
    ) VALUES (?, 'active', 900, 10, 26214400, datetime('now'))
  `
  ).run('acct-owner')

  db.prepare('INSERT INTO folders (id, name, owner_client_id, owner_account_id) VALUES (?, ?, ?, ?)').run(
    'folder-1',
    'Shared Folder',
    'owner-client-1',
    'acct-owner'
  )

  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, ?, ?)
  `
  ).run('folder-1', 'owner-client-1', 'acct-owner', 'Owner', 'owner', 0)

  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, account_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, ?, ?)
  `
  ).run('folder-1', 'editor-client-1', 'acct-owner', 'Editor', 'editor', 0)

  db.prepare(
    `
    INSERT INTO folder_key_epochs (id, folder_id, epoch, status, activated_at, created_at)
    VALUES (?, ?, 1, 'active', datetime('now'), datetime('now'))
  `
  ).run('epoch-1', 'folder-1')

  db.prepare(
    `
    INSERT INTO encrypted_blobs (
      id, folder_id, blob_id, epoch, size_bytes, nonce, aad, digest_hex, storage_path
    ) VALUES (?, ?, ?, 1, 9, ?, NULL, ?, ?)
  `
  ).run(
    'blob-existing',
    'folder-1',
    'existing-blob',
    Buffer.from('nonce-bytes'),
    'f'.repeat(64),
    '/tmp/existing-blob'
  )

  const token = generateAccessToken('editor-client-1', 'Editor', 'folder-1', 'editor', 0)
  const uploadHash = 'a'.repeat(64)
  const payload = Buffer.from('12')

  const req = new MockUploadRequest({
    headers: {
      authorization: `Bearer ${token}`,
      [KEY_EPOCH_HEADER.toLowerCase()]: '1',
      [BLOB_NONCE_HEADER.toLowerCase()]: Buffer.from('nonce-123456').toString('base64'),
      [BLOB_DIGEST_HEADER.toLowerCase()]: uploadHash,
    },
    folderId: 'folder-1',
    hash: uploadHash,
    payload,
  })

  const res = createMockResponse()
  await invokeChain(uploadHandlers, req, res)
  await new Promise((resolve) => setTimeout(resolve, 0))

  assert.equal(res.statusCode, 409)
  assert.deepEqual(res.body, {
    error: 'Hosted owner storage cap exceeded',
    code: 'storage_limit_reached',
  })
})
