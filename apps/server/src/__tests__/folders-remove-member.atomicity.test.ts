import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'
import type { Router } from 'express'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-server-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { foldersRouter } = await import('../routes/folders.js')
const { generateAccessToken } = await import('../hooks/auth.js')
const { issueRefreshToken } = await import('../security/refresh-tokens.js')

initDb()
const db = getDb()

function resetDb(): void {
  db.exec(`
    DELETE FROM folder_key_envelopes;
    DELETE FROM folder_key_epochs;
    DELETE FROM encrypted_doc_events;
    DELETE FROM encrypted_doc_snapshots;
    DELETE FROM encrypted_blobs;
    DELETE FROM blob_access_log;
    DELETE FROM refresh_tokens;
    DELETE FROM revoked_tokens;
    DELETE FROM invites;
    DELETE FROM audit_events;
    DELETE FROM members;
    DELETE FROM folders;
  `)
}

function createMockResponse() {
  return {
    statusCode: 200,
    headers: {} as Record<string, string>,
    body: null as unknown,
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

function routeHandlers(router: Router, pathTemplate: string, method: 'delete' | 'get' | 'post') {
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

const deleteMemberHandlers = routeHandlers(
  foldersRouter as unknown as Router,
  '/:id/members/:clientId',
  'delete'
)

function seedFolderMembers(): void {
  db.prepare('INSERT INTO folders (id, name, owner_client_id) VALUES (?, ?, ?)').run(
    'folder-1',
    'Shared Folder',
    'owner-1'
  )
  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, ?)
  `
  ).run('folder-1', 'owner-1', 'Owner', 'owner', 0)
  db.prepare(
    `
    INSERT INTO members (folder_id, client_id, display_name, role, token_version)
    VALUES (?, ?, ?, ?, ?)
  `
  ).run('folder-1', 'editor-1', 'Editor', 'editor', 0)
}

function ownerToken(): string {
  return generateAccessToken('owner-1', 'Owner', 'folder-1', 'owner', 0)
}

function deleteMemberRequest(body: unknown) {
  return {
    ip: '127.0.0.1',
    headers: {
      authorization: `Bearer ${ownerToken()}`,
    },
    params: {
      id: 'folder-1',
      clientId: 'editor-1',
    },
    body,
  }
}

test('member removal rejects invalid rotate payload without side effects', async () => {
  resetDb()
  seedFolderMembers()

  issueRefreshToken(db, {
    folderId: 'folder-1',
    clientId: 'editor-1',
    displayName: 'Editor',
    role: 'editor',
    tokenVersion: 0,
  })

  const res = createMockResponse()
  await invokeChain(
    deleteMemberHandlers,
    deleteMemberRequest({
      rotate: {
        envelopes: [
          {
            clientId: 'owner-1',
            clientPublicKey: '{"kty":"RSA"}',
            wrappedKeyBase64: 'not-base64',
            wrapAlgorithm: 'rsa-oaep',
          },
        ],
      },
    }),
    res
  )

  assert.equal(res.statusCode, 400)

  const editorMembership = db
    .prepare('SELECT client_id FROM members WHERE folder_id = ? AND client_id = ?')
    .get('folder-1', 'editor-1') as { client_id: string } | undefined
  assert.ok(editorMembership)

  const refreshRows = db
    .prepare('SELECT revoked_at FROM refresh_tokens WHERE folder_id = ? AND client_id = ?')
    .all('folder-1', 'editor-1') as Array<{ revoked_at: string | null }>
  assert.equal(refreshRows.length, 1)
  assert.equal(refreshRows[0].revoked_at, null)
})

test('member removal succeeds and rotates epoch when payload is valid', async () => {
  resetDb()
  seedFolderMembers()

  const res = createMockResponse()
  await invokeChain(
    deleteMemberHandlers,
    deleteMemberRequest({
      rotate: {
        envelopes: [
          {
            clientId: 'owner-1',
            clientPublicKey: '{"kty":"RSA"}',
            wrappedKeyBase64: Buffer.from('wrapped-key').toString('base64'),
            wrapAlgorithm: 'rsa-oaep',
          },
        ],
      },
    }),
    res
  )

  assert.equal(res.statusCode, 200)
  const payload = res.body as { rotatedEpoch: number | null; success: boolean }
  assert.equal(payload.success, true)
  assert.equal(payload.rotatedEpoch, 1)

  const editorMembership = db
    .prepare('SELECT client_id FROM members WHERE folder_id = ? AND client_id = ?')
    .get('folder-1', 'editor-1') as { client_id: string } | undefined
  assert.equal(editorMembership, undefined)

  const activeEpoch = db
    .prepare('SELECT epoch, status FROM folder_key_epochs WHERE folder_id = ? AND status = ?')
    .get('folder-1', 'active') as { epoch: number; status: string } | undefined
  assert.ok(activeEpoch)
  assert.equal(activeEpoch?.epoch, 1)
})
