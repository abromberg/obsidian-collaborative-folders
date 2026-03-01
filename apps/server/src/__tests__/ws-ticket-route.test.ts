import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'
import type { Router } from 'express'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-ws-route-test-'))
process.env.DB_PATH = path.join(tempRoot, 'test.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const { wsRouter } = await import('../routes/ws.js')
const { generateAccessToken } = await import('../hooks/auth.js')
const { clearWsTicketsForTests, consumeWsTicket } = await import('../security/ws-tickets.js')

initDb()
const db = getDb()

function resetDb(): void {
  db.exec(`
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

const issueTicketHandlers = routeHandlers(wsRouter as unknown as Router, '/:id/ws-ticket', 'post')

test('ws-ticket route issues one-time ticket for authenticated folder member', async () => {
  clearWsTicketsForTests()
  resetDb()

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
  ).run('folder-1', 'member-1', 'Member', 'editor', 4)

  const token = generateAccessToken('member-1', 'Member', 'folder-1', 'editor', 4)
  const req = {
    ip: '127.0.0.1',
    headers: {
      authorization: `Bearer ${token}`,
    },
    params: {
      id: 'folder-1',
    },
    body: {
      roomName: 'folder:folder-1:doc:notes.md',
    },
  }
  const res = createMockResponse()
  await invokeChain(issueTicketHandlers, req, res)

  assert.equal(res.statusCode, 201)
  const payload = res.body as { ticket: string; expiresAt: string }
  assert.ok(payload.ticket)
  assert.ok(payload.expiresAt)

  const consumed = consumeWsTicket(payload.ticket)
  assert.ok(consumed)
  assert.equal(consumed?.clientId, 'member-1')
  assert.equal(consumed?.roomName, 'folder:folder-1:doc:notes.md')
})
