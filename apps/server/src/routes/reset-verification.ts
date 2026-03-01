/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import { Router, type Request, type Response } from 'express'
import fs from 'fs'
import { getDb } from '../db/schema.js'

export const resetVerificationRouter: ReturnType<typeof Router> = Router()

const RESET_VERIFICATION_TOKEN = process.env.RESET_VERIFICATION_TOKEN || ''
const BLOB_DIR = process.env.BLOB_DIR || './data/blobs'
const PROTOCOL_GATE_ENABLED = true

function requireResetToken(req: Request, res: Response): boolean {
  if (!RESET_VERIFICATION_TOKEN) {
    res.status(403).json({ error: 'Reset verification endpoint is disabled' })
    return false
  }
  const tokenFromQuery = typeof req.query.token === 'string' ? req.query.token : null
  const provided = req.header('x-reset-verification-token') || tokenFromQuery
  if (provided !== RESET_VERIFICATION_TOKEN) {
    res.status(401).json({ error: 'Invalid or missing reset verification token' })
    return false
  }
  return true
}

function countRows(tableName: string): number {
  const db = getDb()
  try {
    const row = db.prepare(`SELECT COUNT(*) AS count FROM ${tableName}`).get() as { count: number } | undefined
    return row?.count ?? 0
  } catch {
    return 0
  }
}

function countBlobFiles(): number {
  if (!fs.existsSync(BLOB_DIR)) return 0

  let count = 0
  const stack = [BLOB_DIR]

  while (stack.length > 0) {
    const current = stack.pop()
    if (!current) continue

    const entries = fs.readdirSync(current, { withFileTypes: true })
    for (const entry of entries) {
      const absolutePath = `${current}/${entry.name}`
      if (entry.isDirectory()) {
        stack.push(absolutePath)
      } else if (entry.isFile()) {
        count += 1
      }
    }
  }

  return count
}

resetVerificationRouter.get('/reset-verification', (req: Request, res: Response) => {
  if (!requireResetToken(req, res)) return

  const counts = {
    folders: countRows('folders'),
    members: countRows('members'),
    invites: countRows('invites'),
    revokedTokens: countRows('revoked_tokens'),
    refreshTokens: countRows('refresh_tokens'),
    keyEpochs: countRows('folder_key_epochs'),
    keyEnvelopes: countRows('folder_key_envelopes'),
    encryptedDocEvents: countRows('encrypted_doc_events'),
    encryptedDocSnapshots: countRows('encrypted_doc_snapshots'),
    encryptedBlobRows: countRows('encrypted_blobs'),
    blobFiles: countBlobFiles(),
  }

  const stateReset = Object.values(counts).every((value) => value === 0)

  res.json({
    status: 'ok',
    generatedAt: new Date().toISOString(),
    protocolGateEnabled: PROTOCOL_GATE_ENABLED,
    stateReset,
    counts,
  })
})
