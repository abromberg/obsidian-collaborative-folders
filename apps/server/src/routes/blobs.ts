import { Router, type Response } from 'express'
import crypto from 'crypto'
import fs from 'fs'
import { MAX_BLOB_SIZE_BYTES, BLOB_AAD_HEADER, BLOB_DIGEST_HEADER, BLOB_NONCE_HEADER, KEY_EPOCH_HEADER } from '@obsidian-teams/shared'
import { requireHttpAuth, type AuthenticatedRequest } from '../middleware/http-auth.js'
import { requireFolderRole } from '../middleware/require-role.js'
import { createRateLimiter, consumeWindowedQuota } from '../security/rate-limit.js'
import { getDb } from '../db/schema.js'
import { writeAuditEvent } from '../security/audit.js'
import { writeEncryptedBlob } from '../security/encrypted-blob-store.js'
import { isHostedModeEnabled } from '../config/hosted.js'
import {
  getAccountEntitlements,
  getFolderOwnerAccountId,
  recomputeAccountUsage,
  validateBlobUploadEntitlement,
} from '../security/entitlements.js'

export const blobsRouter: ReturnType<typeof Router> = Router()

const SHA256_HEX_RE = /^[a-f0-9]{64}$/
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/
const BLOB_UPLOAD_BYTES_PER_HOUR = Number(process.env.BLOB_UPLOAD_BYTES_PER_HOUR || 200 * 1024 * 1024)
const BLOB_DOWNLOAD_REQUESTS_PER_MINUTE = Number(process.env.BLOB_DOWNLOAD_REQUESTS_PER_MINUTE || 240)
const BLOB_UPLOAD_REQUESTS_PER_MINUTE = Number(process.env.BLOB_UPLOAD_REQUESTS_PER_MINUTE || 120)

interface BlobRow {
  id: string
  folder_id: string
  blob_id: string
  epoch: number
  size_bytes: number
  nonce: Buffer
  aad: Buffer | null
  digest_hex: string
  storage_path: string
}

function normalizeHash(hash: string): string {
  return hash.trim().toLowerCase()
}

function isValidHash(hash: string): boolean {
  return SHA256_HEX_RE.test(hash)
}

function parseEpoch(raw: string | undefined): number | null {
  if (!raw) return null
  const value = Number(raw)
  if (!Number.isFinite(value) || value <= 0) return null
  return Math.trunc(value)
}

function decodeBase64(raw: string): Buffer | null {
  if (!raw || raw.length % 4 !== 0 || !BASE64_RE.test(raw)) return null
  return Buffer.from(raw, 'base64')
}

function getActiveEpoch(folderId: string): number | null {
  const db = getDb()
  const row = db
    .prepare(
      `
      SELECT epoch
      FROM folder_key_epochs
      WHERE folder_id = ? AND status = 'active'
      ORDER BY epoch DESC
      LIMIT 1
    `
    )
    .get(folderId) as { epoch: number } | undefined

  return row?.epoch ?? null
}

const blobUploadRateLimiter = createRateLimiter({
  name: 'blob-upload',
  windowMs: 60_000,
  maxRequests: BLOB_UPLOAD_REQUESTS_PER_MINUTE,
  keyFn: (req) => {
    const actor = (req as AuthenticatedRequest).actor
    return `${req.ip}:${req.params.id}:${actor?.clientId || 'anonymous'}`
  },
})

const blobDownloadRateLimiter = createRateLimiter({
  name: 'blob-download',
  windowMs: 60_000,
  maxRequests: BLOB_DOWNLOAD_REQUESTS_PER_MINUTE,
  keyFn: (req) => {
    const actor = (req as AuthenticatedRequest).actor
    return `${req.ip}:${req.params.id}:${actor?.clientId || 'anonymous'}`
  },
})

/** PUT /api/folders/:id/blobs/:hash — Upload encrypted blob ciphertext for active epoch. */
blobsRouter.put(
  '/:id/blobs/:hash',
  requireHttpAuth,
  requireFolderRole(['editor']),
  blobUploadRateLimiter,
  (req: AuthenticatedRequest, res: Response) => {
    const actor = req.actor
    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const folderId = req.params.id
    const hash = normalizeHash(req.params.hash)
    if (!isValidHash(hash)) {
      res.status(400).json({ error: 'Invalid blob hash format' })
      return
    }

    const keyEpoch = parseEpoch(req.header(KEY_EPOCH_HEADER) || undefined)
    if (!keyEpoch) {
      res.status(400).json({ error: `Missing or invalid ${KEY_EPOCH_HEADER} header` })
      return
    }

    const activeEpoch = getActiveEpoch(folderId)
    if (!activeEpoch) {
      res.status(409).json({ error: 'No active folder key epoch for blob upload' })
      return
    }
    if (keyEpoch !== activeEpoch) {
      res.status(409).json({ error: `Stale key epoch. Active=${activeEpoch}, received=${keyEpoch}` })
      return
    }

    const nonceHeader = req.header(BLOB_NONCE_HEADER) || ''
    const nonce = decodeBase64(nonceHeader)
    if (!nonce || nonce.length < 8) {
      res.status(400).json({ error: `Missing or invalid ${BLOB_NONCE_HEADER} header` })
      return
    }

    const aadHeader = req.header(BLOB_AAD_HEADER) || ''
    const aad = aadHeader ? decodeBase64(aadHeader) : null
    if (aadHeader && !aad) {
      res.status(400).json({ error: `Invalid ${BLOB_AAD_HEADER} header` })
      return
    }

    const digestHex = normalizeHash(req.header(BLOB_DIGEST_HEADER) || hash)
    if (!isValidHash(digestHex)) {
      res.status(400).json({ error: `Invalid ${BLOB_DIGEST_HEADER} header` })
      return
    }

    const db = getDb()
    const hostedOwnerAccountId = isHostedModeEnabled() ? getFolderOwnerAccountId(db, folderId) : null
    if (hostedOwnerAccountId) {
      const preflightViolation = validateBlobUploadEntitlement(db, hostedOwnerAccountId, 0)
      if (preflightViolation) {
        res.status(preflightViolation.status).json({
          error: preflightViolation.error,
          code: preflightViolation.code,
        })
        return
      }
    }

    let maxUploadBytes = MAX_BLOB_SIZE_BYTES
    if (hostedOwnerAccountId) {
      const entitlements = getAccountEntitlements(db, hostedOwnerAccountId)
      if (entitlements) {
        maxUploadBytes = Math.min(maxUploadBytes, entitlements.maxFileSizeBytes)
      }
    }

    const existing = db
      .prepare('SELECT id FROM encrypted_blobs WHERE folder_id = ? AND blob_id = ? AND epoch = ?')
      .get(folderId, hash, keyEpoch) as { id: string } | undefined

    if (existing) {
      res.status(409).json({ message: 'Encrypted blob already exists for epoch' })
      return
    }

    const chunks: Buffer[] = []
    let totalSize = 0

    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length
      if (totalSize > maxUploadBytes) {
        writeAuditEvent(db, {
          folderId,
          actorClientId: actor.clientId,
          eventType: 'blob_upload_rejected',
          target: hash,
          metadata: {
            reason: 'max_blob_size_exceeded',
            attemptedBytes: totalSize,
            maxUploadBytes,
            hostedOwnerAccountId,
          },
        })
        res.status(413).json({
          error: `File exceeds maximum size of ${maxUploadBytes} bytes`,
          code: hostedOwnerAccountId ? 'file_size_limit_exceeded' : undefined,
          retryAfterSeconds: 60,
        })
        req.destroy()
        return
      }
      chunks.push(chunk)
    })

    req.on('end', () => {
      if (res.headersSent) return

      if (hostedOwnerAccountId) {
        const violation = validateBlobUploadEntitlement(db, hostedOwnerAccountId, totalSize)
        if (violation) {
          res.status(violation.status).json({
            error: violation.error,
            code: violation.code,
          })
          return
        }
      }

      const quota = consumeWindowedQuota({
        name: 'blob-upload-bytes-hourly',
        key: `${folderId}:${actor.clientId}`,
        windowMs: 3_600_000,
        maxAmount: BLOB_UPLOAD_BYTES_PER_HOUR,
        amount: totalSize,
      })
      if (!quota.allowed) {
        writeAuditEvent(db, {
          folderId,
          actorClientId: actor.clientId,
          eventType: 'rate_limit_violation',
          target: 'blob-upload-bytes-hourly',
          metadata: { retryAfterSeconds: quota.retryAfterSeconds, attemptedBytes: totalSize },
        })
        res.setHeader('Retry-After', String(quota.retryAfterSeconds))
        res.status(429).json({
          error: 'Blob upload throughput quota exceeded',
          retryAfterSeconds: quota.retryAfterSeconds,
        })
        return
      }

      const ciphertext = Buffer.concat(chunks)
      const storagePath = writeEncryptedBlob({ folderId, epoch: keyEpoch, blobId: hash }, ciphertext)

      const id = crypto.randomUUID()
      db.prepare(
        `
        INSERT INTO encrypted_blobs (
          id, folder_id, blob_id, epoch, size_bytes, nonce, aad, digest_hex, storage_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `
      ).run(id, folderId, hash, keyEpoch, ciphertext.length, nonce, aad, digestHex, storagePath)

      db.prepare(
        `
        INSERT INTO blob_access_log (id, folder_id, actor_client_id, hash, action)
        VALUES (?, ?, ?, ?, ?)
      `
      ).run(crypto.randomUUID(), folderId, actor.clientId, hash, 'upload')

      writeAuditEvent(db, {
        folderId,
        actorClientId: actor.clientId,
        eventType: 'blob_upload',
        target: hash,
        metadata: {
          epoch: keyEpoch,
          size: ciphertext.length,
          digestHex,
        },
      })

      if (hostedOwnerAccountId) {
        recomputeAccountUsage(db, hostedOwnerAccountId)
      }

      res.status(201).json({ blobId: hash, epoch: keyEpoch, size: ciphertext.length })
    })

    req.on('error', () => {
      if (!res.headersSent) {
        res.status(500).json({ error: 'Upload failed' })
      }
    })
  }
)

/** GET /api/folders/:id/blobs/:hash — Download encrypted blob ciphertext. */
blobsRouter.get(
  '/:id/blobs/:hash',
  requireHttpAuth,
  requireFolderRole(['editor']),
  blobDownloadRateLimiter,
  (req: AuthenticatedRequest, res: Response) => {
    const actor = req.actor
    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const folderId = req.params.id
    const hash = normalizeHash(req.params.hash)
    if (!isValidHash(hash)) {
      res.status(400).json({ error: 'Invalid blob hash format' })
      return
    }

    const activeEpoch = getActiveEpoch(folderId)
    if (!activeEpoch) {
      res.status(404).json({ error: 'No active folder key epoch' })
      return
    }

    const requestedEpoch = parseEpoch(typeof req.query.epoch === 'string' ? req.query.epoch : undefined)
    const db = getDb()
    const row = requestedEpoch
      ? (db
          .prepare(
            `
            SELECT id, folder_id, blob_id, epoch, size_bytes, nonce, aad, digest_hex, storage_path
            FROM encrypted_blobs
            WHERE folder_id = ? AND blob_id = ? AND epoch = ?
            LIMIT 1
          `
          )
          .get(folderId, hash, requestedEpoch) as BlobRow | undefined)
      : (db
          .prepare(
            `
            SELECT id, folder_id, blob_id, epoch, size_bytes, nonce, aad, digest_hex, storage_path
            FROM encrypted_blobs
            WHERE folder_id = ? AND blob_id = ? AND epoch <= ?
            ORDER BY epoch DESC
            LIMIT 1
          `
          )
          .get(folderId, hash, activeEpoch) as BlobRow | undefined)

    if (!row) {
      res.status(404).json({ error: 'Encrypted blob not found' })
      return
    }

    if (!fs.existsSync(row.storage_path)) {
      res.status(404).json({ error: 'Encrypted blob payload missing from storage' })
      return
    }

    db.prepare(
      `
      INSERT INTO blob_access_log (id, folder_id, actor_client_id, hash, action)
      VALUES (?, ?, ?, ?, ?)
    `
    ).run(crypto.randomUUID(), folderId, actor.clientId, hash, 'download')

    writeAuditEvent(db, {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'blob_download',
      target: hash,
      metadata: {
        epoch: row.epoch,
      },
    })

    res.setHeader('Content-Type', 'application/octet-stream')
    res.setHeader(KEY_EPOCH_HEADER, String(row.epoch))
    res.setHeader(BLOB_NONCE_HEADER, row.nonce.toString('base64'))
    if (row.aad) {
      res.setHeader(BLOB_AAD_HEADER, row.aad.toString('base64'))
    }
    res.setHeader(BLOB_DIGEST_HEADER, row.digest_hex)
    res.setHeader('Cache-Control', 'private, max-age=0, no-store')
    fs.createReadStream(row.storage_path).pipe(res)
  }
)
