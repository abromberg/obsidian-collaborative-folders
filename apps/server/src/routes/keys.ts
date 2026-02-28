import { Router, type Response } from 'express'
import crypto from 'crypto'
import type {
  ActiveEnvelopeUpsertRequest,
  ActiveEnvelopeUpsertResponse,
  ActiveKeyCoverageResponse,
  ClientKeyDirectoryResponse,
  ClientPublicKeyRecord,
  CurrentKeyEnvelopeResponse,
  FolderKeyEnvelopePayload,
  RegisterClientKeyRequest,
  RotateFolderKeyRequest,
  RotateFolderKeyResponse,
} from '@obsidian-teams/shared'
import { requireHttpAuth, type AuthenticatedRequest } from '../middleware/http-auth.js'
import { requireFolderRole } from '../middleware/require-role.js'
import { getDb } from '../db/schema.js'
import { writeAuditEvent } from '../security/audit.js'

export const keysRouter: ReturnType<typeof Router> = Router()

const SUPPORTED_WRAP_ALGORITHMS = new Set(['rsa-oaep', 'x25519-sealed-box', 'ecdh-p256-aeskw'])
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/

interface MemberRow {
  client_id: string
}

interface KeyDirectoryRow {
  client_id: string
  public_key: string | null
  algorithm: string | null
  created_at: string | null
  updated_at: string | null
}

interface KeyEpochRow {
  id: string
  epoch: number
  activated_at: string
}

interface EnvelopeRow {
  client_id: string
  client_public_key: string
  wrapped_key: Buffer
  wrap_algorithm: string
  created_at: string
}

function normalizeAlgorithm(value: string | undefined): string {
  return value && SUPPORTED_WRAP_ALGORITHMS.has(value) ? value : 'rsa-oaep'
}

function isBase64(value: string): boolean {
  if (!value || value.length % 4 !== 0) return false
  return BASE64_RE.test(value)
}

function decodeWrappedKey(value: string): Buffer | null {
  if (!isBase64(value)) return null
  return Buffer.from(value, 'base64')
}

function readMaxEpoch(folderId: string): number {
  const db = getDb()
  const row = db.prepare('SELECT MAX(epoch) as max_epoch FROM folder_key_epochs WHERE folder_id = ?').get(folderId) as
    | { max_epoch: number | null }
    | undefined
  return row?.max_epoch ?? 0
}

function readActiveEpoch(folderId: string): KeyEpochRow | null {
  const db = getDb()
  const row = db
    .prepare(
      `
      SELECT id, epoch, activated_at
      FROM folder_key_epochs
      WHERE folder_id = ? AND status = 'active'
      ORDER BY epoch DESC
      LIMIT 1
      `
    )
    .get(folderId) as KeyEpochRow | undefined
  return row || null
}

function readMemberIds(folderId: string): string[] {
  const db = getDb()
  const rows = db.prepare('SELECT client_id FROM members WHERE folder_id = ?').all(folderId) as MemberRow[]
  return rows.map((row) => row.client_id)
}

function readEnvelopeClientIds(folderKeyEpochId: string): string[] {
  const db = getDb()
  const rows = db
    .prepare('SELECT client_id FROM folder_key_envelopes WHERE folder_key_epoch_id = ?')
    .all(folderKeyEpochId) as MemberRow[]
  return rows.map((row) => row.client_id)
}

function computeMissingClientIds(folderId: string, folderKeyEpochId: string): string[] {
  const memberIds = readMemberIds(folderId)
  const covered = new Set(readEnvelopeClientIds(folderKeyEpochId))
  return memberIds.filter((clientId) => !covered.has(clientId))
}

/** PUT /api/folders/:id/keys/client-key — register or rotate caller's public key */
keysRouter.put(
  '/:id/keys/client-key',
  requireHttpAuth,
  requireFolderRole(['editor']),
  (req: AuthenticatedRequest, res: Response) => {
    const actor = req.actor
    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const body = (req.body || {}) as RegisterClientKeyRequest
    const publicKey = body.publicKey?.trim()
    if (!publicKey) {
      res.status(400).json({ error: 'Missing required field: publicKey' })
      return
    }

    const algorithm = normalizeAlgorithm(body.algorithm)
    if (!SUPPORTED_WRAP_ALGORITHMS.has(algorithm)) {
      res.status(400).json({ error: 'Unsupported key wrap algorithm' })
      return
    }

    const db = getDb()
    db.prepare(
      `
      INSERT INTO client_identity_keys (
        client_id, public_key, algorithm, created_at, updated_at
      ) VALUES (?, ?, ?, datetime('now'), datetime('now'))
      ON CONFLICT(client_id)
      DO UPDATE SET
        public_key = excluded.public_key,
        algorithm = excluded.algorithm,
        updated_at = datetime('now')
    `
    ).run(actor.clientId, publicKey, algorithm)

    writeAuditEvent(db, {
      folderId: req.params.id,
      actorClientId: actor.clientId,
      eventType: 'client_key_registered',
      metadata: { algorithm },
    })

    res.json({ ok: true, clientId: actor.clientId, algorithm })
  }
)

/** GET /api/folders/:id/keys/current-envelope — fetch active epoch envelope for caller */
keysRouter.get(
  '/:id/keys/current-envelope',
  requireHttpAuth,
  requireFolderRole(['editor']),
  (
    req: AuthenticatedRequest,
    res: Response<
      | CurrentKeyEnvelopeResponse
      | { folderId: string; epoch: number | null; pending: 'no_active_epoch' | 'missing_envelope' }
      | { error: string }
    >
  ) => {
    const actor = req.actor
    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const folderId = req.params.id
    const allowMissing = req.query.allowMissing === '1'
    const activeEpoch = readActiveEpoch(folderId)
    if (!activeEpoch) {
      if (allowMissing) {
        res.json({
          folderId,
          epoch: null,
          pending: 'no_active_epoch',
        })
        return
      }
      res.status(404).json({ error: 'No active folder key epoch' })
      return
    }

    const db = getDb()
    const envelope = db
      .prepare(
        `
        SELECT client_id, client_public_key, wrapped_key, wrap_algorithm, created_at
        FROM folder_key_envelopes
        WHERE folder_key_epoch_id = ? AND client_id = ?
      `
      )
      .get(activeEpoch.id, actor.clientId) as EnvelopeRow | undefined

    if (!envelope) {
      if (allowMissing) {
        res.json({
          folderId,
          epoch: activeEpoch.epoch,
          pending: 'missing_envelope',
        })
        return
      }
      res.status(404).json({ error: 'No wrapped key envelope for this client and epoch' })
      return
    }

    res.json({
      folderId,
      epoch: activeEpoch.epoch,
      envelope: {
        clientId: envelope.client_id,
        clientPublicKey: envelope.client_public_key,
        wrappedKeyBase64: envelope.wrapped_key.toString('base64'),
        wrapAlgorithm: envelope.wrap_algorithm as FolderKeyEnvelopePayload['wrapAlgorithm'],
        createdAt: envelope.created_at,
      },
    })
  }
)

/** GET /api/folders/:id/keys/clients — owner-only directory of member public keys */
keysRouter.get(
  '/:id/keys/clients',
  requireHttpAuth,
  requireFolderRole(['owner']),
  (req: AuthenticatedRequest, res: Response<ClientKeyDirectoryResponse | { error: string }>) => {
    const folderId = req.params.id
    const db = getDb()
    const rows = db
      .prepare(
        `
        SELECT m.client_id, k.public_key, k.algorithm, k.created_at, k.updated_at
        FROM members m
        LEFT JOIN client_identity_keys k ON k.client_id = m.client_id
        WHERE m.folder_id = ?
        ORDER BY m.joined_at ASC
      `
      )
      .all(folderId) as KeyDirectoryRow[]

    if (rows.some((row) => !row.public_key)) {
      res.status(409).json({ error: 'Some members have not registered client keys yet' })
      return
    }

    const members: ClientPublicKeyRecord[] = rows.map((row) => ({
      clientId: row.client_id,
      publicKey: row.public_key || '',
      algorithm: (row.algorithm || 'rsa-oaep') as ClientPublicKeyRecord['algorithm'],
      createdAt: row.created_at || new Date(0).toISOString(),
      updatedAt: row.updated_at || new Date(0).toISOString(),
    }))

    res.json({ folderId, members })
  }
)

/** GET /api/folders/:id/keys/active-coverage — owner-only active epoch envelope coverage */
keysRouter.get(
  '/:id/keys/active-coverage',
  requireHttpAuth,
  requireFolderRole(['owner']),
  (req: AuthenticatedRequest, res: Response<ActiveKeyCoverageResponse | { error: string }>) => {
    const folderId = req.params.id
    const activeEpoch = readActiveEpoch(folderId)

    if (!activeEpoch) {
      const response: ActiveKeyCoverageResponse = {
        folderId,
        epoch: null,
        missingClientIds: readMemberIds(folderId),
      }
      res.json(response)
      return
    }

    const response: ActiveKeyCoverageResponse = {
      folderId,
      epoch: activeEpoch.epoch,
      missingClientIds: computeMissingClientIds(folderId, activeEpoch.id),
    }
    res.json(response)
  }
)

/** POST /api/folders/:id/keys/active-envelopes — owner upserts envelopes for active epoch */
keysRouter.post(
  '/:id/keys/active-envelopes',
  requireHttpAuth,
  requireFolderRole(['owner']),
  (req: AuthenticatedRequest, res: Response<ActiveEnvelopeUpsertResponse | { error: string; missingClientIds?: string[] }>) => {
    const actor = req.actor
    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const folderId = req.params.id
    const activeEpoch = readActiveEpoch(folderId)
    if (!activeEpoch) {
      res.status(404).json({ error: 'No active folder key epoch' })
      return
    }

    const body = (req.body || {}) as ActiveEnvelopeUpsertRequest
    if (!Array.isArray(body.envelopes) || body.envelopes.length === 0) {
      res.status(400).json({ error: 'Missing required field: envelopes[]' })
      return
    }

    const normalizedEnvelopes: Array<{
      clientId: string
      clientPublicKey: string
      wrappedKey: Buffer
      wrapAlgorithm: string
    }> = []

    const seenClients = new Set<string>()
    for (const envelope of body.envelopes) {
      const clientId = envelope.clientId?.trim()
      const clientPublicKey = envelope.clientPublicKey?.trim()
      const wrappedKeyBase64 = envelope.wrappedKeyBase64?.trim()
      const wrapAlgorithm = normalizeAlgorithm(envelope.wrapAlgorithm)

      if (!clientId || !clientPublicKey || !wrappedKeyBase64) {
        res.status(400).json({ error: 'Each envelope must include clientId, clientPublicKey, wrappedKeyBase64' })
        return
      }
      if (seenClients.has(clientId)) {
        res.status(400).json({ error: `Duplicate envelope for clientId '${clientId}'` })
        return
      }
      seenClients.add(clientId)

      const wrappedKey = decodeWrappedKey(wrappedKeyBase64)
      if (!wrappedKey) {
        res.status(400).json({ error: `Envelope wrappedKeyBase64 is invalid for clientId '${clientId}'` })
        return
      }
      if (!SUPPORTED_WRAP_ALGORITHMS.has(wrapAlgorithm)) {
        res.status(400).json({ error: `Unsupported wrap algorithm for clientId '${clientId}'` })
        return
      }

      normalizedEnvelopes.push({
        clientId,
        clientPublicKey,
        wrappedKey,
        wrapAlgorithm,
      })
    }

    const memberIds = new Set(readMemberIds(folderId))
    if (memberIds.size === 0) {
      res.status(400).json({ error: 'Cannot upsert envelopes for folder without active members' })
      return
    }

    for (const envelope of normalizedEnvelopes) {
      if (!memberIds.has(envelope.clientId)) {
        res.status(400).json({ error: `Envelope includes non-member clientId '${envelope.clientId}'` })
        return
      }
    }

    const db = getDb()
    const upsertEnvelope = db.prepare(
      `
      INSERT INTO folder_key_envelopes (
        id, folder_key_epoch_id, folder_id, client_id, client_public_key, wrapped_key, wrap_algorithm, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(folder_key_epoch_id, client_id)
      DO UPDATE SET
        client_public_key = excluded.client_public_key,
        wrapped_key = excluded.wrapped_key,
        wrap_algorithm = excluded.wrap_algorithm,
        created_at = datetime('now')
      `
    )

    let insertedOrUpdated = 0
    for (const envelope of normalizedEnvelopes) {
      const result = upsertEnvelope.run(
        crypto.randomUUID(),
        activeEpoch.id,
        folderId,
        envelope.clientId,
        envelope.clientPublicKey,
        envelope.wrappedKey,
        envelope.wrapAlgorithm
      ) as { changes?: number }
      insertedOrUpdated += result.changes ?? 0
    }

    const missingClientIds = computeMissingClientIds(folderId, activeEpoch.id)
    writeAuditEvent(db, {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'folder_key_active_envelopes_upserted',
      target: String(activeEpoch.epoch),
      metadata: {
        insertedOrUpdated,
        missingClientIds,
      },
    })

    const response: ActiveEnvelopeUpsertResponse = {
      folderId,
      epoch: activeEpoch.epoch,
      insertedOrUpdated,
      missingClientIds,
    }
    res.status(201).json(response)
  }
)

/** POST /api/folders/:id/keys/rotate — owner rotates folder key epoch and posts wrapped envelopes */
keysRouter.post(
  '/:id/keys/rotate',
  requireHttpAuth,
  requireFolderRole(['owner']),
  (req: AuthenticatedRequest, res: Response) => {
    const actor = req.actor
    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const body = (req.body || {}) as RotateFolderKeyRequest
    const folderId = req.params.id
    const envelopes = body.envelopes

    if (!Array.isArray(envelopes) || envelopes.length === 0) {
      res.status(400).json({ error: 'Missing required field: envelopes[]' })
      return
    }

    const normalizedEnvelopes: Array<{
      clientId: string
      clientPublicKey: string
      wrappedKey: Buffer
      wrapAlgorithm: string
    }> = []

    const seenClients = new Set<string>()
    for (const envelope of envelopes) {
      const clientId = envelope.clientId?.trim()
      const clientPublicKey = envelope.clientPublicKey?.trim()
      const wrappedKeyBase64 = envelope.wrappedKeyBase64?.trim()
      const wrapAlgorithm = normalizeAlgorithm(envelope.wrapAlgorithm)

      if (!clientId || !clientPublicKey || !wrappedKeyBase64) {
        res.status(400).json({ error: 'Each envelope must include clientId, clientPublicKey, wrappedKeyBase64' })
        return
      }
      if (seenClients.has(clientId)) {
        res.status(400).json({ error: `Duplicate envelope for clientId '${clientId}'` })
        return
      }
      seenClients.add(clientId)

      const wrappedKey = decodeWrappedKey(wrappedKeyBase64)
      if (!wrappedKey) {
        res.status(400).json({ error: `Envelope wrappedKeyBase64 is invalid for clientId '${clientId}'` })
        return
      }
      if (!SUPPORTED_WRAP_ALGORITHMS.has(wrapAlgorithm)) {
        res.status(400).json({ error: `Unsupported wrap algorithm for clientId '${clientId}'` })
        return
      }

      normalizedEnvelopes.push({
        clientId,
        clientPublicKey,
        wrappedKey,
        wrapAlgorithm,
      })
    }

    const db = getDb()
    const members = db
      .prepare('SELECT client_id FROM members WHERE folder_id = ?')
      .all(folderId) as MemberRow[]

    const memberIds = new Set(members.map((member) => member.client_id))
    if (memberIds.size === 0) {
      res.status(400).json({ error: 'Cannot rotate keys for folder without active members' })
      return
    }

    for (const envelope of normalizedEnvelopes) {
      if (!memberIds.has(envelope.clientId)) {
        res.status(400).json({ error: `Envelope includes non-member clientId '${envelope.clientId}'` })
        return
      }
    }

    const missing = [...memberIds].filter((clientId) => !seenClients.has(clientId))
    if (missing.length > 0) {
      res.status(400).json({
        error: 'Envelopes must be provided for every active member',
        missingClientIds: missing,
      })
      return
    }

    const maxEpoch = readMaxEpoch(folderId)
    const requestedEpoch = typeof body.nextEpoch === 'number' ? Math.trunc(body.nextEpoch) : null
    const nextEpoch = requestedEpoch ?? maxEpoch + 1

    if (nextEpoch <= maxEpoch) {
      res.status(400).json({
        error: 'nextEpoch must be strictly greater than the current max epoch',
        currentMaxEpoch: maxEpoch,
      })
      return
    }

    const nextEpochId = crypto.randomUUID()

    db.exec('BEGIN')
    try {
      db.prepare(
        `
        UPDATE folder_key_epochs
        SET status = 'retired', retired_at = datetime('now')
        WHERE folder_id = ? AND status = 'active'
      `
      ).run(folderId)

      db.prepare(
        `
        INSERT INTO folder_key_epochs (
          id, folder_id, epoch, status, activated_at, retired_at, rotated_by, created_at
        ) VALUES (?, ?, ?, 'active', datetime('now'), NULL, ?, datetime('now'))
      `
      ).run(nextEpochId, folderId, nextEpoch, actor.clientId)

      const insertEnvelope = db.prepare(
        `
        INSERT INTO folder_key_envelopes (
          id, folder_key_epoch_id, folder_id, client_id, client_public_key, wrapped_key, wrap_algorithm, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `
      )

      for (const envelope of normalizedEnvelopes) {
        insertEnvelope.run(
          crypto.randomUUID(),
          nextEpochId,
          folderId,
          envelope.clientId,
          envelope.clientPublicKey,
          envelope.wrappedKey,
          envelope.wrapAlgorithm
        )
      }

      db.exec('COMMIT')
    } catch (error) {
      db.exec('ROLLBACK')
      throw error
    }

    const activeEpoch = readActiveEpoch(folderId)
    if (!activeEpoch || activeEpoch.epoch !== nextEpoch) {
      res.status(500).json({ error: 'Failed to activate new key epoch' })
      return
    }

    writeAuditEvent(db, {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'folder_key_rotated',
      target: String(nextEpoch),
      metadata: {
        envelopeCount: normalizedEnvelopes.length,
      },
    })

    const response: RotateFolderKeyResponse = {
      folderId,
      epoch: nextEpoch,
      activatedAt: activeEpoch.activated_at,
      envelopeCount: normalizedEnvelopes.length,
    }
    res.status(201).json(response)
  }
)
