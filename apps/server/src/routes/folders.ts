import { Router, type Response } from 'express'
import crypto from 'crypto'
import type { FolderInviteStatus, FolderInvitesResponse, RotateFolderKeyRequest } from '@obsidian-teams/shared'
import { getDb } from '../db/schema.js'
import { requireHttpAuth, type AuthenticatedRequest } from '../middleware/http-auth.js'
import { requireFolderRole } from '../middleware/require-role.js'
import { revokeToken } from '../security/authz.js'
import { revokeRefreshTokensForMember } from '../security/refresh-tokens.js'
import { listMemberSessionJtis, revokeMemberSessions } from '../security/session-registry.js'
import { createRateLimiter } from '../security/rate-limit.js'
import { writeAuditEvent } from '../security/audit.js'

export const foldersRouter: ReturnType<typeof Router> = Router()

const TOKEN_HASH_RE = /^[a-f0-9]{64}$/
const SUPPORTED_WRAP_ALGORITHMS = new Set(['rsa-oaep', 'x25519-sealed-box', 'ecdh-p256-aeskw'])
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/

const memberMutationRateLimiter = createRateLimiter({
  name: 'folder-member-mutation',
  windowMs: 60_000,
  maxRequests: Number(process.env.FOLDER_MEMBER_MUTATIONS_PER_MINUTE || 30),
  keyFn: (req) => {
    const actor = (req as AuthenticatedRequest).actor
    return `${req.ip}:${req.params.id}:${actor?.clientId || 'anonymous'}`
  },
})

interface MemberRow {
  client_id: string
  account_id?: string | null
  display_name: string
  invitee_label: string | null
  role: 'owner' | 'editor'
  token_version: number
  joined_at: string
}

interface FolderRow {
  id: string
  name: string
  owner_client_id: string
  created_at: string
}

interface InviteRow {
  token_hash: string
  role: 'editor'
  created_at: string
  created_by: string | null
  invitee_label: string | null
  expires_at: string | null
  max_uses: number
  use_count: number
  consumed_at: string | null
  consumed_by: string | null
  revoked_at: string | null
  revoked_by: string | null
}

interface RemoveMemberBody {
  rotate?: RotateFolderKeyRequest
}

function normalizeAlgorithm(value: string | undefined): string {
  return value && SUPPORTED_WRAP_ALGORITHMS.has(value) ? value : 'rsa-oaep'
}

function decodeWrappedKey(value: string): Buffer | null {
  if (!value || value.length % 4 !== 0 || !BASE64_RE.test(value)) return null
  return Buffer.from(value, 'base64')
}

function deriveInviteStatus(invite: InviteRow): FolderInviteStatus {
  if (invite.revoked_at) return 'revoked'
  if (invite.expires_at && new Date(invite.expires_at).getTime() <= Date.now()) return 'expired'
  if (invite.consumed_at || invite.use_count >= invite.max_uses) return 'consumed'
  return 'active'
}

/** GET /api/folders/:id/members — List members of a folder */
foldersRouter.get(
  '/:id/members',
  requireHttpAuth,
  requireFolderRole(['editor']),
  (req: AuthenticatedRequest, res: Response) => {
    const db = getDb()
    const members = db.prepare(
      `
      SELECT
        m.client_id,
        m.display_name,
        (
          SELECT i.invitee_label
          FROM invites i
          WHERE i.folder_id = m.folder_id
            AND i.consumed_by = m.client_id
            AND i.consumed_at IS NOT NULL
            AND i.invitee_label IS NOT NULL
          ORDER BY datetime(i.consumed_at) DESC
          LIMIT 1
        ) AS invitee_label,
        m.role,
        m.token_version,
        m.joined_at
      FROM members m
      WHERE m.folder_id = ?
      `
    ).all(req.params.id) as MemberRow[]

    res.json({ members })
  }
)

/** GET /api/folders/:id/invites — List invites for a folder (owner only) */
foldersRouter.get(
  '/:id/invites',
  requireHttpAuth,
  requireFolderRole(['owner']),
  (req: AuthenticatedRequest, res: Response<FolderInvitesResponse>) => {
    const db = getDb()
    const rows = db.prepare(
      `
      SELECT
        token_hash,
        role,
        created_at,
        created_by,
        invitee_label,
        expires_at,
        max_uses,
        use_count,
        consumed_at,
        consumed_by,
        revoked_at,
        revoked_by
      FROM invites
      WHERE folder_id = ?
      ORDER BY datetime(created_at) DESC
      `
    ).all(req.params.id) as InviteRow[]

    const invites = rows.map((invite) => ({
      tokenHash: invite.token_hash,
      role: invite.role,
      createdAt: invite.created_at,
      createdBy: invite.created_by,
      inviteeLabel: invite.invitee_label,
      expiresAt: invite.expires_at,
      maxUses: invite.max_uses,
      useCount: invite.use_count,
      consumedAt: invite.consumed_at,
      consumedBy: invite.consumed_by,
      revokedAt: invite.revoked_at,
      revokedBy: invite.revoked_by,
      status: deriveInviteStatus(invite),
    }))

    res.json({ invites })
  }
)

/** DELETE /api/folders/:id/members/:clientId — Remove a member */
foldersRouter.delete(
  '/:id/members/:clientId',
  requireHttpAuth,
  requireFolderRole(['owner']),
  memberMutationRateLimiter,
  (req: AuthenticatedRequest, res: Response) => {
    const db = getDb()
    const { id, clientId } = req.params
    const body = (req.body || {}) as RemoveMemberBody

    const actor = req.actor
    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const member = db.prepare(
      'SELECT client_id, account_id, display_name, role, token_version, joined_at FROM members WHERE folder_id = ? AND client_id = ?'
    ).get(id, clientId) as MemberRow | undefined

    if (!member) {
      res.status(404).json({ error: 'Member not found' })
      return
    }

    if (member.role === 'owner') {
      res.status(403).json({ error: 'Cannot remove the folder owner' })
      return
    }

    const sessionJtis = listMemberSessionJtis(id, clientId)
    const sessionJtiSet = new Set(sessionJtis)
    const rotate = body.rotate
    if (rotate && (!Array.isArray(rotate.envelopes) || rotate.envelopes.length === 0)) {
      res.status(400).json({ error: 'rotate.envelopes must include at least one entry when rotate is provided' })
      return
    }

    let rotationPlan:
      | {
          nextEpochId: string
          nextEpoch: number
          envelopes: Array<{
            clientId: string
            clientPublicKey: string
            wrappedKey: Buffer
            wrapAlgorithm: string
          }>
        }
      | null = null

    if (rotate?.envelopes?.length) {
      const remainingMembers = db
        .prepare('SELECT client_id FROM members WHERE folder_id = ? AND client_id <> ?')
        .all(id, clientId) as Array<{ client_id: string }>
      const memberIds = new Set(remainingMembers.map((row) => row.client_id))
      if (memberIds.size === 0) {
        res.status(400).json({ error: 'Cannot rotate keys for empty remaining member set' })
        return
      }

      const normalized = new Map<
        string,
        {
          clientId: string
          clientPublicKey: string
          wrappedKey: Buffer
          wrapAlgorithm: string
        }
      >()

      for (const envelope of rotate.envelopes) {
        const normalizedClientId = envelope.clientId?.trim()
        const normalizedPublicKey = envelope.clientPublicKey?.trim()
        const wrappedKey = decodeWrappedKey(envelope.wrappedKeyBase64?.trim() || '')
        const wrapAlgorithm = normalizeAlgorithm(envelope.wrapAlgorithm)

        if (!normalizedClientId || !normalizedPublicKey || !wrappedKey) {
          res.status(400).json({ error: 'rotate.envelopes entries must include valid clientId/clientPublicKey/wrappedKeyBase64' })
          return
        }
        if (normalized.has(normalizedClientId)) {
          res.status(400).json({ error: `rotate envelope includes duplicate clientId '${normalizedClientId}'` })
          return
        }
        if (!memberIds.has(normalizedClientId)) {
          res.status(400).json({ error: `rotate envelope includes non-member clientId '${normalizedClientId}'` })
          return
        }

        normalized.set(normalizedClientId, {
          clientId: normalizedClientId,
          clientPublicKey: normalizedPublicKey,
          wrappedKey,
          wrapAlgorithm,
        })
      }

      const missing = [...memberIds].filter((memberId) => !normalized.has(memberId))
      if (missing.length > 0) {
        res.status(400).json({
          error: 'rotate envelopes must be provided for all remaining members',
          missingClientIds: missing,
        })
        return
      }

      const maxEpochRow = db
        .prepare('SELECT MAX(epoch) AS max_epoch FROM folder_key_epochs WHERE folder_id = ?')
        .get(id) as { max_epoch: number | null } | undefined
      const maxEpoch = maxEpochRow?.max_epoch ?? 0
      const requestedEpoch = typeof rotate.nextEpoch === 'number' ? Math.trunc(rotate.nextEpoch) : null
      const nextEpoch = requestedEpoch ?? maxEpoch + 1
      if (nextEpoch <= maxEpoch) {
        res.status(400).json({ error: 'rotate.nextEpoch must be greater than current max epoch', currentMaxEpoch: maxEpoch })
        return
      }

      rotationPlan = {
        nextEpochId: crypto.randomUUID(),
        nextEpoch,
        envelopes: [...normalized.values()],
      }
    }

    let rotatedEpoch: number | null = null
    let revokedRefreshCount = 0
    db.exec('BEGIN')
    try {
      for (const jti of sessionJtis) {
        revokeToken(db, {
          jti,
          folderId: id,
          clientId,
          reason: 'member_removed',
        })
      }

      revokedRefreshCount = revokeRefreshTokensForMember(db, id, clientId, 'member_removed')

      const memberDelete = db.prepare('DELETE FROM members WHERE folder_id = ? AND client_id = ?').run(id, clientId)
      if (memberDelete.changes !== 1) {
        throw new Error('Member delete mutation failed')
      }

      if (rotationPlan) {
        db.prepare(
          `
          UPDATE folder_key_epochs
          SET status = 'retired', retired_at = datetime('now')
          WHERE folder_id = ? AND status = 'active'
        `
        ).run(id)

        db.prepare(
          `
          INSERT INTO folder_key_epochs (
            id, folder_id, epoch, status, activated_at, retired_at, rotated_by, created_at
          ) VALUES (?, ?, ?, 'active', datetime('now'), NULL, ?, datetime('now'))
        `
        ).run(rotationPlan.nextEpochId, id, rotationPlan.nextEpoch, actor.clientId)

        const insertEnvelope = db.prepare(
          `
          INSERT INTO folder_key_envelopes (
            id, folder_key_epoch_id, folder_id, client_id, client_public_key, wrapped_key, wrap_algorithm, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `
        )

        for (const envelope of rotationPlan.envelopes) {
          insertEnvelope.run(
            crypto.randomUUID(),
            rotationPlan.nextEpochId,
            id,
            envelope.clientId,
            envelope.clientPublicKey,
            envelope.wrappedKey,
            envelope.wrapAlgorithm
          )
        }

        rotatedEpoch = rotationPlan.nextEpoch
      }

      db.exec('COMMIT')
    } catch (error) {
      db.exec('ROLLBACK')
      const message = error instanceof Error ? error.message : 'Failed to remove member'
      res.status(500).json({ error: message })
      return
    }

    const sessionRevocation = revokeMemberSessions(id, clientId, 'member-removed')
    for (const jti of sessionRevocation.revokedJtis) {
      if (sessionJtiSet.has(jti)) continue
      try {
        revokeToken(db, {
          jti,
          folderId: id,
          clientId,
          reason: 'member_removed',
        })
      } catch {
        // best effort only; membership + refresh revocation already committed
      }
    }

    writeAuditEvent(db, {
      folderId: id,
      actorClientId: actor.clientId,
      eventType: 'member_remove',
      target: clientId,
      metadata: {
        closedWsSessions: sessionRevocation.closedCount,
        revokedAccessTokens: sessionRevocation.revokedJtis.length,
        revokedRefreshTokens: revokedRefreshCount,
        rotatedEpoch,
      },
    })

    res.json({
      success: true,
      closedWsSessions: sessionRevocation.closedCount,
      revokedAccessTokens: sessionRevocation.revokedJtis.length,
      revokedRefreshTokens: revokedRefreshCount,
      rotatedEpoch,
      rekeyRequired: !rotatedEpoch,
    })
  }
)

/** DELETE /api/folders/:id/invites/:tokenHash — Revoke an invite token hash */
foldersRouter.delete(
  '/:id/invites/:tokenHash',
  requireHttpAuth,
  requireFolderRole(['owner']),
  memberMutationRateLimiter,
  (req: AuthenticatedRequest, res: Response) => {
    const db = getDb()
    const { id, tokenHash } = req.params
    const actor = req.actor

    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const normalizedHash = tokenHash.toLowerCase()
    if (!TOKEN_HASH_RE.test(normalizedHash)) {
      res.status(400).json({ error: 'Invalid invite token hash format' })
      return
    }

    const result = db.prepare(`
      UPDATE invites
      SET revoked_at = datetime('now'),
          revoked_by = ?
      WHERE folder_id = ?
        AND token_hash = ?
        AND revoked_at IS NULL
    `).run(actor.clientId, id, normalizedHash)

    if (result.changes !== 1) {
      res.status(404).json({ error: 'Invite not found or already revoked' })
      return
    }

    writeAuditEvent(db, {
      folderId: id,
      actorClientId: actor.clientId,
      eventType: 'invite_revoke',
      target: normalizedHash,
    })

    res.json({ success: true })
  }
)

/** GET /api/folders/:id — Get folder info */
foldersRouter.get(
  '/:id',
  requireHttpAuth,
  requireFolderRole(['editor']),
  (req: AuthenticatedRequest, res: Response) => {
    const db = getDb()
    const folder = db.prepare('SELECT * FROM folders WHERE id = ?').get(req.params.id) as FolderRow | undefined

    if (!folder) {
      res.status(404).json({ error: 'Folder not found' })
      return
    }

    const members = db.prepare(
      'SELECT client_id, display_name, role, token_version FROM members WHERE folder_id = ?'
    ).all(req.params.id) as Array<Pick<MemberRow, 'client_id' | 'display_name' | 'role' | 'token_version'>>

    res.json({ ...folder, members })
  }
)
