import { Router, type Request, type Response } from 'express'
import type { RefreshResponse } from '@obsidian-teams/shared'
import { generateAccessToken } from '../hooks/auth.js'
import { getDb } from '../db/schema.js'
import {
  getRefreshTokenByRawToken,
  issueRefreshToken,
  markRefreshTokenRotated,
  revokeRefreshTokenFamily,
} from '../security/refresh-tokens.js'
import { writeAuditEvent } from '../security/audit.js'
import { incrementSecurityMetric } from '../security/metrics.js'

interface RefreshRequestBody {
  refreshToken?: string
}

interface MemberRow {
  role: 'owner' | 'editor'
  display_name: string
  token_version: number
}

export const authRouter: ReturnType<typeof Router> = Router()

/** POST /api/auth/refresh — rotate refresh token and mint a fresh access token. */
authRouter.post('/refresh', (req: Request<unknown, unknown, RefreshRequestBody>, res: Response) => {
  try {
    const { refreshToken } = req.body
    if (!refreshToken) {
      res.status(400).json({ error: 'Missing required field: refreshToken' })
      return
    }

    const db = getDb()
    const row = getRefreshTokenByRawToken(db, refreshToken)
    if (!row) {
      incrementSecurityMetric('auth_denied_count')
      res.status(401).json({ error: 'Invalid refresh token' })
      return
    }

    if (row.revoked_at) {
      if (row.revoked_reason === 'rotated' || row.revoked_reason === 'family_replay') {
        revokeRefreshTokenFamily(db, row.family_id, 'family_replay')
        incrementSecurityMetric('revoked_token_use_attempt_count')
        writeAuditEvent(db, {
          folderId: row.folder_id,
          actorClientId: row.client_id,
          eventType: 'token_refresh_replay',
          target: row.family_id,
          metadata: {
            tokenHash: row.token_hash,
            priorReason: row.revoked_reason,
          },
        })
      }

      incrementSecurityMetric('auth_denied_count')
      res.status(401).json({ error: 'Refresh token has been revoked' })
      return
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      db.prepare(`
        UPDATE refresh_tokens
        SET revoked_at = COALESCE(revoked_at, datetime('now')),
            revoked_reason = COALESCE(revoked_reason, 'expired')
        WHERE token_hash = ?
      `).run(row.token_hash)

      incrementSecurityMetric('auth_denied_count')
      res.status(401).json({ error: 'Refresh token has expired' })
      return
    }

    const member = db
      .prepare('SELECT role, display_name, token_version FROM members WHERE folder_id = ? AND client_id = ?')
      .get(row.folder_id, row.client_id) as MemberRow | undefined

    if (!member) {
      revokeRefreshTokenFamily(db, row.family_id, 'member_removed')
      incrementSecurityMetric('auth_denied_count')
      res.status(403).json({ error: 'No active membership for this folder' })
      return
    }

    if (member.token_version !== row.token_version) {
      revokeRefreshTokenFamily(db, row.family_id, 'token_version_mismatch')
      incrementSecurityMetric('auth_denied_count')
      incrementSecurityMetric('revoked_token_use_attempt_count')
      res.status(401).json({ error: 'Refresh token has been invalidated' })
      return
    }

    const rotated = markRefreshTokenRotated(db, refreshToken)
    if (!rotated.ok) {
      incrementSecurityMetric('auth_denied_count')
      res.status(401).json({ error: 'Refresh token rotation failed' })
      return
    }

    const issuedRefresh = issueRefreshToken(db, {
      familyId: row.family_id,
      folderId: row.folder_id,
      clientId: row.client_id,
      displayName: member.display_name,
      role: member.role,
      tokenVersion: member.token_version,
      rotatedFromHash: rotated.tokenHash,
    })

    const accessToken = generateAccessToken(
      row.client_id,
      member.display_name,
      row.folder_id,
      member.role,
      member.token_version
    )

    writeAuditEvent(db, {
      folderId: row.folder_id,
      actorClientId: row.client_id,
      eventType: 'token_refresh_rotated',
      target: row.family_id,
      metadata: {
        oldTokenHash: row.token_hash,
        newFamilyId: issuedRefresh.familyId,
      },
    })

    const response: RefreshResponse = {
      accessToken,
      refreshToken: issuedRefresh.refreshToken,
    }
    res.json(response)
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Internal server error'
    res.status(500).json({ error: message })
  }
})
