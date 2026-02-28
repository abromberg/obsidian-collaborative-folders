import crypto from 'crypto'
import type Database from 'better-sqlite3'

export interface RefreshTokenRow {
  token_hash: string
  family_id: string
  folder_id: string
  client_id: string
  display_name: string
  role: 'owner' | 'editor'
  token_version: number
  created_at: string
  last_used_at: string | null
  expires_at: string
  rotated_from_hash: string | null
  revoked_at: string | null
  revoked_reason: string | null
}

const REFRESH_TOKEN_TTL_DAYS = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30)

function refreshTokenExpiryIso(days = REFRESH_TOKEN_TTL_DAYS): string {
  const expiry = new Date()
  expiry.setDate(expiry.getDate() + days)
  return expiry.toISOString()
}

export function hashOpaqueToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex')
}

function generateOpaqueToken(): string {
  return crypto.randomBytes(32).toString('base64url')
}

export function issueRefreshToken(
  db: Database.Database,
  input: {
    familyId?: string
    folderId: string
    clientId: string
    displayName: string
    role: 'owner' | 'editor'
    tokenVersion: number
    rotatedFromHash?: string | null
  }
): { refreshToken: string; familyId: string; expiresAt: string } {
  const refreshToken = generateOpaqueToken()
  const tokenHash = hashOpaqueToken(refreshToken)
  const familyId = input.familyId || crypto.randomUUID()
  const expiresAt = refreshTokenExpiryIso()

  db.prepare(`
    INSERT INTO refresh_tokens (
      token_hash,
      family_id,
      folder_id,
      client_id,
      display_name,
      role,
      token_version,
      expires_at,
      rotated_from_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    tokenHash,
    familyId,
    input.folderId,
    input.clientId,
    input.displayName,
    input.role,
    input.tokenVersion,
    expiresAt,
    input.rotatedFromHash ?? null
  )

  return { refreshToken, familyId, expiresAt }
}

export function getRefreshTokenByRawToken(
  db: Database.Database,
  refreshToken: string
): RefreshTokenRow | null {
  const tokenHash = hashOpaqueToken(refreshToken)
  const row = db.prepare(`
    SELECT
      token_hash,
      family_id,
      folder_id,
      client_id,
      display_name,
      role,
      token_version,
      created_at,
      last_used_at,
      expires_at,
      rotated_from_hash,
      revoked_at,
      revoked_reason
    FROM refresh_tokens
    WHERE token_hash = ?
    LIMIT 1
  `).get(tokenHash) as RefreshTokenRow | undefined

  return row ?? null
}

export function revokeRefreshTokenFamily(
  db: Database.Database,
  familyId: string,
  reason: string
): number {
  const result = db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = COALESCE(revoked_at, datetime('now')),
        revoked_reason = CASE WHEN revoked_reason IS NULL THEN ? ELSE revoked_reason END
    WHERE family_id = ?
      AND revoked_at IS NULL
  `).run(reason, familyId)

  return result.changes
}

export function revokeRefreshTokensForMember(
  db: Database.Database,
  folderId: string,
  clientId: string,
  reason: string
): number {
  const result = db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = COALESCE(revoked_at, datetime('now')),
        revoked_reason = CASE WHEN revoked_reason IS NULL THEN ? ELSE revoked_reason END
    WHERE folder_id = ?
      AND client_id = ?
      AND revoked_at IS NULL
  `).run(reason, folderId, clientId)

  return result.changes
}

export function markRefreshTokenRotated(
  db: Database.Database,
  refreshToken: string
): { ok: boolean; tokenHash: string } {
  const tokenHash = hashOpaqueToken(refreshToken)
  const result = db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = datetime('now'),
        revoked_reason = 'rotated',
        last_used_at = datetime('now')
    WHERE token_hash = ?
      AND revoked_at IS NULL
  `).run(tokenHash)

  return { ok: result.changes === 1, tokenHash }
}
