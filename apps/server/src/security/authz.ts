import type Database from 'better-sqlite3'

export interface MemberAuthRow {
  role: 'owner' | 'editor'
  token_version: number
}

interface RevokedTokenRow {
  jti: string
}

export function getMemberAuthRow(
  db: Database.Database,
  folderId: string,
  clientId: string
): MemberAuthRow | null {
  const row = db
    .prepare('SELECT role, token_version FROM members WHERE folder_id = ? AND client_id = ?')
    .get(folderId, clientId) as MemberAuthRow | undefined

  return row ?? null
}

export function isTokenRevoked(db: Database.Database, jti: string): boolean {
  const row = db
    .prepare(`
      SELECT jti
      FROM revoked_tokens
      WHERE jti = ?
        AND (expires_at IS NULL OR expires_at > datetime('now'))
      LIMIT 1
    `)
    .get(jti) as RevokedTokenRow | undefined

  return Boolean(row)
}

export function revokeToken(
  db: Database.Database,
  input: {
    jti: string
    folderId: string
    clientId: string
    reason: string
    expiresAt?: string | null
  }
): void {
  db.prepare(`
    INSERT OR IGNORE INTO revoked_tokens (
      jti, folder_id, client_id, reason, expires_at
    ) VALUES (?, ?, ?, ?, ?)
  `).run(
    input.jti,
    input.folderId,
    input.clientId,
    input.reason,
    input.expiresAt ?? null
  )
}
