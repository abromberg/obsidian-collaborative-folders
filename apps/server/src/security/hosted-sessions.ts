import crypto from 'crypto'
import type Database from 'better-sqlite3'
import type { Request } from 'express'
import { HOSTED_SESSION_HEADER } from '@obsidian-teams/shared'

const DEFAULT_SESSION_TTL_HOURS = Number(process.env.HOSTED_SESSION_TTL_HOURS || 24 * 30)

interface HostedSessionRow {
  session_id: string
  account_id: string
  email_norm: string
  display_name: string | null
  status: string
  expires_at: string
}

export interface HostedSessionActor {
  sessionId: string
  accountId: string
  email: string
  displayName: string
  status: string
  expiresAt: string
}

export function normalizeHostedEmail(input: string): string | null {
  const normalized = input.trim().toLowerCase()
  if (!normalized) return null
  const at = normalized.indexOf('@')
  if (at <= 0 || at >= normalized.length - 1) return null
  return normalized
}

function hashHostedSessionToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex')
}

export function extractHostedSessionToken(req: Pick<Request, 'header'>): string | null {
  const raw = req.header(HOSTED_SESSION_HEADER)
  const token = (Array.isArray(raw) ? raw[0] : raw)?.trim()
  if (!token) return null
  return token
}

export function issueHostedSession(
  db: Database.Database,
  accountId: string,
  ttlHours = DEFAULT_SESSION_TTL_HOURS
): { sessionId: string; sessionToken: string; expiresAt: string } {
  const sessionToken = crypto.randomBytes(32).toString('hex')
  const sessionId = crypto.randomUUID()
  const tokenHash = hashHostedSessionToken(sessionToken)
  const expiresAt = new Date(Date.now() + Math.max(1, ttlHours) * 3_600_000).toISOString()

  db.prepare(
    `
    INSERT INTO hosted_account_sessions (id, account_id, token_hash, expires_at)
    VALUES (?, ?, ?, ?)
  `
  ).run(sessionId, accountId, tokenHash, expiresAt)

  return {
    sessionId,
    sessionToken,
    expiresAt,
  }
}

export function revokeHostedSession(db: Database.Database, rawToken: string): boolean {
  const tokenHash = hashHostedSessionToken(rawToken)
  const result = db.prepare(
    `
    UPDATE hosted_account_sessions
    SET revoked_at = COALESCE(revoked_at, datetime('now'))
    WHERE token_hash = ?
      AND revoked_at IS NULL
  `
  ).run(tokenHash)

  return result.changes > 0
}

export function resolveHostedSession(
  db: Database.Database,
  rawToken: string
): HostedSessionActor | null {
  const tokenHash = hashHostedSessionToken(rawToken)
  const row = db
    .prepare(
      `
      SELECT
        s.id AS session_id,
        s.account_id,
        a.email_norm,
        a.display_name,
        a.status,
        s.expires_at
      FROM hosted_account_sessions s
      JOIN hosted_accounts a ON a.id = s.account_id
      WHERE s.token_hash = ?
        AND s.revoked_at IS NULL
      LIMIT 1
    `
    )
    .get(tokenHash) as HostedSessionRow | undefined

  if (!row) return null
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    db.prepare(
      `
      UPDATE hosted_account_sessions
      SET revoked_at = COALESCE(revoked_at, datetime('now'))
      WHERE id = ?
    `
    ).run(row.session_id)
    return null
  }

  return {
    sessionId: row.session_id,
    accountId: row.account_id,
    email: row.email_norm,
    displayName: row.display_name || row.email_norm,
    status: row.status,
    expiresAt: row.expires_at,
  }
}
