/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import { Router, type Request, type Response } from 'express'
import crypto from 'crypto'
import type { HostedAuthMeResponse, HostedSessionResponse } from '@obsidian-teams/shared'
import { getDb } from '../db/schema.js'
import { hostedMaxFileSizeBytes, hostedSeatPriceCents, hostedStorageCapBytes } from '../config/hosted.js'
import {
  extractHostedSessionToken,
  issueHostedSession,
  normalizeHostedEmail,
  resolveHostedSession,
  revokeHostedSession,
} from '../security/hosted-sessions.js'

export const hostedAuthRouter: ReturnType<typeof Router> = Router()

interface CreateHostedSessionBody {
  email?: string
  displayName?: string
}

interface HostedAccountRow {
  id: string
  email_norm: string
  display_name: string | null
  status: string
}

interface HostedAccountSnapshotRow {
  id: string
  email_norm: string
  display_name: string | null
  status: string
  subscription_status: string | null
  price_cents: number | null
  storage_cap_bytes: number | null
  max_file_size_bytes: number | null
  current_period_end: string | null
  cancel_at_period_end: number | null
  owned_folder_count: number | null
  owned_storage_bytes: number | null
}

function deriveDisplayName(email: string, proposed?: string | null): string {
  const trimmed = proposed?.trim()
  if (trimmed) return trimmed
  return email.split('@')[0] || email
}

function resolveSessionActor(req: Request, res: Response) {
  const db = getDb()
  const sessionToken = extractHostedSessionToken(req)
  if (!sessionToken) {
    res.status(401).json({
      error: 'Hosted session token required',
      code: 'hosted_session_required',
    })
    return null
  }

  const actor = resolveHostedSession(db, sessionToken)
  if (!actor) {
    res.status(401).json({
      error: 'Hosted session is invalid or expired',
      code: 'hosted_session_required',
    })
    return null
  }

  return actor
}

/** POST /api/hosted/auth/session — create or refresh hosted account session by email identity. */
hostedAuthRouter.post(
  '/session',
  (
    req: Request<Record<string, never>, unknown, CreateHostedSessionBody>,
    res: Response<HostedSessionResponse | { error: string }>
  ) => {
  const email = normalizeHostedEmail(req.body.email || '')
  if (!email) {
    res.status(400).json({ error: 'Valid email is required' })
    return
  }

  const db = getDb()
  const requestedDisplayName = req.body.displayName?.trim() || null

  let account = db
    .prepare(
      `
      SELECT id, email_norm, display_name, status
      FROM hosted_accounts
      WHERE email_norm = ?
      LIMIT 1
    `
    )
    .get(email) as HostedAccountRow | undefined

  if (!account) {
    const id = crypto.randomUUID()
    db.prepare(
      `
      INSERT INTO hosted_accounts (id, email_norm, display_name, status, created_at, updated_at)
      VALUES (?, ?, ?, 'active', datetime('now'), datetime('now'))
    `
    ).run(id, email, deriveDisplayName(email, requestedDisplayName))

    account = db
      .prepare(
        `
        SELECT id, email_norm, display_name, status
        FROM hosted_accounts
        WHERE id = ?
        LIMIT 1
      `
      )
      .get(id) as HostedAccountRow | undefined
  } else if (requestedDisplayName) {
    db.prepare(
      `
      UPDATE hosted_accounts
      SET display_name = ?,
          updated_at = datetime('now')
      WHERE id = ?
    `
    ).run(requestedDisplayName, account.id)

    account.display_name = requestedDisplayName
  }

  if (!account) {
    res.status(500).json({ error: 'Failed to resolve hosted account' })
    return
  }

  const issued = issueHostedSession(db, account.id)

  res.json({
    account: {
      id: account.id,
      email: account.email_norm,
      displayName: account.display_name || deriveDisplayName(account.email_norm, null),
      status: account.status,
    },
    sessionToken: issued.sessionToken,
    expiresAt: issued.expiresAt,
  })
  }
)

/** GET /api/hosted/auth/me — resolve hosted session identity and account billing snapshot. */
hostedAuthRouter.get('/me', (req: Request, res: Response<HostedAuthMeResponse | { error: string }>) => {
  const actor = resolveSessionActor(req, res)
  if (!actor) return

  const db = getDb()
  const row = db
    .prepare(
      `
      SELECT
        a.id,
        a.email_norm,
        a.display_name,
        a.status,
        b.subscription_status,
        b.price_cents,
        b.storage_cap_bytes,
        b.max_file_size_bytes,
        b.current_period_end,
        b.cancel_at_period_end,
        u.owned_folder_count,
        u.owned_storage_bytes
      FROM hosted_accounts a
      LEFT JOIN hosted_account_billing b ON b.account_id = a.id
      LEFT JOIN hosted_account_usage u ON u.account_id = a.id
      WHERE a.id = ?
      LIMIT 1
    `
    )
    .get(actor.accountId) as HostedAccountSnapshotRow | undefined

  if (!row) {
    res.status(404).json({ error: 'Hosted account not found' })
    return
  }

  res.json({
    account: {
      id: row.id,
      email: row.email_norm,
      displayName: row.display_name || deriveDisplayName(row.email_norm, null),
      status: row.status,
      expiresAt: actor.expiresAt,
    },
    billing: {
      subscriptionStatus: (row.subscription_status || 'inactive').trim() || 'inactive',
      priceCents: Math.max(0, Number(row.price_cents ?? hostedSeatPriceCents())),
      storageCapBytes: Math.max(1, Number(row.storage_cap_bytes ?? hostedStorageCapBytes())),
      maxFileSizeBytes: Math.max(1, Number(row.max_file_size_bytes ?? hostedMaxFileSizeBytes())),
      currentPeriodEnd: row.current_period_end || null,
      cancelAtPeriodEnd: Boolean(row.cancel_at_period_end),
    },
    usage: {
      ownedFolderCount: Math.max(0, Number(row.owned_folder_count ?? 0)),
      ownedStorageBytes: Math.max(0, Number(row.owned_storage_bytes ?? 0)),
    },
  })
})

/** DELETE /api/hosted/auth/session — revoke the current hosted session token. */
hostedAuthRouter.delete('/session', (req: Request, res: Response) => {
  const sessionToken = extractHostedSessionToken(req)
  if (!sessionToken) {
    res.status(400).json({ error: 'Hosted session token required' })
    return
  }

  revokeHostedSession(getDb(), sessionToken)
  res.json({ success: true })
})
