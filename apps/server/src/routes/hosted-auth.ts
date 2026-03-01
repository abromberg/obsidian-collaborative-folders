/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import { Router, type Request, type Response } from 'express'
import crypto from 'crypto'
import type { HostedAuthMeResponse, HostedOtpStartResponse, HostedSessionResponse } from '@obsidian-teams/shared'
import { getDb } from '../db/schema.js'
import {
  hostedMaxFileSizeBytes,
  hostedSeatPriceCents,
  hostedStorageCapBytes,
  hostedSupabaseAuthKey,
  hostedSupabaseUrl,
} from '../config/hosted.js'
import {
  extractHostedSessionToken,
  issueHostedSession,
  normalizeHostedEmail,
  resolveHostedSession,
  revokeHostedSession,
} from '../security/hosted-sessions.js'

export const hostedAuthRouter: ReturnType<typeof Router> = Router()

interface HostedErrorResponse {
  error: string
  code?: string
}

interface HostedOtpStartBody {
  email?: string
}

interface HostedOtpVerifyBody {
  email?: string
  code?: string
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

interface SupabaseAuthResponse {
  status: number
  payload: unknown
}

function deriveDisplayName(email: string, proposed?: string | null): string {
  const trimmed = proposed?.trim()
  if (trimmed) return trimmed
  return email.split('@')[0] || email
}

function readSupabaseErrorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== 'object') return fallback
  const record = payload as Record<string, unknown>
  const descriptions = [record.error_description, record.msg, record.error]
  for (const value of descriptions) {
    if (typeof value === 'string' && value.trim()) return value
  }
  return fallback
}

function normalizeSupabaseAuthBase(url: string): string {
  return url.replace(/\/+$/, '')
}

function resolveSupabaseAuthConfig(
  res: Response
): { baseUrl: string; authKey: string } | null {
  const baseUrl = hostedSupabaseUrl()
  const authKey = hostedSupabaseAuthKey()
  if (!baseUrl || !authKey) {
    res.status(503).json({
      error: 'Hosted auth is not configured',
      code: 'hosted_auth_unavailable',
    })
    return null
  }
  return {
    baseUrl: normalizeSupabaseAuthBase(baseUrl),
    authKey,
  }
}

async function postSupabaseAuth(
  baseUrl: string,
  authKey: string,
  path: '/auth/v1/otp' | '/auth/v1/verify',
  payload: Record<string, unknown>
): Promise<SupabaseAuthResponse> {
  const response = await globalThis.fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      apikey: authKey,
      Authorization: `Bearer ${authKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })
  const parsed: unknown = await response.json().catch(() => null)
  return {
    status: response.status,
    payload: parsed,
  }
}

function upsertHostedAccountByEmail(
  email: string,
  requestedDisplayName: string | null
): HostedAccountRow | null {
  const db = getDb()

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
    const accountId = crypto.randomUUID()
    db.prepare(
      `
      INSERT INTO hosted_accounts (id, email_norm, display_name, status, created_at, updated_at)
      VALUES (?, ?, ?, 'active', datetime('now'), datetime('now'))
    `
    ).run(accountId, email, deriveDisplayName(email, requestedDisplayName))

    account = db
      .prepare(
        `
        SELECT id, email_norm, display_name, status
        FROM hosted_accounts
        WHERE id = ?
        LIMIT 1
      `
      )
      .get(accountId) as HostedAccountRow | undefined
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

  return account || null
}

function resolveSessionActor(req: Request, res: Response<HostedAuthMeResponse | HostedErrorResponse>) {
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

/** POST /api/hosted/auth/otp/start — send a Supabase email OTP code. */
export async function handleHostedOtpStart(
  req: Request<Record<string, never>, unknown, HostedOtpStartBody>,
  res: Response<HostedOtpStartResponse | HostedErrorResponse>
): Promise<void> {
  const email = normalizeHostedEmail(req.body.email || '')
  if (!email) {
    res.status(400).json({ error: 'Valid email is required' })
    return
  }

  const supabase = resolveSupabaseAuthConfig(res)
  if (!supabase) return

  const otpStart = await postSupabaseAuth(supabase.baseUrl, supabase.authKey, '/auth/v1/otp', {
    email,
    create_user: true,
    should_create_user: true,
  })

  if (otpStart.status < 200 || otpStart.status >= 300) {
    const message = readSupabaseErrorMessage(otpStart.payload, 'Failed to send verification code')
    res.status(502).json({ error: message, code: 'hosted_otp_start_failed' })
    return
  }

  res.json({ success: true })
}

hostedAuthRouter.post(
  '/otp/start',
  (
    req: Request<Record<string, never>, unknown, HostedOtpStartBody>,
    res: Response<HostedOtpStartResponse | HostedErrorResponse>
  ) => {
    void handleHostedOtpStart(req, res).catch((error: unknown) => {
      const message = error instanceof Error && error.message ? error.message : 'Failed to start hosted OTP flow'
      res.status(500).json({ error: message })
    })
  }
)

/** POST /api/hosted/auth/otp/verify — verify Supabase OTP code and issue hosted session. */
export async function handleHostedOtpVerify(
  req: Request<Record<string, never>, unknown, HostedOtpVerifyBody>,
  res: Response<HostedSessionResponse | HostedErrorResponse>
): Promise<void> {
  const email = normalizeHostedEmail(req.body.email || '')
  const code = (req.body.code || '').trim()
  if (!email) {
    res.status(400).json({ error: 'Valid email is required' })
    return
  }
  if (!code) {
    res.status(400).json({ error: 'Verification code is required' })
    return
  }

  const supabase = resolveSupabaseAuthConfig(res)
  if (!supabase) return

  const verification = await postSupabaseAuth(supabase.baseUrl, supabase.authKey, '/auth/v1/verify', {
    type: 'email',
    email,
    token: code,
  })

  if (verification.status < 200 || verification.status >= 300) {
    const message = readSupabaseErrorMessage(verification.payload, 'Failed to verify code')
    const isInvalidCode = verification.status === 400 || verification.status === 401 || verification.status === 422
    if (isInvalidCode) {
      res.status(401).json({ error: message, code: 'hosted_otp_invalid' })
      return
    }
    res.status(502).json({ error: message, code: 'hosted_otp_verify_failed' })
    return
  }

  const verifiedEmail = normalizeHostedEmail(
    (
      verification.payload as {
        user?: {
          email?: string
        }
      }
    ).user?.email || ''
  )

  if (!verifiedEmail) {
    res.status(502).json({ error: 'Hosted auth provider response missing verified user email' })
    return
  }

  const requestedDisplayName = req.body.displayName?.trim() || null
  const account = upsertHostedAccountByEmail(verifiedEmail, requestedDisplayName)
  if (!account) {
    res.status(500).json({ error: 'Failed to resolve hosted account' })
    return
  }

  const issued = issueHostedSession(getDb(), account.id)
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

hostedAuthRouter.post(
  '/otp/verify',
  (
    req: Request<Record<string, never>, unknown, HostedOtpVerifyBody>,
    res: Response<HostedSessionResponse | HostedErrorResponse>
  ) => {
    void handleHostedOtpVerify(req, res).catch((error: unknown) => {
      const message = error instanceof Error && error.message ? error.message : 'Failed to verify hosted OTP code'
      res.status(500).json({ error: message })
    })
  }
)

/** GET /api/hosted/auth/me — resolve hosted session identity and account billing snapshot. */
hostedAuthRouter.get('/me', (req: Request, res: Response<HostedAuthMeResponse | HostedErrorResponse>) => {
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
hostedAuthRouter.delete('/session', (req: Request, res: Response<HostedErrorResponse | { success: true }>) => {
  const sessionToken = extractHostedSessionToken(req)
  if (!sessionToken) {
    res.status(400).json({ error: 'Hosted session token required' })
    return
  }

  revokeHostedSession(getDb(), sessionToken)
  res.json({ success: true })
})
