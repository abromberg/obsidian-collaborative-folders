import type Database from 'better-sqlite3'
import type { HostedEntitlementCode } from '@obsidian-teams/shared'
import {
  hostedMaxFileSizeBytes,
  hostedSeatPriceCents,
  hostedStorageCapBytes,
  isHostedModeEnabled,
} from '../config/hosted.js'

const COLLABORATION_ALLOWED_STATUSES = new Set(['active', 'trialing'])

interface FolderOwnerRow {
  owner_account_id: string | null
}

interface AccountEntitlementRow {
  account_id: string
  subscription_status: string | null
  price_cents: number | null
  storage_cap_bytes: number | null
  max_file_size_bytes: number | null
  owned_folder_count: number | null
  owned_storage_bytes: number | null
}

export interface EntitlementViolation {
  status: number
  code: HostedEntitlementCode
  error: string
}

export interface AccountEntitlements {
  accountId: string
  subscriptionStatus: string
  priceCents: number
  storageCapBytes: number
  maxFileSizeBytes: number
  ownedFolderCount: number
  ownedStorageBytes: number
}

function normalizeSubscriptionStatus(value: string | null | undefined): string {
  const normalized = (value || '').trim().toLowerCase()
  return normalized || 'inactive'
}

function collaborationStatusViolation(status: string, target: string): EntitlementViolation {
  if (status === 'past_due') {
    return {
      status: 402,
      code: 'subscription_past_due',
      error: `Subscription is past due for ${target}`,
    }
  }

  return {
    status: 402,
    code: 'subscription_inactive',
    error: `Subscription is not active for ${target}`,
  }
}

export function isHostedEntitlementsEnabled(): boolean {
  return isHostedModeEnabled()
}

export function getFolderOwnerAccountId(db: Database.Database, folderId: string): string | null {
  const row = db
    .prepare('SELECT owner_account_id FROM folders WHERE id = ?')
    .get(folderId) as FolderOwnerRow | undefined
  return row?.owner_account_id || null
}

export function recomputeAccountUsage(
  db: Database.Database,
  accountId: string
): { ownedFolderCount: number; ownedStorageBytes: number } {
  const usageRow = db
    .prepare(
      `
      SELECT
        (
          SELECT COUNT(*)
          FROM folders f
          WHERE f.owner_account_id = ?
        ) AS owned_folder_count,
        (
          SELECT COALESCE(SUM(b.size_bytes), 0)
          FROM folders f
          LEFT JOIN encrypted_blobs b ON b.folder_id = f.id
          WHERE f.owner_account_id = ?
        ) AS owned_storage_bytes
    `
    )
    .get(accountId, accountId) as
    | {
        owned_folder_count: number
        owned_storage_bytes: number
      }
    | undefined

  const ownedFolderCount = Math.max(0, Number(usageRow?.owned_folder_count ?? 0))
  const ownedStorageBytes = Math.max(0, Number(usageRow?.owned_storage_bytes ?? 0))

  db.prepare(
    `
    INSERT INTO hosted_account_usage (
      account_id,
      owned_folder_count,
      owned_storage_bytes,
      updated_at
    ) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(account_id) DO UPDATE SET
      owned_folder_count = excluded.owned_folder_count,
      owned_storage_bytes = excluded.owned_storage_bytes,
      updated_at = datetime('now')
  `
  ).run(accountId, ownedFolderCount, ownedStorageBytes)

  return { ownedFolderCount, ownedStorageBytes }
}

export function getAccountEntitlements(
  db: Database.Database,
  accountId: string
): AccountEntitlements | null {
  const row = db
    .prepare(
      `
      SELECT
        a.id AS account_id,
        b.subscription_status,
        b.price_cents,
        b.storage_cap_bytes,
        b.max_file_size_bytes,
        u.owned_folder_count,
        u.owned_storage_bytes
      FROM hosted_accounts a
      LEFT JOIN hosted_account_billing b ON b.account_id = a.id
      LEFT JOIN hosted_account_usage u ON u.account_id = a.id
      WHERE a.id = ?
      LIMIT 1
    `
    )
    .get(accountId) as AccountEntitlementRow | undefined

  if (!row) return null

  return {
    accountId: row.account_id,
    subscriptionStatus: normalizeSubscriptionStatus(row.subscription_status),
    priceCents: Math.max(0, Number(row.price_cents ?? hostedSeatPriceCents())),
    storageCapBytes: Math.max(1, Number(row.storage_cap_bytes ?? hostedStorageCapBytes())),
    maxFileSizeBytes: Math.max(1, Number(row.max_file_size_bytes ?? hostedMaxFileSizeBytes())),
    ownedFolderCount: Math.max(0, Number(row.owned_folder_count ?? 0)),
    ownedStorageBytes: Math.max(0, Number(row.owned_storage_bytes ?? 0)),
  }
}

export function validateInviteCreateEntitlement(
  db: Database.Database,
  ownerAccountId: string
): EntitlementViolation | null {
  const entitlements = getAccountEntitlements(db, ownerAccountId)
  if (!entitlements) {
    return {
      status: 404,
      code: 'subscription_inactive',
      error: 'Hosted account not found',
    }
  }

  if (!COLLABORATION_ALLOWED_STATUSES.has(entitlements.subscriptionStatus)) {
    return collaborationStatusViolation(entitlements.subscriptionStatus, 'hosted collaboration')
  }

  return null
}

export function validateInviteRedeemEntitlement(
  db: Database.Database,
  accountId: string
): EntitlementViolation | null {
  const entitlements = getAccountEntitlements(db, accountId)
  if (!entitlements) {
    return {
      status: 404,
      code: 'subscription_inactive',
      error: 'Hosted account not found',
    }
  }

  if (!COLLABORATION_ALLOWED_STATUSES.has(entitlements.subscriptionStatus)) {
    return collaborationStatusViolation(entitlements.subscriptionStatus, 'invite redemption')
  }

  return null
}

export function validateBlobUploadEntitlement(
  db: Database.Database,
  ownerAccountId: string,
  incomingBytes: number
): EntitlementViolation | null {
  const entitlements = getAccountEntitlements(db, ownerAccountId)
  if (!entitlements) {
    return {
      status: 404,
      code: 'subscription_inactive',
      error: 'Hosted account not found',
    }
  }

  if (!COLLABORATION_ALLOWED_STATUSES.has(entitlements.subscriptionStatus)) {
    return collaborationStatusViolation(entitlements.subscriptionStatus, 'uploads')
  }

  if (incomingBytes > entitlements.maxFileSizeBytes) {
    return {
      status: 413,
      code: 'file_size_limit_exceeded',
      error: `File exceeds hosted max file size of ${entitlements.maxFileSizeBytes} bytes`,
    }
  }

  const usage = recomputeAccountUsage(db, ownerAccountId)
  if (usage.ownedStorageBytes + incomingBytes > entitlements.storageCapBytes) {
    return {
      status: 409,
      code: 'storage_limit_reached',
      error: 'Hosted owner storage cap exceeded',
    }
  }

  return null
}
