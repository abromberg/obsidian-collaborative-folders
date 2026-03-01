/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import Database from 'better-sqlite3'
import path from 'path'
import fs from 'fs'
import { hostedMaxFileSizeBytes, hostedSeatPriceCents, hostedStorageCapBytes } from '../config/hosted.js'

const DB_PATH = process.env.DB_PATH || './data/obsidian-teams.sqlite'

const LEGACY_HOSTED_SEGMENT = 'hosted'
const LEGACY_SCOPE_SEGMENT = 'workspace'
const LEGACY_SCOPE_PREFIX = `${LEGACY_HOSTED_SEGMENT}_${LEGACY_SCOPE_SEGMENT}`
const LEGACY_SCOPE_ID_COLUMN = `${LEGACY_SCOPE_SEGMENT}_id`
const LEGACY_TABLES = {
  root: `${LEGACY_SCOPE_PREFIX}s`,
  members: `${LEGACY_SCOPE_PREFIX}_members`,
  billing: `${LEGACY_SCOPE_PREFIX}_billing`,
  usage: `${LEGACY_SCOPE_PREFIX}_usage`,
}

let db: Database.Database

interface TableInfoRow {
  name: string
}

interface LegacyOwnerCountRow {
  account_id: string | null
  link_count: number
}

interface LegacyFolderOwnerGapRow {
  folder_id: string
}

interface LegacyBillingRow {
  account_id: string
  stripe_customer_id: string | null
  stripe_subscription_id: string | null
  stripe_subscription_item_id: string | null
  subscription_status: string | null
  price_cents: number | null
  storage_cap_bytes: number | null
  max_file_size_bytes: number | null
  current_period_end: string | null
  cancel_at_period_end: number | null
}

function quoteIdent(value: string): string {
  return `"${value.replaceAll('"', '""')}"`
}

function tableExists(db: Database.Database, table: string): boolean {
  const row = db
    .prepare(
      `
      SELECT name
      FROM sqlite_master
      WHERE type = 'table' AND name = ?
      LIMIT 1
    `
    )
    .get(table) as { name: string } | undefined
  return Boolean(row?.name)
}

function getTableColumns(db: Database.Database, table: string): Set<string> {
  if (!tableExists(db, table)) return new Set()
  const rows = db.prepare(`PRAGMA table_info(${quoteIdent(table)})`).all() as TableInfoRow[]
  return new Set(rows.map((row) => row.name))
}

function columnExists(db: Database.Database, table: string, column: string): boolean {
  return getTableColumns(db, table).has(column)
}

function addColumnIfMissing(
  db: Database.Database,
  table: string,
  column: string,
  definition: string
): void {
  if (!tableExists(db, table)) return
  if (columnExists(db, table, column)) return
  db.exec(`ALTER TABLE ${quoteIdent(table)} ADD COLUMN ${quoteIdent(column)} ${definition};`)
}

function runLegacyOwnerMappingPreflight(db: Database.Database): void {
  if (!tableExists(db, LEGACY_TABLES.root) || !tableExists(db, LEGACY_TABLES.billing)) return

  const ownerDuplicates = db
    .prepare(
      `
      SELECT w.owner_account_id AS account_id, COUNT(*) AS link_count
      FROM ${quoteIdent(LEGACY_TABLES.root)} w
      JOIN ${quoteIdent(LEGACY_TABLES.billing)} b ON b.${quoteIdent(LEGACY_SCOPE_ID_COLUMN)} = w.id
      GROUP BY w.owner_account_id
      HAVING COUNT(*) > 1
    `
    )
    .all() as LegacyOwnerCountRow[]

  if (ownerDuplicates.length > 0) {
    const offenders = ownerDuplicates.map((row) => row.account_id || 'null').join(', ')
    throw new Error(
      `[db:migration] blocked: ambiguous legacy billing owner mappings detected (${offenders})`
    )
  }

  if (!tableExists(db, 'folders') || !columnExists(db, 'folders', LEGACY_SCOPE_ID_COLUMN)) return

  const unmappedFolders = db
    .prepare(
      `
      SELECT f.id AS folder_id
      FROM folders f
      LEFT JOIN ${quoteIdent(LEGACY_TABLES.root)} w ON w.id = f.${quoteIdent(LEGACY_SCOPE_ID_COLUMN)}
      WHERE f.${quoteIdent(LEGACY_SCOPE_ID_COLUMN)} IS NOT NULL
        AND w.owner_account_id IS NULL
      LIMIT 20
    `
    )
    .all() as LegacyFolderOwnerGapRow[]

  if (unmappedFolders.length > 0) {
    const ids = unmappedFolders.map((row) => row.folder_id).join(', ')
    throw new Error(`[db:migration] blocked: legacy folder owner mappings missing for folders (${ids})`)
  }
}

function backfillFolderOwners(db: Database.Database): void {
  if (!tableExists(db, 'folders') || !columnExists(db, 'folders', 'owner_account_id')) return

  if (tableExists(db, LEGACY_TABLES.root) && columnExists(db, 'folders', LEGACY_SCOPE_ID_COLUMN)) {
    db.exec(`
      UPDATE folders
      SET owner_account_id = (
            SELECT w.owner_account_id
            FROM ${quoteIdent(LEGACY_TABLES.root)} w
            WHERE w.id = folders.${quoteIdent(LEGACY_SCOPE_ID_COLUMN)}
          )
      WHERE owner_account_id IS NULL
        AND ${quoteIdent(LEGACY_SCOPE_ID_COLUMN)} IS NOT NULL;
    `)
  }

  db.exec(`
    UPDATE folders
    SET owner_account_id = (
          SELECT m.account_id
          FROM members m
          WHERE m.folder_id = folders.id
            AND m.role = 'owner'
            AND m.account_id IS NOT NULL
          ORDER BY datetime(m.joined_at) ASC
          LIMIT 1
        )
    WHERE owner_account_id IS NULL;
  `)
}

function upsertLegacyBillingByOwner(
  db: Database.Database,
  defaultPriceCents: number,
  defaultStorageCap: number,
  defaultMaxFileSize: number
): void {
  if (!tableExists(db, LEGACY_TABLES.root) || !tableExists(db, LEGACY_TABLES.billing)) return

  const legacyRows = db
    .prepare(
      `
      SELECT
        w.owner_account_id AS account_id,
        b.stripe_customer_id,
        b.stripe_subscription_id,
        b.stripe_subscription_item_id,
        b.subscription_status,
        COALESCE(b.seat_price_cents, ?) AS price_cents,
        COALESCE(b.storage_cap_bytes, ?) AS storage_cap_bytes,
        COALESCE(b.max_file_size_bytes, ?) AS max_file_size_bytes,
        b.current_period_end,
        COALESCE(b.cancel_at_period_end, 0) AS cancel_at_period_end
      FROM ${quoteIdent(LEGACY_TABLES.billing)} b
      JOIN ${quoteIdent(LEGACY_TABLES.root)} w ON w.id = b.${quoteIdent(LEGACY_SCOPE_ID_COLUMN)}
      WHERE w.owner_account_id IS NOT NULL
    `
    )
    .all(defaultPriceCents, defaultStorageCap, defaultMaxFileSize) as LegacyBillingRow[]

  const upsert = db.prepare(`
    INSERT INTO hosted_account_billing (
      account_id,
      stripe_customer_id,
      stripe_subscription_id,
      stripe_subscription_item_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      current_period_end,
      cancel_at_period_end,
      updated_at
    ) VALUES (
      @account_id,
      @stripe_customer_id,
      @stripe_subscription_id,
      @stripe_subscription_item_id,
      @subscription_status,
      @price_cents,
      @storage_cap_bytes,
      @max_file_size_bytes,
      @current_period_end,
      @cancel_at_period_end,
      datetime('now')
    )
    ON CONFLICT(account_id) DO UPDATE SET
      stripe_customer_id = COALESCE(excluded.stripe_customer_id, hosted_account_billing.stripe_customer_id),
      stripe_subscription_id = COALESCE(excluded.stripe_subscription_id, hosted_account_billing.stripe_subscription_id),
      stripe_subscription_item_id = COALESCE(excluded.stripe_subscription_item_id, hosted_account_billing.stripe_subscription_item_id),
      subscription_status = COALESCE(NULLIF(TRIM(excluded.subscription_status), ''), hosted_account_billing.subscription_status),
      price_cents = COALESCE(excluded.price_cents, hosted_account_billing.price_cents),
      storage_cap_bytes = COALESCE(excluded.storage_cap_bytes, hosted_account_billing.storage_cap_bytes),
      max_file_size_bytes = COALESCE(excluded.max_file_size_bytes, hosted_account_billing.max_file_size_bytes),
      current_period_end = COALESCE(excluded.current_period_end, hosted_account_billing.current_period_end),
      cancel_at_period_end = COALESCE(excluded.cancel_at_period_end, hosted_account_billing.cancel_at_period_end),
      updated_at = datetime('now')
  `)

  for (const row of legacyRows) {
    upsert.run({
      account_id: row.account_id,
      stripe_customer_id: row.stripe_customer_id,
      stripe_subscription_id: row.stripe_subscription_id,
      stripe_subscription_item_id: row.stripe_subscription_item_id,
      subscription_status: row.subscription_status || 'inactive',
      price_cents: row.price_cents ?? defaultPriceCents,
      storage_cap_bytes: row.storage_cap_bytes ?? defaultStorageCap,
      max_file_size_bytes: row.max_file_size_bytes ?? defaultMaxFileSize,
      current_period_end: row.current_period_end,
      cancel_at_period_end: row.cancel_at_period_end ?? 0,
    })
  }
}

function ensureBillingRowsForAllAccounts(
  db: Database.Database,
  defaultPriceCents: number,
  defaultStorageCap: number,
  defaultMaxFileSize: number
): void {
  db.prepare(
    `
    INSERT INTO hosted_account_billing (
      account_id,
      subscription_status,
      price_cents,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    )
    SELECT a.id, 'inactive', ?, ?, ?, datetime('now')
    FROM hosted_accounts a
    WHERE NOT EXISTS (
      SELECT 1
      FROM hosted_account_billing b
      WHERE b.account_id = a.id
    )
  `
  ).run(defaultPriceCents, defaultStorageCap, defaultMaxFileSize)

  db.exec(`
    UPDATE hosted_account_billing
    SET subscription_status = COALESCE(NULLIF(TRIM(subscription_status), ''), 'inactive'),
        price_cents = COALESCE(price_cents, ${defaultPriceCents}),
        storage_cap_bytes = COALESCE(storage_cap_bytes, ${defaultStorageCap}),
        max_file_size_bytes = COALESCE(max_file_size_bytes, ${defaultMaxFileSize}),
        cancel_at_period_end = COALESCE(cancel_at_period_end, 0),
        updated_at = COALESCE(updated_at, datetime('now'));
  `)
}

function backfillBillingEventsAccountLink(db: Database.Database): void {
  if (!tableExists(db, 'hosted_billing_events') || !columnExists(db, 'hosted_billing_events', 'account_id')) {
    return
  }

  if (tableExists(db, LEGACY_TABLES.root) && columnExists(db, 'hosted_billing_events', LEGACY_SCOPE_ID_COLUMN)) {
    db.exec(`
      UPDATE hosted_billing_events
      SET account_id = COALESCE(
            account_id,
            (
              SELECT w.owner_account_id
              FROM ${quoteIdent(LEGACY_TABLES.root)} w
              WHERE w.id = hosted_billing_events.${quoteIdent(LEGACY_SCOPE_ID_COLUMN)}
            )
          )
      WHERE account_id IS NULL;
    `)
  }
}

function recomputeAllAccountUsage(db: Database.Database): void {
  db.exec(`
    INSERT INTO hosted_account_usage (
      account_id,
      owned_folder_count,
      owned_storage_bytes,
      updated_at
    )
    SELECT
      a.id,
      COALESCE(folder_counts.owned_folder_count, 0),
      COALESCE(storage_totals.owned_storage_bytes, 0),
      datetime('now')
    FROM hosted_accounts a
    LEFT JOIN (
      SELECT owner_account_id AS account_id, COUNT(*) AS owned_folder_count
      FROM folders
      WHERE owner_account_id IS NOT NULL
      GROUP BY owner_account_id
    ) AS folder_counts ON folder_counts.account_id = a.id
    LEFT JOIN (
      SELECT f.owner_account_id AS account_id, COALESCE(SUM(b.size_bytes), 0) AS owned_storage_bytes
      FROM folders f
      LEFT JOIN encrypted_blobs b ON b.folder_id = f.id
      WHERE f.owner_account_id IS NOT NULL
      GROUP BY f.owner_account_id
    ) AS storage_totals ON storage_totals.account_id = a.id
    ON CONFLICT(account_id) DO UPDATE SET
      owned_folder_count = excluded.owned_folder_count,
      owned_storage_bytes = excluded.owned_storage_bytes,
      updated_at = datetime('now');
  `)
}

function rebuildHostedBillingEventsWithoutLegacyScopeLink(db: Database.Database): void {
  if (!tableExists(db, 'hosted_billing_events')) return
  if (!columnExists(db, 'hosted_billing_events', LEGACY_SCOPE_ID_COLUMN)) return

  const hasAccountIdColumn = columnExists(db, 'hosted_billing_events', 'account_id')
  const accountIdSelect = hasAccountIdColumn ? 'account_id' : 'NULL AS account_id'

  db.pragma('foreign_keys = OFF')
  db.exec(`
    CREATE TABLE hosted_billing_events_next (
      stripe_event_id TEXT PRIMARY KEY,
      account_id TEXT REFERENCES hosted_accounts(id) ON DELETE SET NULL,
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      received_at TEXT NOT NULL DEFAULT (datetime('now')),
      processed_at TEXT,
      processing_error TEXT
    );

    INSERT INTO hosted_billing_events_next (
      stripe_event_id,
      account_id,
      event_type,
      payload_json,
      received_at,
      processed_at,
      processing_error
    )
    SELECT
      stripe_event_id,
      ${accountIdSelect},
      event_type,
      payload_json,
      received_at,
      processed_at,
      processing_error
    FROM hosted_billing_events;

    DROP TABLE hosted_billing_events;
    ALTER TABLE hosted_billing_events_next RENAME TO hosted_billing_events;
  `)
  db.pragma('foreign_keys = ON')

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_hosted_billing_events_account
      ON hosted_billing_events (account_id, received_at DESC);
  `)
}

function rebuildFoldersWithoutLegacyScopeLink(db: Database.Database): void {
  if (!tableExists(db, 'folders')) return
  if (!columnExists(db, 'folders', LEGACY_SCOPE_ID_COLUMN)) return

  db.pragma('foreign_keys = OFF')
  db.exec(`
    CREATE TABLE folders_next (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_client_id TEXT NOT NULL,
      owner_account_id TEXT REFERENCES hosted_accounts(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    INSERT INTO folders_next (id, name, owner_client_id, owner_account_id, created_at)
    SELECT id, name, owner_client_id, owner_account_id, created_at
    FROM folders;

    DROP TABLE folders;
    ALTER TABLE folders_next RENAME TO folders;
  `)
  db.pragma('foreign_keys = ON')

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_hosted_billing_events_account
      ON hosted_billing_events (account_id, received_at DESC);

    CREATE INDEX IF NOT EXISTS idx_folders_owner_account
      ON folders (owner_account_id);
  `)
}

function dropLegacyTables(db: Database.Database): void {
  db.exec(`
    DROP TABLE IF EXISTS ${quoteIdent(LEGACY_TABLES.members)};
    DROP TABLE IF EXISTS ${quoteIdent(LEGACY_TABLES.usage)};
    DROP TABLE IF EXISTS ${quoteIdent(LEGACY_TABLES.billing)};
    DROP TABLE IF EXISTS ${quoteIdent(LEGACY_TABLES.root)};
  `)
}

export function getDb(): Database.Database {
  if (!db) {
    const dir = path.dirname(DB_PATH)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
    db = new Database(DB_PATH)
    db.pragma('journal_mode = WAL')
    db.pragma('foreign_keys = ON')
  }
  return db
}

export function initDb(): void {
  const db = getDb()
  const defaultPriceCents = hostedSeatPriceCents()
  const defaultStorageCap = hostedStorageCapBytes()
  const defaultMaxFileSize = hostedMaxFileSizeBytes()

  db.exec(`
    CREATE TABLE IF NOT EXISTS hosted_accounts (
      id TEXT PRIMARY KEY,
      email_norm TEXT NOT NULL UNIQUE,
      display_name TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_hosted_accounts_email
      ON hosted_accounts (email_norm);

    CREATE TABLE IF NOT EXISTS hosted_account_sessions (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES hosted_accounts(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_hosted_account_sessions_account
      ON hosted_account_sessions (account_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_hosted_account_sessions_token
      ON hosted_account_sessions (token_hash);

    CREATE TABLE IF NOT EXISTS hosted_account_billing (
      account_id TEXT PRIMARY KEY REFERENCES hosted_accounts(id) ON DELETE CASCADE,
      stripe_customer_id TEXT UNIQUE,
      stripe_subscription_id TEXT UNIQUE,
      stripe_subscription_item_id TEXT,
      subscription_status TEXT NOT NULL DEFAULT 'inactive',
      price_cents INTEGER NOT NULL DEFAULT 900,
      storage_cap_bytes INTEGER NOT NULL DEFAULT 3221225472,
      max_file_size_bytes INTEGER NOT NULL DEFAULT 26214400,
      current_period_end TEXT,
      cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_hosted_account_billing_customer
      ON hosted_account_billing (stripe_customer_id);
    CREATE INDEX IF NOT EXISTS idx_hosted_account_billing_subscription
      ON hosted_account_billing (stripe_subscription_id);

    CREATE TABLE IF NOT EXISTS hosted_account_usage (
      account_id TEXT PRIMARY KEY REFERENCES hosted_accounts(id) ON DELETE CASCADE,
      owned_folder_count INTEGER NOT NULL DEFAULT 0,
      owned_storage_bytes INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS hosted_billing_events (
      stripe_event_id TEXT PRIMARY KEY,
      account_id TEXT REFERENCES hosted_accounts(id) ON DELETE SET NULL,
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      received_at TEXT NOT NULL DEFAULT (datetime('now')),
      processed_at TEXT,
      processing_error TEXT
    );

    CREATE TABLE IF NOT EXISTS folders (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_client_id TEXT NOT NULL,
      owner_account_id TEXT REFERENCES hosted_accounts(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS members (
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      client_id TEXT NOT NULL,
      account_id TEXT,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('owner', 'editor')),
      token_version INTEGER NOT NULL DEFAULT 0,
      joined_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (folder_id, client_id)
    );

    CREATE TABLE IF NOT EXISTS invites (
      token_hash TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('editor')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      consumed_at TEXT,
      consumed_by TEXT,
      created_by TEXT,
      invitee_label TEXT,
      expires_at TEXT,
      max_uses INTEGER NOT NULL DEFAULT 1,
      use_count INTEGER NOT NULL DEFAULT 0,
      revoked_at TEXT,
      revoked_by TEXT
    );

    CREATE TABLE IF NOT EXISTS file_share_links (
      token_hash TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      file_id TEXT,
      relative_path TEXT NOT NULL,
      file_name TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      revoked_at TEXT,
      revoked_by TEXT,
      open_count INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_file_share_links_folder_created
      ON file_share_links (folder_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_file_share_links_expires
      ON file_share_links (expires_at);

    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL,
      client_id TEXT NOT NULL,
      revoked_at TEXT NOT NULL DEFAULT (datetime('now')),
      reason TEXT,
      expires_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_revoked_tokens_folder_client
      ON revoked_tokens (folder_id, client_id);

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token_hash TEXT PRIMARY KEY,
      family_id TEXT NOT NULL,
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      client_id TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('owner', 'editor')),
      token_version INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at TEXT,
      expires_at TEXT NOT NULL,
      rotated_from_hash TEXT,
      revoked_at TEXT,
      revoked_reason TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
      ON refresh_tokens (family_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_member
      ON refresh_tokens (folder_id, client_id);

    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      folder_id TEXT,
      actor_client_id TEXT,
      event_type TEXT NOT NULL,
      target TEXT,
      metadata_json TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_audit_events_folder_created
      ON audit_events (folder_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_events_actor_created
      ON audit_events (actor_client_id, created_at);

    CREATE TABLE IF NOT EXISTS blob_access_log (
      id TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL,
      actor_client_id TEXT NOT NULL,
      hash TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_blob_access_folder_created
      ON blob_access_log (folder_id, created_at);

    CREATE TABLE IF NOT EXISTS client_identity_keys (
      client_id TEXT PRIMARY KEY,
      public_key TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'x25519-sealed-box',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS folder_key_epochs (
      id TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      epoch INTEGER NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
      activated_at TEXT NOT NULL DEFAULT (datetime('now')),
      retired_at TEXT,
      rotated_by TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (folder_id, epoch)
    );

    CREATE INDEX IF NOT EXISTS idx_folder_key_epochs_folder_epoch
      ON folder_key_epochs (folder_id, epoch);

    CREATE UNIQUE INDEX IF NOT EXISTS idx_folder_key_epochs_active
      ON folder_key_epochs (folder_id)
      WHERE status = 'active';

    CREATE TABLE IF NOT EXISTS folder_key_envelopes (
      id TEXT PRIMARY KEY,
      folder_key_epoch_id TEXT NOT NULL REFERENCES folder_key_epochs(id) ON DELETE CASCADE,
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      client_id TEXT NOT NULL,
      client_public_key TEXT NOT NULL,
      wrapped_key BLOB NOT NULL,
      wrap_algorithm TEXT NOT NULL DEFAULT 'x25519-sealed-box',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (folder_key_epoch_id, client_id)
    );

    CREATE INDEX IF NOT EXISTS idx_folder_key_envelopes_lookup
      ON folder_key_envelopes (folder_id, client_id);

    CREATE TABLE IF NOT EXISTS encrypted_doc_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      room_name TEXT NOT NULL,
      epoch INTEGER NOT NULL,
      nonce BLOB NOT NULL,
      ciphertext BLOB NOT NULL,
      aad BLOB,
      sender_client_id TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_encrypted_doc_events_room_id
      ON encrypted_doc_events (folder_id, room_name, id);

    CREATE TABLE IF NOT EXISTS encrypted_doc_snapshots (
      id TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      room_name TEXT NOT NULL,
      epoch INTEGER NOT NULL,
      nonce BLOB NOT NULL,
      ciphertext BLOB NOT NULL,
      aad BLOB,
      base_event_id INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (folder_id, room_name)
    );

    CREATE TABLE IF NOT EXISTS encrypted_blobs (
      id TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      blob_id TEXT NOT NULL,
      epoch INTEGER NOT NULL,
      size_bytes INTEGER NOT NULL,
      nonce BLOB NOT NULL,
      aad BLOB,
      digest_hex TEXT NOT NULL,
      storage_path TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (folder_id, blob_id, epoch)
    );

    CREATE INDEX IF NOT EXISTS idx_encrypted_blobs_lookup
      ON encrypted_blobs (folder_id, blob_id, epoch DESC);
  `)

  addColumnIfMissing(db, 'folders', 'owner_account_id', 'TEXT')
  addColumnIfMissing(db, 'members', 'token_version', 'INTEGER NOT NULL DEFAULT 0')
  addColumnIfMissing(db, 'members', 'account_id', 'TEXT')
  addColumnIfMissing(db, 'invites', 'created_by', 'TEXT')
  addColumnIfMissing(db, 'invites', 'invitee_label', 'TEXT')
  addColumnIfMissing(db, 'invites', 'expires_at', 'TEXT')
  addColumnIfMissing(db, 'invites', 'max_uses', 'INTEGER NOT NULL DEFAULT 1')
  addColumnIfMissing(db, 'invites', 'use_count', 'INTEGER NOT NULL DEFAULT 0')
  addColumnIfMissing(db, 'invites', 'revoked_at', 'TEXT')
  addColumnIfMissing(db, 'invites', 'revoked_by', 'TEXT')
  addColumnIfMissing(db, 'hosted_billing_events', 'account_id', 'TEXT')

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_folders_owner_account
      ON folders (owner_account_id);

    CREATE INDEX IF NOT EXISTS idx_members_account
      ON members (account_id);

    CREATE INDEX IF NOT EXISTS idx_members_folder_account
      ON members (folder_id, account_id);

    CREATE INDEX IF NOT EXISTS idx_file_share_links_folder_created
      ON file_share_links (folder_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_file_share_links_expires
      ON file_share_links (expires_at);

    UPDATE invites
    SET max_uses = COALESCE(max_uses, 1),
        use_count = COALESCE(use_count, CASE WHEN consumed_at IS NOT NULL THEN 1 ELSE 0 END)
    WHERE max_uses IS NULL OR use_count IS NULL;

    UPDATE invites
    SET expires_at = COALESCE(expires_at, datetime(created_at, '+7 days'))
    WHERE expires_at IS NULL;
  `)

  runLegacyOwnerMappingPreflight(db)
  backfillFolderOwners(db)
  upsertLegacyBillingByOwner(db, defaultPriceCents, defaultStorageCap, defaultMaxFileSize)
  ensureBillingRowsForAllAccounts(db, defaultPriceCents, defaultStorageCap, defaultMaxFileSize)
  backfillBillingEventsAccountLink(db)
  recomputeAllAccountUsage(db)

  rebuildHostedBillingEventsWithoutLegacyScopeLink(db)
  rebuildFoldersWithoutLegacyScopeLink(db)
  dropLegacyTables(db)
}
