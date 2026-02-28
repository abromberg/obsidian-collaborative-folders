import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import os from 'os'
import fs from 'fs'

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-teams-schema-migration-test-'))
process.env.DB_PATH = path.join(tempRoot, 'legacy.sqlite')
process.env.BLOB_DIR = path.join(tempRoot, 'blobs')
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { initDb, getDb } = await import('../db/schema.js')
const db = getDb()

const legacyScopePrefix = ['hosted', 'workspace'].join('_')
const legacyScopeColumn = ['workspace', 'id'].join('_')
const legacyTables = {
  root: `${legacyScopePrefix}s`,
  billing: `${legacyScopePrefix}_billing`,
  usage: `${legacyScopePrefix}_usage`,
  members: `${legacyScopePrefix}_members`,
}

function resetDb(): void {
  db.pragma('foreign_keys = OFF')
  db.exec(`
    DROP TABLE IF EXISTS folder_key_envelopes;
    DROP TABLE IF EXISTS folder_key_epochs;
    DROP TABLE IF EXISTS encrypted_doc_snapshots;
    DROP TABLE IF EXISTS encrypted_doc_events;
    DROP TABLE IF EXISTS encrypted_blobs;
    DROP TABLE IF EXISTS blob_access_log;
    DROP TABLE IF EXISTS audit_events;
    DROP TABLE IF EXISTS refresh_tokens;
    DROP TABLE IF EXISTS revoked_tokens;
    DROP TABLE IF EXISTS invites;
    DROP TABLE IF EXISTS members;
    DROP TABLE IF EXISTS folders;
    DROP TABLE IF EXISTS hosted_billing_events;
    DROP TABLE IF EXISTS hosted_account_usage;
    DROP TABLE IF EXISTS hosted_account_billing;
    DROP TABLE IF EXISTS hosted_account_sessions;
    DROP TABLE IF EXISTS hosted_accounts;
    DROP TABLE IF EXISTS ${legacyTables.usage};
    DROP TABLE IF EXISTS ${legacyTables.billing};
    DROP TABLE IF EXISTS ${legacyTables.members};
    DROP TABLE IF EXISTS ${legacyTables.root};
  `)
  db.pragma('foreign_keys = ON')
}

test('initDb migrates legacy hosted ownership/billing into account-scoped tables', () => {
  resetDb()

  db.exec(`
    CREATE TABLE hosted_accounts (
      id TEXT PRIMARY KEY,
      email_norm TEXT NOT NULL UNIQUE,
      display_name TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE ${legacyTables.root} (
      id TEXT PRIMARY KEY,
      owner_account_id TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE ${legacyTables.billing} (
      ${legacyScopeColumn} TEXT PRIMARY KEY,
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      stripe_subscription_item_id TEXT,
      subscription_status TEXT,
      seat_price_cents INTEGER,
      seat_limit INTEGER,
      storage_cap_bytes INTEGER,
      max_file_size_bytes INTEGER,
      current_period_end TEXT,
      cancel_at_period_end INTEGER,
      updated_at TEXT
    );

    CREATE TABLE ${legacyTables.usage} (
      ${legacyScopeColumn} TEXT PRIMARY KEY,
      seat_count INTEGER,
      storage_bytes INTEGER,
      updated_at TEXT
    );

    CREATE TABLE ${legacyTables.members} (
      id TEXT PRIMARY KEY,
      ${legacyScopeColumn} TEXT NOT NULL,
      account_id TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT,
      removed_at TEXT
    );

    CREATE TABLE folders (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_client_id TEXT NOT NULL,
      ${legacyScopeColumn} TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE members (
      folder_id TEXT NOT NULL,
      client_id TEXT NOT NULL,
      account_id TEXT,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL,
      joined_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (folder_id, client_id)
    );

    CREATE TABLE invites (
      token_hash TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      consumed_at TEXT,
      consumed_by TEXT
    );

    CREATE TABLE hosted_billing_events (
      stripe_event_id TEXT PRIMARY KEY,
      ${legacyScopeColumn} TEXT,
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      received_at TEXT NOT NULL DEFAULT (datetime('now')),
      processed_at TEXT,
      processing_error TEXT
    );

    CREATE TABLE encrypted_blobs (
      id TEXT PRIMARY KEY,
      folder_id TEXT NOT NULL,
      blob_id TEXT NOT NULL,
      epoch INTEGER NOT NULL,
      size_bytes INTEGER NOT NULL,
      nonce BLOB NOT NULL,
      aad BLOB,
      digest_hex TEXT NOT NULL,
      storage_path TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES ('acct-owner', 'owner@example.com', 'Owner', 'active');

    INSERT INTO ${legacyTables.root} (id, owner_account_id, name)
    VALUES ('scope-1', 'acct-owner', 'Owner Scope');

    INSERT INTO ${legacyTables.billing} (
      ${legacyScopeColumn},
      stripe_customer_id,
      stripe_subscription_id,
      stripe_subscription_item_id,
      subscription_status,
      seat_price_cents,
      seat_limit,
      storage_cap_bytes,
      max_file_size_bytes,
      current_period_end,
      cancel_at_period_end,
      updated_at
    ) VALUES (
      'scope-1',
      'cus_test_1',
      'sub_test_1',
      'si_test_1',
      'active',
      900,
      1,
      12345,
      2500,
      '2026-03-31T00:00:00.000Z',
      0,
      datetime('now')
    );

    INSERT INTO folders (id, name, owner_client_id, ${legacyScopeColumn})
    VALUES ('folder-1', 'Shared Folder', 'owner-client-1', 'scope-1');

    INSERT INTO members (folder_id, client_id, account_id, display_name, role)
    VALUES ('folder-1', 'owner-client-1', 'acct-owner', 'Owner', 'owner');

    INSERT INTO encrypted_blobs (
      id,
      folder_id,
      blob_id,
      epoch,
      size_bytes,
      nonce,
      aad,
      digest_hex,
      storage_path
    ) VALUES (
      'blob-1',
      'folder-1',
      'blob-main',
      1,
      11,
      X'0011223344',
      NULL,
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      '/tmp/blob-1'
    );

    INSERT INTO hosted_billing_events (
      stripe_event_id,
      ${legacyScopeColumn},
      event_type,
      payload_json,
      received_at
    ) VALUES (
      'evt_1',
      'scope-1',
      'checkout.session.completed',
      '{"id":"evt_1"}',
      datetime('now')
    );
  `)

  initDb()

  const folderColumns = db.prepare('PRAGMA table_info(folders)').all() as Array<{ name: string }>
  assert.equal(folderColumns.some((column) => column.name === 'owner_account_id'), true)
  assert.equal(folderColumns.some((column) => column.name === legacyScopeColumn), false)

  const eventColumns = db.prepare('PRAGMA table_info(hosted_billing_events)').all() as Array<{ name: string }>
  assert.equal(eventColumns.some((column) => column.name === 'account_id'), true)
  assert.equal(eventColumns.some((column) => column.name === legacyScopeColumn), false)

  const migratedFolder = db
    .prepare('SELECT owner_account_id FROM folders WHERE id = ? LIMIT 1')
    .get('folder-1') as { owner_account_id: string | null } | undefined
  assert.equal(migratedFolder?.owner_account_id, 'acct-owner')

  const accountBilling = db
    .prepare(
      `
      SELECT
        stripe_customer_id,
        stripe_subscription_id,
        stripe_subscription_item_id,
        subscription_status,
        price_cents,
        storage_cap_bytes,
        max_file_size_bytes
      FROM hosted_account_billing
      WHERE account_id = ?
      LIMIT 1
    `
    )
    .get('acct-owner') as
    | {
        stripe_customer_id: string | null
        stripe_subscription_id: string | null
        stripe_subscription_item_id: string | null
        subscription_status: string
        price_cents: number
        storage_cap_bytes: number
        max_file_size_bytes: number
      }
    | undefined

  assert.equal(accountBilling?.stripe_customer_id, 'cus_test_1')
  assert.equal(accountBilling?.stripe_subscription_id, 'sub_test_1')
  assert.equal(accountBilling?.stripe_subscription_item_id, 'si_test_1')
  assert.equal(accountBilling?.subscription_status, 'active')
  assert.equal(accountBilling?.price_cents, 900)
  assert.equal(accountBilling?.storage_cap_bytes, 12345)
  assert.equal(accountBilling?.max_file_size_bytes, 2500)

  const usage = db
    .prepare(
      `
      SELECT owned_folder_count, owned_storage_bytes
      FROM hosted_account_usage
      WHERE account_id = ?
      LIMIT 1
    `
    )
    .get('acct-owner') as { owned_folder_count: number; owned_storage_bytes: number } | undefined
  assert.equal(usage?.owned_folder_count, 1)
  assert.equal(usage?.owned_storage_bytes, 11)

  const eventRow = db
    .prepare('SELECT account_id FROM hosted_billing_events WHERE stripe_event_id = ? LIMIT 1')
    .get('evt_1') as { account_id: string | null } | undefined
  assert.equal(eventRow?.account_id, 'acct-owner')

  const tables = db
    .prepare(
      `
      SELECT name
      FROM sqlite_master
      WHERE type = 'table'
    `
    )
    .all() as Array<{ name: string }>

  const tableNames = new Set(tables.map((row) => row.name))
  assert.equal(tableNames.has(legacyTables.root), false)
  assert.equal(tableNames.has(legacyTables.billing), false)
  assert.equal(tableNames.has(legacyTables.usage), false)
  assert.equal(tableNames.has(legacyTables.members), false)
})

test('initDb blocks migration when one owner maps to multiple billed legacy scopes', () => {
  resetDb()

  db.exec(`
    CREATE TABLE hosted_accounts (
      id TEXT PRIMARY KEY,
      email_norm TEXT NOT NULL UNIQUE,
      display_name TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE ${legacyTables.root} (
      id TEXT PRIMARY KEY,
      owner_account_id TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE ${legacyTables.billing} (
      ${legacyScopeColumn} TEXT PRIMARY KEY,
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      subscription_status TEXT,
      seat_price_cents INTEGER,
      seat_limit INTEGER,
      storage_cap_bytes INTEGER,
      max_file_size_bytes INTEGER,
      current_period_end TEXT,
      cancel_at_period_end INTEGER,
      updated_at TEXT
    );

    INSERT INTO hosted_accounts (id, email_norm, display_name, status)
    VALUES ('acct-owner', 'owner@example.com', 'Owner', 'active');

    INSERT INTO ${legacyTables.root} (id, owner_account_id, name)
    VALUES ('scope-a', 'acct-owner', 'A');

    INSERT INTO ${legacyTables.root} (id, owner_account_id, name)
    VALUES ('scope-b', 'acct-owner', 'B');

    INSERT INTO ${legacyTables.billing} (
      ${legacyScopeColumn},
      stripe_customer_id,
      stripe_subscription_id,
      subscription_status,
      seat_price_cents,
      seat_limit,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES ('scope-a', 'cus_1', 'sub_1', 'active', 900, 1, 3221225472, 26214400, datetime('now'));

    INSERT INTO ${legacyTables.billing} (
      ${legacyScopeColumn},
      stripe_customer_id,
      stripe_subscription_id,
      subscription_status,
      seat_price_cents,
      seat_limit,
      storage_cap_bytes,
      max_file_size_bytes,
      updated_at
    ) VALUES ('scope-b', 'cus_2', 'sub_2', 'active', 900, 1, 3221225472, 26214400, datetime('now'));
  `)

  assert.throws(
    () => initDb(),
    /ambiguous legacy billing owner mappings detected/
  )
})
