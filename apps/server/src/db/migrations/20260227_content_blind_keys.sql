-- Content-blind key lifecycle tables (Phase 1)

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
