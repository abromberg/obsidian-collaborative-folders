/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import crypto from 'crypto'
import { type CiphertextEnvelope, PROTOCOL_V2 } from '@obsidian-teams/shared'
import { getDb } from '../db/schema.js'

interface SnapshotRow {
  id: string
  folder_id: string
  room_name: string
  epoch: number
  nonce: Buffer
  ciphertext: Buffer
  aad: Buffer | null
  base_event_id: number
  created_at: string
}

interface EventRow {
  id: number
  folder_id: string
  room_name: string
  epoch: number
  nonce: Buffer
  ciphertext: Buffer
  aad: Buffer | null
  sender_client_id: string
  created_at: string
}

function decodeBase64(value: string): Buffer {
  return Buffer.from(value, 'base64')
}

function encodeBase64(value: Buffer | null): string | undefined {
  if (!value) return undefined
  return value.toString('base64')
}

export function appendEncryptedDocEvent(input: {
  folderId: string
  roomName: string
  senderClientId: string
  envelope: CiphertextEnvelope
}): number {
  const db = getDb()
  const result = db
    .prepare(
      `
      INSERT INTO encrypted_doc_events (
        folder_id, room_name, epoch, nonce, ciphertext, aad, sender_client_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `
    )
    .run(
      input.folderId,
      input.roomName,
      input.envelope.keyEpoch,
      decodeBase64(input.envelope.nonceBase64),
      decodeBase64(input.envelope.ciphertextBase64),
      input.envelope.aadBase64 ? decodeBase64(input.envelope.aadBase64) : null,
      input.senderClientId
    )

  return Number(result.lastInsertRowid)
}

export function getEncryptedDocEventsAfter(input: {
  folderId: string
  roomName: string
  afterEventId: number
  limit?: number
}): Array<{
  eventId: number
  senderClientId: string
  sentAt: string
  envelope: CiphertextEnvelope
}> {
  const db = getDb()
  const limit = Math.min(Math.max(input.limit ?? 5000, 1), 20_000)
  const rows = db
    .prepare(
      `
      SELECT id, folder_id, room_name, epoch, nonce, ciphertext, aad, sender_client_id, created_at
      FROM encrypted_doc_events
      WHERE folder_id = ? AND room_name = ? AND id > ?
      ORDER BY id ASC
      LIMIT ?
    `
    )
    .all(input.folderId, input.roomName, input.afterEventId, limit) as EventRow[]

  return rows.map((row) => ({
    eventId: row.id,
    senderClientId: row.sender_client_id,
    sentAt: row.created_at,
    envelope: {
      protocol: PROTOCOL_V2,
      keyEpoch: row.epoch,
      kind: 'doc-update',
      target: row.room_name,
      nonceBase64: row.nonce.toString('base64'),
      ciphertextBase64: row.ciphertext.toString('base64'),
      aadBase64: encodeBase64(row.aad),
    },
  }))
}

export function upsertEncryptedDocSnapshot(input: {
  folderId: string
  roomName: string
  envelope: CiphertextEnvelope
  baseEventId: number
}): void {
  const db = getDb()
  const snapshotId = crypto.randomUUID()

  db.prepare(
    `
    INSERT INTO encrypted_doc_snapshots (
      id, folder_id, room_name, epoch, nonce, ciphertext, aad, base_event_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(folder_id, room_name)
    DO UPDATE SET
      id = excluded.id,
      epoch = excluded.epoch,
      nonce = excluded.nonce,
      ciphertext = excluded.ciphertext,
      aad = excluded.aad,
      base_event_id = excluded.base_event_id,
      created_at = datetime('now')
  `
  ).run(
    snapshotId,
    input.folderId,
    input.roomName,
    input.envelope.keyEpoch,
    decodeBase64(input.envelope.nonceBase64),
    decodeBase64(input.envelope.ciphertextBase64),
    input.envelope.aadBase64 ? decodeBase64(input.envelope.aadBase64) : null,
    input.baseEventId
  )
}

export function getLatestEncryptedDocSnapshot(input: {
  folderId: string
  roomName: string
}):
  | {
      baseEventId: number
      createdAt: string
      envelope: CiphertextEnvelope
    }
  | null {
  const db = getDb()
  const row = db
    .prepare(
      `
      SELECT id, folder_id, room_name, epoch, nonce, ciphertext, aad, base_event_id, created_at
      FROM encrypted_doc_snapshots
      WHERE folder_id = ? AND room_name = ?
      LIMIT 1
    `
    )
    .get(input.folderId, input.roomName) as SnapshotRow | undefined

  if (!row) return null

  return {
    baseEventId: row.base_event_id,
    createdAt: row.created_at,
    envelope: {
      protocol: PROTOCOL_V2,
      keyEpoch: row.epoch,
      kind: 'doc-snapshot',
      target: row.room_name,
      nonceBase64: row.nonce.toString('base64'),
      ciphertextBase64: row.ciphertext.toString('base64'),
      aadBase64: encodeBase64(row.aad),
    },
  }
}
