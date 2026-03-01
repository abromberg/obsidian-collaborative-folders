/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import crypto from 'crypto'
import type Database from 'better-sqlite3'

export interface AuditEventInput {
  folderId?: string | null
  actorClientId?: string | null
  eventType: string
  target?: string | null
  metadata?: Record<string, unknown> | null
}

export function writeAuditEvent(db: Database.Database, input: AuditEventInput): void {
  const id = crypto.randomUUID()
  const metadataJson = input.metadata ? JSON.stringify(input.metadata) : null

  db.prepare(`
    INSERT INTO audit_events (
      id, folder_id, actor_client_id, event_type, target, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    id,
    input.folderId ?? null,
    input.actorClientId ?? null,
    input.eventType,
    input.target ?? null,
    metadataJson
  )
}
