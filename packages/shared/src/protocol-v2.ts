export const PROTOCOL_V2 = 'v2' as const
export const PROTOCOL_HEADER = 'x-obsidian-teams-protocol' as const
export const KEY_EPOCH_HEADER = 'x-obsidian-teams-key-epoch' as const
export const BLOB_NONCE_HEADER = 'x-obsidian-teams-blob-nonce' as const
export const BLOB_AAD_HEADER = 'x-obsidian-teams-blob-aad' as const
export const BLOB_DIGEST_HEADER = 'x-obsidian-teams-blob-digest' as const

export type V2EntityKind = 'doc-update' | 'doc-snapshot' | 'blob'

export interface CiphertextEnvelope {
  /** Protocol gate. */
  protocol: typeof PROTOCOL_V2
  /** Per-folder key epoch used for encryption. */
  keyEpoch: number
  /** Content channel type. */
  kind: V2EntityKind
  /** Target document ID or blob hash/ID. */
  target: string
  /** Base64 nonce used by AEAD. */
  nonceBase64: string
  /** Base64 ciphertext + authentication tag. */
  ciphertextBase64: string
  /** Base64-encoded associated data when present. */
  aadBase64?: string
}

export interface EncryptedSyncMessage {
  protocol: typeof PROTOCOL_V2
  folderId: string
  roomName: string
  envelope: CiphertextEnvelope
  sentAt: string
}

export interface EncryptedSnapshotRecord {
  protocol: typeof PROTOCOL_V2
  folderId: string
  docId: string
  keyEpoch: number
  envelope: CiphertextEnvelope
  createdAt: string
}

export interface EncryptedRelayHandshake {
  type: 'hello'
  protocol: typeof PROTOCOL_V2
  roomName: string
  folderId: string
  actorClientId: string
  actorDisplayName: string
  actorRole: 'owner' | 'editor'
  serverTime: string
}

export interface EncryptedRelayUpdate {
  type: 'doc_update'
  protocol: typeof PROTOCOL_V2
  roomName: string
  senderClientId: string
  eventId: number
  envelope: CiphertextEnvelope
  sentAt: string
}

export interface EncryptedRelaySnapshot {
  type: 'doc_snapshot'
  protocol: typeof PROTOCOL_V2
  roomName: string
  senderClientId: string
  baseEventId: number
  envelope: CiphertextEnvelope
  sentAt: string
}

export interface EncryptedRelayAwareness {
  type: 'awareness_update'
  protocol: typeof PROTOCOL_V2
  roomName: string
  senderClientId: string
  awarenessBase64: string
  sentAt: string
}

export interface EncryptedRelayAck {
  type: 'ack'
  protocol: typeof PROTOCOL_V2
  roomName: string
  eventId: number
}

export interface EncryptedRelaySynced {
  type: 'synced'
  protocol: typeof PROTOCOL_V2
  roomName: string
  lastEventId: number
}

export interface EncryptedRelayError {
  type: 'error'
  protocol: typeof PROTOCOL_V2
  roomName?: string
  code:
    | 'invalid_message'
    | 'protocol_mismatch'
    | 'auth_failed'
    | 'stale_epoch'
    | 'forbidden'
    | 'internal_error'
  message: string
}

export type EncryptedRelayMessage =
  | EncryptedRelayHandshake
  | EncryptedRelayUpdate
  | EncryptedRelaySnapshot
  | EncryptedRelayAwareness
  | EncryptedRelayAck
  | EncryptedRelaySynced
  | EncryptedRelayError
