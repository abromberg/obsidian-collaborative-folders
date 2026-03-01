export type KeyWrapAlgorithm = 'rsa-oaep' | 'x25519-sealed-box' | 'ecdh-p256-aeskw'

export interface ClientPublicKeyRecord {
  clientId: string
  publicKey: string
  algorithm: KeyWrapAlgorithm
  createdAt: string
  updatedAt: string
}

export interface FolderKeyEnvelopePayload {
  clientId: string
  clientPublicKey: string
  wrappedKeyBase64: string
  wrapAlgorithm: KeyWrapAlgorithm
}

export interface RotateFolderKeyRequest {
  nextEpoch?: number
  envelopes: FolderKeyEnvelopePayload[]
}

export interface ClientKeyDirectoryResponse {
  folderId: string
  members: ClientPublicKeyRecord[]
}

export interface RotateFolderKeyResponse {
  folderId: string
  epoch: number
  activatedAt: string
  envelopeCount: number
}

export interface RegisterClientKeyRequest {
  publicKey: string
  algorithm?: KeyWrapAlgorithm
}

export interface CurrentKeyEnvelopeResponse {
  folderId: string
  epoch: number
  envelope: FolderKeyEnvelopePayload & {
    createdAt: string
  }
}

export interface CurrentKeyEnvelopePendingResponse {
  folderId: string
  epoch: number | null
  pending: 'no_active_epoch' | 'missing_envelope'
}

export type CurrentKeyEnvelopeLookupResponse =
  | CurrentKeyEnvelopeResponse
  | CurrentKeyEnvelopePendingResponse

export interface ActiveKeyCoverageResponse {
  folderId: string
  epoch: number | null
  missingClientIds: string[]
}

export interface ActiveEnvelopeUpsertRequest {
  envelopes: FolderKeyEnvelopePayload[]
}

export interface ActiveEnvelopeUpsertResponse {
  folderId: string
  epoch: number
  insertedOrUpdated: number
  missingClientIds: string[]
}
