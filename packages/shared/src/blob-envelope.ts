import type { KeyWrapAlgorithm } from './key-types.js'
import { PROTOCOL_V2 } from './protocol-v2.js'

export interface EncryptedBlobEnvelope {
  protocol: typeof PROTOCOL_V2
  folderId: string
  blobId: string
  keyEpoch: number
  nonceBase64: string
  ciphertextBase64: string
  aadBase64?: string
  digestHex: string
  wrapAlgorithmHint?: KeyWrapAlgorithm
}
