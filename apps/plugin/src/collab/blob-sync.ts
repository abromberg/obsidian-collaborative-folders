import {
  BLOB_AAD_HEADER,
  BLOB_DIGEST_HEADER,
  BLOB_NONCE_HEADER,
  KEY_EPOCH_HEADER,
  PROTOCOL_HEADER,
  PROTOCOL_V2,
} from '@obsidian-teams/shared'
import { CryptoEngine, fromBase64, toBase64 } from '../crypto/engine'
import { FolderKeyManager } from '../crypto/folder-key-manager'
import { httpRequest } from '../utils/http'

const engine = new CryptoEngine()

interface BlobUploadErrorBody {
  error?: string
  message?: string
}

async function readUploadErrorDetail(response: {
  json: () => Promise<unknown>
  text: () => Promise<string>
}): Promise<string> {
  const payload = await response
    .json()
    .catch(async () => {
      const text = await response.text().catch(() => '')
      return { error: text }
    }) as BlobUploadErrorBody

  if (typeof payload.error === 'string' && payload.error.trim()) {
    return payload.error.trim()
  }
  if (typeof payload.message === 'string' && payload.message.trim()) {
    return payload.message.trim()
  }
  return ''
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

function blobEndpoint(serverUrl: string, folderId: string, hash: string): string {
  const encodedFolderId = encodeURIComponent(folderId)
  const encodedHash = encodeURIComponent(hash)
  return `${serverUrl}/api/folders/${encodedFolderId}/blobs/${encodedHash}`
}

function aadBytes(folderId: string, hash: string): Uint8Array {
  return new TextEncoder().encode(`${folderId}:${hash}:blob`)
}

/** Compute SHA-256 hash of binary content */
export async function computeHash(content: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', content)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function keyForEpoch(
  keyManager: FolderKeyManager,
  folderId: string,
  epoch: number
): Promise<CryptoKey> {
  const cached = await keyManager.getCachedContentKey(folderId, epoch)
  if (cached) return cached

  const active = await keyManager.getActiveContentKey(folderId, { forceRefresh: true })
  if (active.epoch !== epoch) {
    throw new Error(`Required key epoch ${epoch} is unavailable (active=${active.epoch})`)
  }
  return active.key
}

/** Upload encrypted blob ciphertext. Returns plaintext digest hash used as blob id. */
export async function uploadBlob(
  serverUrl: string,
  folderId: string,
  getAuthToken: () => Promise<string | null>,
  keyManager: FolderKeyManager,
  content: ArrayBuffer
): Promise<string> {
  const hash = await computeHash(content)
  const token = await getAuthToken()
  if (!token) {
    throw new Error('Blob upload failed: missing auth token')
  }

  const { key, epoch } = await keyManager.getActiveContentKey(folderId)
  const aad = aadBytes(folderId, hash)
  const encrypted = await engine.encryptBytes(new Uint8Array(content), key, { aad })

  const response = await httpRequest(blobEndpoint(serverUrl, folderId, hash), {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/octet-stream',
      [PROTOCOL_HEADER]: PROTOCOL_V2,
      [KEY_EPOCH_HEADER]: String(epoch),
      [BLOB_NONCE_HEADER]: toBase64(encrypted.nonce),
      [BLOB_AAD_HEADER]: toBase64(aad),
      [BLOB_DIGEST_HEADER]: hash,
    },
    body: toArrayBuffer(encrypted.ciphertext),
  })

  if (!response.ok) {
    const detail = await readUploadErrorDetail(response)

    if (response.status === 409) {
      if (detail.toLowerCase().includes('already exists')) {
        return hash
      }
      throw new Error(detail ? `Blob upload failed: ${detail}` : 'Blob upload failed: HTTP 409')
    }

    throw new Error(detail ? `Blob upload failed: ${detail}` : `Blob upload failed: HTTP ${response.status}`)
  }

  return hash
}

/** Download encrypted blob and decrypt into plaintext. */
export async function downloadBlob(
  serverUrl: string,
  folderId: string,
  getAuthToken: () => Promise<string | null>,
  keyManager: FolderKeyManager,
  hash: string
): Promise<ArrayBuffer> {
  const token = await getAuthToken()
  if (!token) {
    throw new Error('Blob download failed: missing auth token')
  }

  const response = await httpRequest(blobEndpoint(serverUrl, folderId, hash), {
    headers: {
      Authorization: `Bearer ${token}`,
      [PROTOCOL_HEADER]: PROTOCOL_V2,
    },
  })

  if (!response.ok) {
    throw new Error(`Blob download failed: HTTP ${response.status}`)
  }

  const epochHeader = response.headers.get(KEY_EPOCH_HEADER)
  const nonceHeader = response.headers.get(BLOB_NONCE_HEADER)
  const aadHeader = response.headers.get(BLOB_AAD_HEADER)
  const digestHeader = response.headers.get(BLOB_DIGEST_HEADER) || hash

  const epoch = epochHeader ? Number(epochHeader) : NaN
  if (!Number.isFinite(epoch) || epoch <= 0 || !nonceHeader) {
    throw new Error('Blob download failed: missing encryption headers')
  }

  const ciphertext = new Uint8Array(await response.arrayBuffer())
  const key = await keyForEpoch(keyManager, folderId, Math.trunc(epoch))
  const plaintext = await engine.decryptBytes(
    {
      nonce: fromBase64(nonceHeader),
      ciphertext,
      aad: aadHeader ? fromBase64(aadHeader) : undefined,
    },
    key,
    {
      aad: aadHeader ? fromBase64(aadHeader) : aadBytes(folderId, hash),
    }
  )

  const computed = await computeHash(toArrayBuffer(plaintext))
  if (computed !== digestHeader) {
    throw new Error('Blob digest verification failed after decryption')
  }

  return toArrayBuffer(plaintext)
}

/**
 * Upload a blob with exponential backoff retry.
 * Retries up to 3 times on failure.
 */
export async function uploadBlobWithRetry(
  serverUrl: string,
  folderId: string,
  getAuthToken: () => Promise<string | null>,
  keyManager: FolderKeyManager,
  content: ArrayBuffer,
  maxRetries = 3
): Promise<string> {
  let lastError: Error | null = null

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await uploadBlob(serverUrl, folderId, getAuthToken, keyManager, content)
    } catch (err: unknown) {
      lastError = err instanceof Error ? err : new Error(String(err))
      if (attempt < maxRetries - 1) {
        const delay = Math.min(1000 * Math.pow(2, attempt), 10000)
        await new Promise((resolve) => setTimeout(resolve, delay))
      }
    }
  }

  throw lastError || new Error('Upload failed after retries')
}
