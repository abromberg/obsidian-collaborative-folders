import {
  type ActiveEnvelopeUpsertRequest,
  type ActiveKeyCoverageResponse,
  PROTOCOL_HEADER,
  PROTOCOL_V2,
  type ClientKeyDirectoryResponse,
  type CurrentKeyEnvelopeResponse,
  type RotateFolderKeyRequest,
  type RotateFolderKeyResponse,
} from '@obsidian-teams/shared'
import { CryptoEngine } from './engine'
import { KeyStore } from './key-store'
import { decodeAccessToken } from '../utils/auth'
import { httpRequest, type HttpResponseLike } from '../utils/http'

type TokenOptions = { forceRefresh?: boolean }
const ENVELOPE_WAIT_MAX_ATTEMPTS = 8
const ENVELOPE_WAIT_BASE_DELAY_MS = 500
type CurrentEnvelopeLookupResponse =
  | CurrentKeyEnvelopeResponse
  | {
      folderId: string
      epoch: number | null
      pending: 'no_active_epoch' | 'missing_envelope'
    }

function readErrorMessage(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null
  const value = (payload as { error?: unknown }).error
  return typeof value === 'string' && value.length > 0 ? value : null
}

function assertOk(response: HttpResponseLike, message: string): Promise<void> {
  if (response.ok) return Promise.resolve()
  return response
    .json()
    .catch(() => null)
    .then((body) => {
      const detail = readErrorMessage(body) ?? `HTTP ${response.status}`
      throw new Error(`${message}: ${detail}`)
    })
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

export class FolderKeyManager {
  private inFlightByFolder = new Map<string, Promise<{ key: CryptoKey; epoch: number }>>()

  constructor(
    private readonly serverUrl: string,
    private readonly clientId: string,
    private readonly getAuthToken: (folderId: string, options?: TokenOptions) => Promise<string | null>,
    private readonly keyStore = new KeyStore(),
    private readonly engine = new CryptoEngine()
  ) {}

  clearFolderKeys(folderId: string): void {
    this.keyStore.clearFolderKeys(folderId)
  }

  clearLocalIdentity(): void {
    this.keyStore.clearClientKeyPair(this.clientId)
  }

  async getCachedContentKey(folderId: string, epoch: number): Promise<CryptoKey | null> {
    return this.keyStore.loadFolderContentKey(folderId, epoch)
  }

  async ensureRegistered(folderId: string, options: TokenOptions = {}): Promise<void> {
    const token = await this.getAuthToken(folderId, options)
    if (!token) {
      throw new Error('Missing folder auth token for key registration')
    }

    const pair = await this.keyStore.getOrCreateClientKeyPair(this.clientId)
    const publicKeyJwk = await this.engine.exportPublicKeyJwk(pair.publicKey)

    const response = await httpRequest(`${this.serverUrl}/api/folders/${encodeURIComponent(folderId)}/keys/client-key`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
      body: JSON.stringify({
        publicKey: JSON.stringify(publicKeyJwk),
        algorithm: 'rsa-oaep',
      }),
    })

    await assertOk(response, 'Client key registration failed')
  }

  async getActiveContentKey(folderId: string, options: TokenOptions = {}): Promise<{ key: CryptoKey; epoch: number }> {
    const existing = this.inFlightByFolder.get(folderId)
    if (existing) return existing

    const request = this.resolveActiveContentKey(folderId, options).finally(() => {
      this.inFlightByFolder.delete(folderId)
    })
    this.inFlightByFolder.set(folderId, request)
    return request
  }

  private async resolveActiveContentKey(folderId: string, options: TokenOptions): Promise<{ key: CryptoKey; epoch: number }> {
    await this.ensureRegistered(folderId, options)

    let envelope = await this.fetchCurrentEnvelope(folderId, options)
    const token = await this.getAuthToken(folderId, options)
    const access = token ? decodeAccessToken(token) : null

    if (!envelope) {
      if (access?.role === 'owner') {
        await this.bootstrapEpochAsOwner(folderId, options)
        envelope = await this.fetchCurrentEnvelope(folderId, options)
      } else {
        envelope = await this.waitForCurrentEnvelope(folderId, options)
      }

      if (!envelope) {
        throw new Error('Folder key envelope is unavailable. Waiting for owner key sync.')
      }
    }

    const cached = await this.keyStore.loadFolderContentKey(folderId, envelope.epoch)
    if (cached) {
      return { key: cached, epoch: envelope.epoch }
    }

    const pair = await this.keyStore.getOrCreateClientKeyPair(this.clientId)
    const key = await this.engine.unwrapContentKeyWithPrivateKey(envelope.envelope.wrappedKeyBase64, pair.privateKey)
    await this.keyStore.storeFolderContentKey(folderId, envelope.epoch, key)
    return { key, epoch: envelope.epoch }
  }

  async ensureOwnerEnvelopeCoverage(folderId: string, options: TokenOptions = {}): Promise<boolean> {
    const token = await this.getAuthToken(folderId, options)
    if (!token) return false

    const access = decodeAccessToken(token)
    if (!access || access.role !== 'owner') {
      return false
    }

    await this.ensureRegistered(folderId, options)

    let envelope = await this.fetchCurrentEnvelope(folderId, options)
    if (!envelope) {
      await this.bootstrapEpochAsOwner(folderId, options)
      return true
    }

    let coverage = await this.fetchActiveCoverage(folderId, token)
    if (coverage.epoch === null) {
      await this.bootstrapEpochAsOwner(folderId, options)
      return true
    }

    if (coverage.epoch !== envelope.epoch) {
      envelope = await this.fetchCurrentEnvelope(folderId, { forceRefresh: true })
      if (!envelope) {
        await this.bootstrapEpochAsOwner(folderId, options)
        return true
      }
      coverage = await this.fetchActiveCoverage(folderId, token)
    }

    if (coverage.missingClientIds.length === 0) {
      return false
    }

    if (coverage.epoch === null) {
      await this.bootstrapEpochAsOwner(folderId, options)
      return true
    }

    const directory = await this.fetchClientDirectory(folderId, token)
    const memberById = new Map(directory.members.map((member) => [member.clientId, member]))
    const missingMembers = coverage.missingClientIds
      .map((clientId) => memberById.get(clientId))
      .filter(
        (member): member is ClientKeyDirectoryResponse['members'][number] =>
          typeof member !== 'undefined'
      )

    if (missingMembers.length !== coverage.missingClientIds.length) {
      throw new Error('Owner rekey required: members missing registered client keys')
    }

    let contentKey = await this.keyStore.loadFolderContentKey(folderId, coverage.epoch)
    if (!contentKey) {
      const pair = await this.keyStore.getOrCreateClientKeyPair(this.clientId)
      contentKey = await this.engine.unwrapContentKeyWithPrivateKey(envelope.envelope.wrappedKeyBase64, pair.privateKey)
      await this.keyStore.storeFolderContentKey(folderId, coverage.epoch, contentKey)
    }

    const envelopes: ActiveEnvelopeUpsertRequest['envelopes'] = []
    for (const member of missingMembers) {
      const publicKeyJwk = JSON.parse(member.publicKey) as JsonWebKey
      const wrappedKeyBase64 = await this.engine.wrapContentKeyWithPublicKey(contentKey, publicKeyJwk)
      envelopes.push({
        clientId: member.clientId,
        clientPublicKey: member.publicKey,
        wrappedKeyBase64,
        wrapAlgorithm: 'rsa-oaep',
      })
    }

    if (envelopes.length === 0) return false

    await this.upsertActiveEnvelopes(folderId, token, envelopes)
    return true
  }

  async buildRotatePayloadForMemberRemoval(
    folderId: string,
    removedClientId: string,
    options: TokenOptions = {}
  ): Promise<{ rotate: RotateFolderKeyRequest; contentKey: CryptoKey }> {
    const token = await this.getAuthToken(folderId, options)
    if (!token) {
      throw new Error('Cannot remove member without folder auth token')
    }

    const access = decodeAccessToken(token)
    if (!access || access.role !== 'owner') {
      throw new Error('Only the folder owner can remove members')
    }

    await this.ensureRegistered(folderId, options)

    const directory = await this.fetchClientDirectory(folderId, token)
    const remainingMembers = directory.members.filter((member) => member.clientId !== removedClientId)

    if (remainingMembers.length === directory.members.length) {
      throw new Error(`Cannot remove unknown member '${removedClientId}'`)
    }
    if (remainingMembers.length === 0) {
      throw new Error('Cannot rotate folder key for empty member set')
    }

    const contentKey = await this.engine.generateContentKey()
    const envelopes: RotateFolderKeyRequest['envelopes'] = []

    for (const member of remainingMembers) {
      const publicKeyJwk = JSON.parse(member.publicKey) as JsonWebKey
      const wrappedKeyBase64 = await this.engine.wrapContentKeyWithPublicKey(contentKey, publicKeyJwk)
      envelopes.push({
        clientId: member.clientId,
        clientPublicKey: member.publicKey,
        wrappedKeyBase64,
        wrapAlgorithm: 'rsa-oaep',
      })
    }

    return {
      rotate: { envelopes },
      contentKey,
    }
  }

  async storeContentKeyForEpoch(folderId: string, epoch: number, key: CryptoKey): Promise<void> {
    await this.keyStore.storeFolderContentKey(folderId, epoch, key)
  }

  private async fetchCurrentEnvelope(folderId: string, options: TokenOptions): Promise<CurrentKeyEnvelopeResponse | null> {
    const token = await this.getAuthToken(folderId, options)
    if (!token) return null

    const requestUrl = new URL(
      `/api/folders/${encodeURIComponent(folderId)}/keys/current-envelope`,
      this.serverUrl
    )
    requestUrl.searchParams.set('allowMissing', '1')

    const response = await httpRequest(
      requestUrl.toString(),
      {
        headers: {
          Authorization: `Bearer ${token}`,
          [PROTOCOL_HEADER]: PROTOCOL_V2,
        },
      }
    )

    // Backward-compatible with servers that do not support allowMissing.
    if (response.status === 404) {
      return null
    }

    await assertOk(response, 'Failed to fetch current key envelope')
    const payload = (await response.json()) as CurrentEnvelopeLookupResponse
    if ('pending' in payload) return null
    return payload
  }

  private async waitForCurrentEnvelope(
    folderId: string,
    options: TokenOptions
  ): Promise<CurrentKeyEnvelopeResponse | null> {
    for (let attempt = 0; attempt < ENVELOPE_WAIT_MAX_ATTEMPTS; attempt += 1) {
      const envelope = await this.fetchCurrentEnvelope(folderId, options)
      if (envelope) return envelope

      if (attempt < ENVELOPE_WAIT_MAX_ATTEMPTS - 1) {
        const backoff = Math.min(5_000, ENVELOPE_WAIT_BASE_DELAY_MS * Math.pow(2, attempt))
        await delay(backoff)
      }
    }

    return null
  }

  private async fetchClientDirectory(folderId: string, token: string): Promise<ClientKeyDirectoryResponse> {
    const response = await httpRequest(
      `${this.serverUrl}/api/folders/${encodeURIComponent(folderId)}/keys/clients`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          [PROTOCOL_HEADER]: PROTOCOL_V2,
        },
      }
    )
    await assertOk(response, 'Failed to fetch client key directory')
    return (await response.json()) as ClientKeyDirectoryResponse
  }

  private async fetchActiveCoverage(folderId: string, token: string): Promise<ActiveKeyCoverageResponse> {
    const response = await httpRequest(
      `${this.serverUrl}/api/folders/${encodeURIComponent(folderId)}/keys/active-coverage`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          [PROTOCOL_HEADER]: PROTOCOL_V2,
        },
      }
    )
    await assertOk(response, 'Failed to fetch active key coverage')
    return (await response.json()) as ActiveKeyCoverageResponse
  }

  private async upsertActiveEnvelopes(
    folderId: string,
    token: string,
    envelopes: ActiveEnvelopeUpsertRequest['envelopes']
  ): Promise<void> {
    const response = await httpRequest(
      `${this.serverUrl}/api/folders/${encodeURIComponent(folderId)}/keys/active-envelopes`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          [PROTOCOL_HEADER]: PROTOCOL_V2,
        },
        body: JSON.stringify({ envelopes }),
      }
    )
    await assertOk(response, 'Failed to upsert active key envelopes')
  }

  private async bootstrapEpochAsOwner(folderId: string, options: TokenOptions): Promise<void> {
    const token = await this.getAuthToken(folderId, options)
    if (!token) {
      throw new Error('Cannot bootstrap key epoch without folder auth token')
    }

    const access = decodeAccessToken(token)
    if (!access || access.role !== 'owner') {
      throw new Error('Folder key epoch is missing. Only the folder owner can bootstrap encryption.')
    }

    const directory = await this.fetchClientDirectory(folderId, token)
    if (directory.members.length === 0) {
      throw new Error('Cannot bootstrap folder keys without members')
    }

    const contentKey = await this.engine.generateContentKey()
    const envelopes: RotateFolderKeyRequest['envelopes'] = []

    for (const member of directory.members) {
      const publicKeyJwk = JSON.parse(member.publicKey) as JsonWebKey
      const wrappedKeyBase64 = await this.engine.wrapContentKeyWithPublicKey(contentKey, publicKeyJwk)

      envelopes.push({
        clientId: member.clientId,
        clientPublicKey: member.publicKey,
        wrappedKeyBase64,
        wrapAlgorithm: 'rsa-oaep',
      })
    }

    const rotateResponse = await httpRequest(`${this.serverUrl}/api/folders/${encodeURIComponent(folderId)}/keys/rotate`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
      body: JSON.stringify({ envelopes }),
    })
    await assertOk(rotateResponse, 'Failed to rotate folder key epoch')

    const rotate = (await rotateResponse.json()) as RotateFolderKeyResponse
    await this.keyStore.storeFolderContentKey(folderId, rotate.epoch, contentKey)
  }
}
