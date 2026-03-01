import { CryptoEngine } from './engine'

const STORAGE_KEY_PREFIX = 'obsidian-teams:v2'

interface StoredClientKeyPair {
  publicKeyJwk: JsonWebKey
  privateKeyJwk: JsonWebKey
  createdAt: string
}

interface StoredFolderKey {
  rawKeyBase64: string
  createdAt: string
}

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function getStorage(): Storage | null {
  if (typeof globalThis === 'undefined') return null
  if (!('localStorage' in globalThis)) return null
  return globalThis.localStorage
}

export class KeyStore {
  private memoryFallback = new Map<string, string>()

  constructor(private readonly engine = new CryptoEngine()) {}

  private get(key: string): string | null {
    const storage = getStorage()
    if (storage) return storage.getItem(key)
    return this.memoryFallback.get(key) ?? null
  }

  private set(key: string, value: string): void {
    const storage = getStorage()
    if (storage) {
      storage.setItem(key, value)
      return
    }
    this.memoryFallback.set(key, value)
  }

  private remove(key: string): void {
    const storage = getStorage()
    if (storage) {
      storage.removeItem(key)
      return
    }
    this.memoryFallback.delete(key)
  }

  private clientKey(clientId: string): string {
    return `${STORAGE_KEY_PREFIX}:client:${clientId}`
  }

  private folderKey(folderId: string, epoch: number): string {
    return `${STORAGE_KEY_PREFIX}:folder:${folderId}:epoch:${epoch}`
  }

  async getOrCreateClientKeyPair(clientId: string): Promise<CryptoKeyPair> {
    const raw = this.get(this.clientKey(clientId))
    if (raw) {
      const parsed = JSON.parse(raw) as StoredClientKeyPair
      const publicKey = await this.engine.importPublicKeyJwk(parsed.publicKeyJwk)
      const privateKey = await this.engine.importPrivateKeyJwk(parsed.privateKeyJwk)
      return { publicKey, privateKey }
    }

    const pair = await this.engine.generateClientKeyPair()
    const payload: StoredClientKeyPair = {
      publicKeyJwk: await this.engine.exportPublicKeyJwk(pair.publicKey),
      privateKeyJwk: await this.engine.exportPrivateKeyJwk(pair.privateKey),
      createdAt: new Date().toISOString(),
    }
    this.set(this.clientKey(clientId), JSON.stringify(payload))
    return pair
  }

  getClientPublicKeyJwk(clientId: string): JsonWebKey | null {
    const raw = this.get(this.clientKey(clientId))
    if (!raw) return null
    const parsed = JSON.parse(raw) as StoredClientKeyPair
    return parsed.publicKeyJwk
  }

  async storeFolderContentKey(folderId: string, epoch: number, key: CryptoKey): Promise<void> {
    const rawKey = await this.engine.exportContentKey(key)
    const payload: StoredFolderKey = {
      rawKeyBase64: toBase64(rawKey),
      createdAt: new Date().toISOString(),
    }
    this.set(this.folderKey(folderId, epoch), JSON.stringify(payload))
  }

  async loadFolderContentKey(folderId: string, epoch: number): Promise<CryptoKey | null> {
    const raw = this.get(this.folderKey(folderId, epoch))
    if (!raw) return null

    const parsed = JSON.parse(raw) as StoredFolderKey
    const rawKey = fromBase64(parsed.rawKeyBase64)
    return this.engine.importContentKey(rawKey)
  }

  clearFolderKeys(folderId: string): void {
    const prefix = `${STORAGE_KEY_PREFIX}:folder:${folderId}:epoch:`
    const storage = getStorage()

    if (storage) {
      const keys: string[] = []
      for (let i = 0; i < storage.length; i += 1) {
        const key = storage.key(i)
        if (key && key.startsWith(prefix)) keys.push(key)
      }
      keys.forEach((key) => storage.removeItem(key))
      return
    }

    for (const key of this.memoryFallback.keys()) {
      if (key.startsWith(prefix)) {
        this.memoryFallback.delete(key)
      }
    }
  }

  clearClientKeyPair(clientId: string): void {
    this.remove(this.clientKey(clientId))
  }
}
