import { PROTOCOL_V2, type CiphertextEnvelope } from '@obsidian-teams/shared'

const AES_ALGORITHM = 'AES-GCM'
const AES_KEY_LENGTH = 256
const NONCE_BYTES = 12

export interface EncryptOptions {
  kind: CiphertextEnvelope['kind']
  target: string
  keyEpoch: number
  aad?: Uint8Array
}

export interface DecryptOptions {
  aad?: Uint8Array
}

export interface EncryptedBinary {
  nonce: Uint8Array
  ciphertext: Uint8Array
  aad?: Uint8Array
}

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

export class CryptoEngine {
  async generateContentKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      {
        name: AES_ALGORITHM,
        length: AES_KEY_LENGTH,
      },
      true,
      ['encrypt', 'decrypt']
    )
  }

  async exportContentKey(key: CryptoKey): Promise<Uint8Array> {
    const raw = await crypto.subtle.exportKey('raw', key)
    return new Uint8Array(raw)
  }

  async importContentKey(raw: Uint8Array | ArrayBuffer): Promise<CryptoKey> {
    const normalized = raw instanceof Uint8Array ? raw : new Uint8Array(raw)
    return crypto.subtle.importKey('raw', toArrayBuffer(normalized), AES_ALGORITHM, true, ['encrypt', 'decrypt'])
  }

  /** One RSA-OAEP keypair per client for folder content-key wrapping. */
  async generateClientKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    )
  }

  async exportPublicKeyJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
    return crypto.subtle.exportKey('jwk', publicKey)
  }

  async exportPrivateKeyJwk(privateKey: CryptoKey): Promise<JsonWebKey> {
    return crypto.subtle.exportKey('jwk', privateKey)
  }

  async importPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
    return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt'])
  }

  async importPrivateKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
    return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt'])
  }

  async wrapContentKeyWithPublicKey(contentKey: CryptoKey, recipientPublicKeyJwk: JsonWebKey): Promise<string> {
    const recipientPublicKey = await this.importPublicKeyJwk(recipientPublicKeyJwk)
    const rawKey = await this.exportContentKey(contentKey)
    const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPublicKey, toArrayBuffer(rawKey))
    return toBase64(new Uint8Array(wrapped))
  }

  async unwrapContentKeyWithPrivateKey(wrappedKeyBase64: string, privateKey: CryptoKey): Promise<CryptoKey> {
    const wrapped = fromBase64(wrappedKeyBase64)
    const rawKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, toArrayBuffer(wrapped))
    return this.importContentKey(new Uint8Array(rawKey))
  }

  async encryptBytes(
    plaintext: Uint8Array,
    key: CryptoKey,
    options: { aad?: Uint8Array; nonce?: Uint8Array } = {}
  ): Promise<EncryptedBinary> {
    const nonce = options.nonce || crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: AES_ALGORITHM,
        iv: toArrayBuffer(nonce),
        additionalData: options.aad ? toArrayBuffer(options.aad) : undefined,
      },
      key,
      toArrayBuffer(plaintext)
    )

    return {
      nonce,
      ciphertext: new Uint8Array(ciphertext),
      aad: options.aad,
    }
  }

  async decryptBytes(
    encrypted: EncryptedBinary,
    key: CryptoKey,
    options: { aad?: Uint8Array } = {}
  ): Promise<Uint8Array> {
    const aad = options.aad ?? encrypted.aad
    const plaintext = await crypto.subtle.decrypt(
      {
        name: AES_ALGORITHM,
        iv: toArrayBuffer(encrypted.nonce),
        additionalData: aad ? toArrayBuffer(aad) : undefined,
      },
      key,
      toArrayBuffer(encrypted.ciphertext)
    )

    return new Uint8Array(plaintext)
  }

  async encrypt(plaintext: Uint8Array, key: CryptoKey, options: EncryptOptions): Promise<CiphertextEnvelope> {
    const encrypted = await this.encryptBytes(plaintext, key, { aad: options.aad })

    return {
      protocol: PROTOCOL_V2,
      keyEpoch: options.keyEpoch,
      kind: options.kind,
      target: options.target,
      nonceBase64: toBase64(encrypted.nonce),
      ciphertextBase64: toBase64(encrypted.ciphertext),
      aadBase64: encrypted.aad ? toBase64(encrypted.aad) : undefined,
    }
  }

  async decrypt(envelope: CiphertextEnvelope, key: CryptoKey, options: DecryptOptions = {}): Promise<Uint8Array> {
    const aad = options.aad ?? (envelope.aadBase64 ? fromBase64(envelope.aadBase64) : undefined)

    return this.decryptBytes(
      {
        nonce: fromBase64(envelope.nonceBase64),
        ciphertext: fromBase64(envelope.ciphertextBase64),
        aad,
      },
      key,
      { aad }
    )
  }
}
