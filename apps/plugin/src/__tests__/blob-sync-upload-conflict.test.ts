import test from 'node:test'
import assert from 'node:assert/strict'
import type { FolderKeyManager } from '../crypto/folder-key-manager'
import { uploadBlob, uploadBlobWithRetry } from '../collab/blob-sync'

interface MockRequest {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: string | ArrayBuffer
  throw?: boolean
}

interface MockResponse {
  status: number
  headers: Record<string, string>
  arrayBuffer: ArrayBuffer
  json: unknown
  text: string
}

function makeResponse(status: number, json: unknown, text = ''): MockResponse {
  return {
    status,
    headers: {},
    arrayBuffer: new ArrayBuffer(0),
    json,
    text,
  }
}

function withRequestUrlMock(fn: (request: MockRequest) => Promise<MockResponse>) {
  const previous = globalThis.__obsidianRequestUrl
  globalThis.__obsidianRequestUrl = fn as typeof globalThis.__obsidianRequestUrl
  return () => {
    globalThis.__obsidianRequestUrl = previous
  }
}

function keyManagerForEpochs(epochs: number[]): FolderKeyManager {
  let index = 0

  return {
    async getActiveContentKey() {
      const epoch = epochs[Math.min(index, epochs.length - 1)]
      index += 1
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      )
      return { key, epoch }
    },
  } as unknown as FolderKeyManager
}

test('uploadBlob accepts 409 only for already-existing blob conflicts', async () => {
  const restore = withRequestUrlMock(async () =>
    makeResponse(409, { message: 'Encrypted blob already exists for epoch' })
  )

  try {
    const hash = await uploadBlob(
      'https://example.com',
      'folder-1',
      async () => 'token',
      keyManagerForEpochs([1]),
      new TextEncoder().encode('payload').buffer
    )
    assert.match(hash, /^[a-f0-9]{64}$/)
  } finally {
    restore()
  }
})

test('uploadBlob throws on stale epoch 409 conflicts', async () => {
  const restore = withRequestUrlMock(async () =>
    makeResponse(409, { error: 'Stale key epoch. Active=2, received=1' })
  )

  try {
    await assert.rejects(
      () =>
        uploadBlob(
          'https://example.com',
          'folder-1',
          async () => 'token',
          keyManagerForEpochs([1]),
          new TextEncoder().encode('payload').buffer
        ),
      /Stale key epoch/
    )
  } finally {
    restore()
  }
})

test('uploadBlobWithRetry retries stale-epoch conflicts until successful upload', async () => {
  let requestCount = 0
  const restore = withRequestUrlMock(async () => {
    requestCount += 1
    if (requestCount === 1) {
      return makeResponse(409, { error: 'Stale key epoch. Active=2, received=1' })
    }
    return makeResponse(201, { blobId: 'ok' })
  })

  try {
    const hash = await uploadBlobWithRetry(
      'https://example.com',
      'folder-1',
      async () => 'token',
      keyManagerForEpochs([1, 2]),
      new TextEncoder().encode('payload').buffer,
      3
    )

    assert.match(hash, /^[a-f0-9]{64}$/)
    assert.equal(requestCount, 2)
  } finally {
    restore()
  }
})
