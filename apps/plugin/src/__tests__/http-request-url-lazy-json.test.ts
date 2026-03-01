import test from 'node:test'
import assert from 'node:assert/strict'
import { httpRequest } from '../utils/http'

interface MockRequest {
  url: string
  method?: string
  body?: string | ArrayBuffer
  headers?: Record<string, string>
  throw?: boolean
}

function withRequestUrlMock(
  fn: (request: MockRequest) => Promise<{
    status: number
    headers: Record<string, string>
    arrayBuffer: ArrayBuffer
    json: unknown
    text: string
  }>
) {
  const previous = globalThis.__obsidianRequestUrl
  globalThis.__obsidianRequestUrl = fn as typeof globalThis.__obsidianRequestUrl
  return () => {
    globalThis.__obsidianRequestUrl = previous
  }
}

test('httpRequest does not eagerly evaluate requestUrl json getter', async () => {
  const binary = new Uint8Array([1, 255, 9, 124]).buffer

  const restore = withRequestUrlMock(async () => ({
    status: 200,
    headers: { 'content-type': 'application/octet-stream' },
    arrayBuffer: binary,
    get json() {
      throw new SyntaxError('binary body is not JSON')
    },
    text: '\u0001\u00ff\u0009|',
  }))

  try {
    const response = await httpRequest('https://example.com/blob')
    const body = await response.arrayBuffer()

    assert.equal(response.ok, true)
    assert.equal(body.byteLength, 4)
  } finally {
    restore()
  }
})

test('httpRequest surfaces json parse errors only when json() is called', async () => {
  const restore = withRequestUrlMock(async () => ({
    status: 200,
    headers: { 'content-type': 'application/octet-stream' },
    arrayBuffer: new Uint8Array([1, 2, 3]).buffer,
    get json() {
      throw new SyntaxError('invalid JSON payload')
    },
    text: '\u0001\u0002\u0003',
  }))

  try {
    const response = await httpRequest('https://example.com/blob')
    await assert.rejects(() => response.json(), /invalid JSON payload/)
  } finally {
    restore()
  }
})
