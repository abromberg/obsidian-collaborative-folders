import test from 'node:test'
import assert from 'node:assert/strict'
import { type AccessTokenPayload, PROTOCOL_HEADER, PROTOCOL_V2 } from '@obsidian-teams/shared'
import {
  createFileShareLink,
  previewFileShareLink,
  resolveFileShareLink,
} from '../utils/auth.js'

interface PluginStub {
  settings: {
    serverUrl: string
    folderTokens: Record<string, string>
    folderRefreshTokens: Record<string, string>
  }
  saveSettings: () => Promise<void>
}

function base64Url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64url')
}

function makeAccessToken(expEpochSeconds: number, overrides: Partial<AccessTokenPayload> = {}): string {
  const payload: AccessTokenPayload = {
    clientId: overrides.clientId || 'client-1',
    displayName: overrides.displayName || 'Client',
    folderId: overrides.folderId || 'folder-1',
    role: overrides.role || 'editor',
    type: 'access',
    tokenVersion: overrides.tokenVersion ?? 0,
    exp: overrides.exp ?? expEpochSeconds,
    iat: overrides.iat ?? Math.floor(Date.now() / 1000),
  }
  return `${base64Url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${base64Url(JSON.stringify(payload))}.sig`
}

function makePlugin(accessToken: string, refreshToken = 'refresh-1'): PluginStub {
  return {
    settings: {
      serverUrl: 'https://teams.example.com',
      folderTokens: { 'folder-1': accessToken },
      folderRefreshTokens: { 'folder-1': refreshToken },
    },
    saveSettings: async () => {},
  }
}

test('createFileShareLink posts authenticated payload and returns share URL', async () => {
  const now = Math.floor(Date.now() / 1000)
  const plugin = makePlugin(makeAccessToken(now + 3600))

  const calls: Array<{ url: string; init?: RequestInit }> = []
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(
      JSON.stringify({
        shareToken: 'file-token-123',
        shareUrl: 'https://teams.example.com/api/file-links/open?token=file-token-123',
        expiresAt: '2026-03-08T00:00:00.000Z',
      }),
      {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  }) as typeof fetch

  try {
    const result = await createFileShareLink(plugin as any, 'folder-1', {
      fileId: 'file-1',
      relativePath: 'notes/today.md',
      fileName: 'today.md',
    })

    assert.equal(result.shareToken, 'file-token-123')
    assert.equal(result.shareUrl, 'https://teams.example.com/api/file-links/open?token=file-token-123')
    assert.equal(calls.length, 1)
    assert.match(calls[0].url, /\/api\/folders\/folder-1\/file-links$/)

    const request = calls[0].init || {}
    const headers = request.headers as Record<string, string>
    assert.equal(headers.Authorization.startsWith('Bearer '), true)
    assert.equal(headers[PROTOCOL_HEADER], PROTOCOL_V2)
    const body = JSON.parse(String(request.body || '{}'))
    assert.deepEqual(body, {
      fileId: 'file-1',
      relativePath: 'notes/today.md',
      fileName: 'today.md',
    })
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('resolveFileShareLink posts token to folder-scoped endpoint', async () => {
  const now = Math.floor(Date.now() / 1000)
  const plugin = makePlugin(makeAccessToken(now + 3600))

  const calls: Array<{ url: string; init?: RequestInit }> = []
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(
      JSON.stringify({
        folderId: 'folder-1',
        fileId: 'file-1',
        relativePath: 'notes/today.md',
        fileName: 'today.md',
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  }) as typeof fetch

  try {
    const result = await resolveFileShareLink(plugin as any, 'folder-1', 'file-token-123')
    assert.deepEqual(result, {
      folderId: 'folder-1',
      fileId: 'file-1',
      relativePath: 'notes/today.md',
      fileName: 'today.md',
    })
    assert.equal(calls.length, 1)
    assert.match(calls[0].url, /\/api\/folders\/folder-1\/file-links\/resolve$/)
    const body = JSON.parse(String(calls[0].init?.body || '{}'))
    assert.deepEqual(body, { token: 'file-token-123' })
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('previewFileShareLink fetches public metadata endpoint', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(
      JSON.stringify({
        folderId: 'folder-1',
        folderName: 'Roadmap',
        fileName: 'today.md',
        expiresAt: '2026-03-08T00:00:00.000Z',
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  }) as typeof fetch

  try {
    const result = await previewFileShareLink('https://teams.example.com', 'token-abc')
    assert.equal(result.folderId, 'folder-1')
    assert.equal(result.fileName, 'today.md')
    assert.equal(calls.length, 1)
    assert.match(calls[0].url, /\/api\/file-links\/preview\?token=token-abc$/)
    const headers = calls[0].init?.headers as Record<string, string>
    assert.equal(headers[PROTOCOL_HEADER], PROTOCOL_V2)
  } finally {
    globalThis.fetch = originalFetch
  }
})
