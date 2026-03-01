import test from 'node:test'
import assert from 'node:assert/strict'
import { type AccessTokenPayload } from '@obsidian-teams/shared'
import { getOrRefreshToken } from '../utils/auth.js'

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

function makePlugin(accessToken: string, refreshToken: string): PluginStub {
  return {
    settings: {
      serverUrl: 'https://teams.example.com',
      folderTokens: { 'folder-1': accessToken },
      folderRefreshTokens: { 'folder-1': refreshToken },
    },
    saveSettings: async () => {},
  }
}

test('getOrRefreshToken rotates token when access token is near expiry', async () => {
  const now = Math.floor(Date.now() / 1000)
  const staleAccessToken = makeAccessToken(now + 30)
  const freshAccessToken = makeAccessToken(now + 3600)
  const plugin = makePlugin(staleAccessToken, 'refresh-1')

  const fetchCalls: Array<{ url: string; init?: RequestInit }> = []
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    fetchCalls.push({ url: String(url), init })
    return new Response(
      JSON.stringify({
        accessToken: freshAccessToken,
        refreshToken: 'refresh-2',
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  }) as typeof fetch

  try {
    const token = await getOrRefreshToken(plugin as any, 'folder-1')
    assert.equal(token, freshAccessToken)
    assert.equal(plugin.settings.folderTokens['folder-1'], freshAccessToken)
    assert.equal(plugin.settings.folderRefreshTokens['folder-1'], 'refresh-2')
    assert.equal(fetchCalls.length, 1)
    assert.match(fetchCalls[0].url, /\/api\/auth\/refresh$/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('getOrRefreshToken falls back to existing token when refresh fails but token is not expired', async () => {
  const now = Math.floor(Date.now() / 1000)
  const staleButUsableAccessToken = makeAccessToken(now + 60)
  const plugin = makePlugin(staleButUsableAccessToken, 'refresh-1')

  const originalFetch = globalThis.fetch
  globalThis.fetch = (async () => {
    throw new Error('network down')
  }) as typeof fetch

  try {
    const token = await getOrRefreshToken(plugin as any, 'folder-1')
    assert.equal(token, staleButUsableAccessToken)
    assert.equal(plugin.settings.folderTokens['folder-1'], staleButUsableAccessToken)
    assert.equal(plugin.settings.folderRefreshTokens['folder-1'], 'refresh-1')
  } finally {
    globalThis.fetch = originalFetch
  }
})
