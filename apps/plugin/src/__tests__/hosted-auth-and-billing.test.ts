import test from 'node:test'
import assert from 'node:assert/strict'
import {
  createHostedSession,
  createHostedCheckoutSession,
  createHostedPortalSession,
  createInvite,
  redeemInvite,
} from '../utils/auth.js'
import { HOSTED_SESSION_HEADER, PROTOCOL_HEADER, PROTOCOL_V2 } from '@obsidian-teams/shared'

test('createHostedSession posts account identity to hosted auth endpoint', async () => {
  const originalFetch = globalThis.fetch
  const calls: Array<{ url: string; init?: RequestInit }> = []

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(
      JSON.stringify({
        account: {
          id: 'acct-1',
          email: 'owner@example.com',
          displayName: 'Owner',
          status: 'active',
        },
        sessionToken: 'session-token-1',
        expiresAt: '2026-03-01T00:00:00.000Z',
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  }) as typeof fetch

  try {
    const response = await createHostedSession('https://teams.example.com', 'owner@example.com', 'Owner')
    assert.equal(response.account.email, 'owner@example.com')
    assert.equal(calls.length, 1)
    assert.equal(calls[0].url, 'https://teams.example.com/api/hosted/auth/session')

    const headers = calls[0].init?.headers as Record<string, string>
    assert.equal(headers[PROTOCOL_HEADER], PROTOCOL_V2)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('createInvite and redeemInvite include hosted session context when provided', async () => {
  const originalFetch = globalThis.fetch
  const calls: Array<{ url: string; init?: RequestInit }> = []

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    if (String(url).endsWith('/api/invite')) {
      return new Response(
        JSON.stringify({
          inviteToken: 'token-1',
          inviteUrl: 'https://teams.example.com/api/invite/redeem?token=token-1',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    }

    return new Response(
      JSON.stringify({
        accessToken: 'access-1',
        refreshToken: 'refresh-1',
        folderId: 'folder-1',
        folderName: 'Shared Folder',
        serverUrl: 'https://teams.example.com',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  try {
      await createInvite(
        'https://teams.example.com',
        'folder-1',
        'Shared Folder',
      'owner-client-1',
      'Owner',
        null,
        {
          hostedSessionToken: 'hosted-session-1',
        }
      )

    await redeemInvite(
      'https://teams.example.com',
      'invite-token-1',
      'collab-client-1',
      'Collaborator',
      'hosted-session-1'
    )

    assert.equal(calls.length, 2)

    const inviteHeaders = calls[0].init?.headers as Record<string, string>
    const inviteBody = JSON.parse(String(calls[0].init?.body)) as { folderId: string }
    assert.equal(inviteHeaders[HOSTED_SESSION_HEADER], 'hosted-session-1')
    assert.equal(inviteBody.folderId, 'folder-1')

    const redeemHeaders = calls[1].init?.headers as Record<string, string>
    const redeemBody = JSON.parse(String(calls[1].init?.body)) as { hostedSessionToken?: string }
    assert.equal(redeemHeaders[HOSTED_SESSION_HEADER], 'hosted-session-1')
    assert.equal(redeemBody.hostedSessionToken, 'hosted-session-1')
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('hosted billing helpers call checkout and portal endpoints', async () => {
  const originalFetch = globalThis.fetch
  const calls: Array<{ url: string; init?: RequestInit }> = []

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    if (String(url).includes('/checkout-session')) {
      return new Response(
        JSON.stringify({ checkoutSessionId: 'cs_1', checkoutUrl: 'https://checkout.stripe.test/session' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    }

    return new Response(
      JSON.stringify({ portalUrl: 'https://billing.stripe.test/portal' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  try {
    const checkout = await createHostedCheckoutSession('https://teams.example.com', 'session-token-1')
    const portal = await createHostedPortalSession('https://teams.example.com', 'session-token-1')

    assert.equal(checkout.checkoutSessionId, 'cs_1')
    assert.equal(portal.portalUrl, 'https://billing.stripe.test/portal')

    const checkoutBody = JSON.parse(String(calls[0].init?.body)) as Record<string, unknown>
    assert.deepEqual(checkoutBody, {})
  } finally {
    globalThis.fetch = originalFetch
  }
})
