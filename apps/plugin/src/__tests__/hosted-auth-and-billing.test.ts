import test from 'node:test'
import assert from 'node:assert/strict'
import {
  startHostedOtp,
  verifyHostedOtp,
  createHostedCheckoutSession,
  createHostedPortalSession,
  getHostedAuthMe,
  createInvite,
  previewInvite,
  redeemInvite,
  silentHostedRelink,
} from '../utils/auth.js'
import { HOSTED_SESSION_HEADER, PROTOCOL_HEADER, PROTOCOL_V2 } from '@obsidian-teams/shared'

test('startHostedOtp posts email identity to hosted auth OTP start endpoint', async () => {
  const originalFetch = globalThis.fetch
  const calls: Array<{ url: string; init?: RequestInit }> = []

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }) as typeof fetch

  try {
    const response = await startHostedOtp('https://teams.example.com', 'owner@example.com')
    assert.equal(response.success, true)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].url, 'https://teams.example.com/api/hosted/auth/otp/start')

    const headers = calls[0].init?.headers as Record<string, string>
    assert.equal(headers[PROTOCOL_HEADER], PROTOCOL_V2)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('verifyHostedOtp posts OTP code and returns hosted session payload', async () => {
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
    const response = await verifyHostedOtp(
      'https://teams.example.com',
      'owner@example.com',
      '123456',
      'Owner'
    )
    assert.equal(response.account.email, 'owner@example.com')
    assert.equal(calls.length, 1)
    assert.equal(calls[0].url, 'https://teams.example.com/api/hosted/auth/otp/verify')

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

test('previewInvite fetches invite metadata without consuming token', async () => {
  const originalFetch = globalThis.fetch
  const calls: Array<{ url: string; init?: RequestInit }> = []

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(
      JSON.stringify({
        folderName: 'Shared Folder',
        ownerDisplayName: 'Owner',
        expiresAt: '2026-03-01T00:00:00.000Z',
        remainingUses: 1,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  try {
    const payload = await previewInvite('https://teams.example.com', 'invite-token-1')
    assert.equal(payload.folderName, 'Shared Folder')
    assert.equal(calls.length, 1)
    assert.equal(calls[0].url, 'https://teams.example.com/api/invite/preview?token=invite-token-1')
    const headers = calls[0].init?.headers as Record<string, string>
    assert.equal(headers[PROTOCOL_HEADER], PROTOCOL_V2)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('silentHostedRelink refreshes hosted billing snapshot for existing hosted session', async () => {
  const originalFetch = globalThis.fetch

  globalThis.fetch = (async () => {
    return new Response(
      JSON.stringify({
        account: {
          id: 'acct-1',
          email: 'owner@example.com',
          displayName: 'Owner',
          status: 'active',
          expiresAt: '2026-04-01T00:00:00.000Z',
        },
        billing: {
          subscriptionStatus: 'active',
          priceCents: 900,
          storageCapBytes: 3221225472,
          maxFileSizeBytes: 26214400,
          currentPeriodEnd: null,
          cancelAtPeriodEnd: false,
        },
        usage: {
          ownedFolderCount: 0,
          ownedStorageBytes: 0,
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  const pluginStub = {
    settings: {
      deploymentMode: 'hosted-service' as const,
      hostedAccountEmail: 'owner@example.com',
      hostedAccountDisplayName: '',
      hostedOtpCode: '',
      hostedSessionToken: 'session-token-1',
      hostedSessionExpiresAt: '2026-01-01T00:00:00.000Z',
      hostedSubscriptionStatus: '',
      displayName: 'Owner',
      serverUrl: 'https://teams.example.com',
      folderTokens: {},
      folderRefreshTokens: {},
    },
    saveSettings: async () => {},
  }

  try {
    const relinked = await silentHostedRelink(pluginStub as any, { force: true })
    assert.equal(relinked, true)
    assert.equal(pluginStub.settings.hostedSessionToken, 'session-token-1')
    assert.equal(pluginStub.settings.hostedSessionExpiresAt, '2026-04-01T00:00:00.000Z')
    assert.equal(pluginStub.settings.hostedSubscriptionStatus, 'active')
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('silentHostedRelink returns false when hosted session token is missing', async () => {
  const pluginStub = {
    settings: {
      deploymentMode: 'hosted-service' as const,
      hostedAccountEmail: 'owner@example.com',
      hostedAccountDisplayName: '',
      hostedOtpCode: '',
      hostedSessionToken: '',
      hostedSessionExpiresAt: '',
      hostedSubscriptionStatus: '',
      displayName: 'Owner',
      serverUrl: 'https://teams.example.com',
      folderTokens: {},
      folderRefreshTokens: {},
    },
    saveSettings: async () => {},
  }

  const relinked = await silentHostedRelink(pluginStub as any, { force: true })
  assert.equal(relinked, false)
})

test('hosted billing helpers call checkout, portal, and account snapshot endpoints', async () => {
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

    if (String(url).includes('/portal-session')) {
      return new Response(
        JSON.stringify({ portalUrl: 'https://billing.stripe.test/portal' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    }

    return new Response(
      JSON.stringify({
        account: {
          id: 'acct-1',
          email: 'owner@example.com',
          displayName: 'Owner',
          status: 'active',
          expiresAt: '2026-03-01T00:00:00.000Z',
        },
        billing: {
          subscriptionStatus: 'active',
          priceCents: 900,
          storageCapBytes: 3221225472,
          maxFileSizeBytes: 26214400,
          currentPeriodEnd: null,
          cancelAtPeriodEnd: false,
        },
        usage: {
          ownedFolderCount: 0,
          ownedStorageBytes: 0,
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    )
  }) as typeof fetch

  try {
    const checkout = await createHostedCheckoutSession('https://teams.example.com', 'session-token-1', {
      successUrl: 'https://teams.example.com/api/hosted/billing/return?status=success',
      cancelUrl: 'https://teams.example.com/api/hosted/billing/return?status=cancel',
    })
    const portal = await createHostedPortalSession('https://teams.example.com', 'session-token-1', {
      returnUrl: 'https://teams.example.com/api/hosted/billing/return?status=return',
    })
    const me = await getHostedAuthMe('https://teams.example.com', 'session-token-1')

    assert.equal(checkout.checkoutSessionId, 'cs_1')
    assert.equal(portal.portalUrl, 'https://billing.stripe.test/portal')
    assert.equal(me.billing.subscriptionStatus, 'active')

    const checkoutBody = JSON.parse(String(calls[0].init?.body)) as Record<string, unknown>
    assert.deepEqual(checkoutBody, {
      successUrl: 'https://teams.example.com/api/hosted/billing/return?status=success',
      cancelUrl: 'https://teams.example.com/api/hosted/billing/return?status=cancel',
    })

    const portalBody = JSON.parse(String(calls[1].init?.body)) as Record<string, unknown>
    assert.deepEqual(portalBody, {
      returnUrl: 'https://teams.example.com/api/hosted/billing/return?status=return',
    })

    const meHeaders = calls[2].init?.headers as Record<string, string>
    assert.equal(meHeaders[PROTOCOL_HEADER], PROTOCOL_V2)
    assert.equal(meHeaders[HOSTED_SESSION_HEADER], 'session-token-1')
  } finally {
    globalThis.fetch = originalFetch
  }
})
