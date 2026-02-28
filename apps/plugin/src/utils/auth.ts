import type ObsidianTeamsPlugin from '../main'
import type {
  CreateInviteRequest,
  RedeemInviteRequest,
  RedeemResponse,
  InviteResponse,
  AccessTokenPayload,
  RefreshResponse,
  FolderMemberRecord,
  FolderInviteRecord,
  RemoveMemberResponse,
  RotateFolderKeyRequest,
  HostedSessionResponse,
  HostedAuthMeResponse,
  HostedCheckoutSessionResponse,
  HostedPortalSessionResponse,
} from '@obsidian-teams/shared'
import { PROTOCOL_HEADER, PROTOCOL_V2, HOSTED_SESSION_HEADER } from '@obsidian-teams/shared'
import { httpRequest } from './http'

const DEFAULT_REFRESH_WINDOW_MS = 5 * 60 * 1000
const refreshInFlightByFolder = new Map<string, Promise<RefreshResponse>>()

interface RawFolderMemberRecord {
  client_id: string
  display_name: string
  invitee_label: string | null
  role: 'owner' | 'editor'
  token_version: number
  joined_at: string
}

interface RawFolderMembersResponse {
  members: RawFolderMemberRecord[]
}

/** Store an access token for a folder */
export async function storeAccessToken(
  plugin: ObsidianTeamsPlugin,
  folderId: string,
  token: string
): Promise<void> {
  plugin.settings.folderTokens[folderId] = token
  await plugin.saveSettings()
}

/** Store a refresh token for a folder */
export async function storeRefreshToken(
  plugin: ObsidianTeamsPlugin,
  folderId: string,
  token: string
): Promise<void> {
  plugin.settings.folderRefreshTokens[folderId] = token
  await plugin.saveSettings()
}

/** Get the access token for a folder */
export function getAccessToken(
  plugin: ObsidianTeamsPlugin,
  folderId: string
): string | null {
  return plugin.settings.folderTokens[folderId] || null
}

/** Get the refresh token for a folder */
export function getRefreshToken(
  plugin: ObsidianTeamsPlugin,
  folderId: string
): string | null {
  return plugin.settings.folderRefreshTokens[folderId] || null
}

/** Decode a JWT payload without verification (client-side convenience only). */
function decodeJwtPayload<T>(token: string): T | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const pad = (4 - (base64.length % 4)) % 4
    const padded = base64 + '='.repeat(pad)
    return JSON.parse(atob(padded)) as T
  } catch {
    return null
  }
}

/** Decode an access token payload for local UX logic. */
export function decodeAccessToken(token: string): AccessTokenPayload | null {
  const payload = decodeJwtPayload<Partial<AccessTokenPayload>>(token)
  if (!payload) return null
  if (payload.type !== 'access') return null
  if (!payload.folderId || !payload.clientId || !payload.role || !payload.displayName) return null
  return payload as AccessTokenPayload
}

/** Return true when the token should be refreshed soon. */
export function shouldRefreshSoon(
  payload: AccessTokenPayload,
  windowMs = DEFAULT_REFRESH_WINDOW_MS
): boolean {
  if (!payload.exp) return false
  return payload.exp * 1000 - Date.now() <= windowMs
}

/** Return true when the token is already expired. */
export function isTokenExpired(payload: AccessTokenPayload): boolean {
  if (!payload.exp) return false
  return payload.exp * 1000 <= Date.now()
}

/** Read the current member role for a folder from the stored access token. */
export function getFolderRole(
  plugin: ObsidianTeamsPlugin,
  folderId: string
): AccessTokenPayload['role'] | null {
  const token = getAccessToken(plugin, folderId)
  if (!token) return null
  const payload = decodeAccessToken(token)
  if (!payload || payload.folderId !== folderId) return null
  return payload.role
}

/** Remove access token for a folder */
export async function removeAccessToken(
  plugin: ObsidianTeamsPlugin,
  folderId: string
): Promise<void> {
  delete plugin.settings.folderTokens[folderId]
  delete plugin.settings.folderRefreshTokens[folderId]
  await plugin.saveSettings()
}

/** Request the server to refresh an access token. */
export async function refreshAccessToken(
  serverUrl: string,
  refreshToken: string
): Promise<RefreshResponse> {
  const response = await httpRequest(`${serverUrl}/api/auth/refresh`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      [PROTOCOL_HEADER]: PROTOCOL_V2,
    },
    body: JSON.stringify({ refreshToken }),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  const data = (await response.json()) as RefreshResponse
  if (!data.accessToken || !data.refreshToken) {
    throw new Error('Refresh response missing accessToken or refreshToken')
  }
  return data
}

/** Deduplicate concurrent refresh requests per folder in this plugin instance. */
export function refreshAccessTokenDeduped(
  plugin: ObsidianTeamsPlugin,
  folderId: string,
  refreshToken: string
): Promise<RefreshResponse> {
  const existing = refreshInFlightByFolder.get(folderId)
  if (existing) return existing

  const request = refreshAccessToken(plugin.settings.serverUrl, refreshToken).finally(() => {
    refreshInFlightByFolder.delete(folderId)
  })

  refreshInFlightByFolder.set(folderId, request)
  return request
}

/**
 * Return a token for provider auth. Refresh when close to expiry or forced by caller.
 * Falls back to the current token when refresh fails but the token is still unexpired.
 */
export async function getOrRefreshToken(
  plugin: ObsidianTeamsPlugin,
  folderId: string,
  options: { forceRefresh?: boolean } = {}
): Promise<string | null> {
  const accessToken = getAccessToken(plugin, folderId)
  const refreshToken = getRefreshToken(plugin, folderId)
  if (!accessToken) return null
  if (!refreshToken) return accessToken

  const payload = decodeAccessToken(accessToken)
  if (!payload) return accessToken
  if (payload.folderId !== folderId) return accessToken

  const forceRefresh = options.forceRefresh ?? false
  const shouldRefresh = forceRefresh || shouldRefreshSoon(payload)
  if (!shouldRefresh) return accessToken

  try {
    const refreshed = await refreshAccessTokenDeduped(plugin, folderId, refreshToken)
    plugin.settings.folderTokens[folderId] = refreshed.accessToken
    plugin.settings.folderRefreshTokens[folderId] = refreshed.refreshToken
    await plugin.saveSettings()
    return refreshed.accessToken
  } catch (error) {
    if (!forceRefresh && !isTokenExpired(payload)) {
      return accessToken
    }
    throw error
  }
}

/** Request the server to generate an invite link */
export async function createInvite(
  serverUrl: string,
  folderId: string,
  folderName: string,
  ownerClientId: string,
  ownerDisplayName: string,
  accessToken?: string | null,
  options: {
    hostedSessionToken?: string
    expiresInHours?: number
    maxUses?: number
    inviteeLabel?: string
  } = {}
): Promise<InviteResponse> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    [PROTOCOL_HEADER]: PROTOCOL_V2,
  }
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`
  }
  if (options.hostedSessionToken) {
    headers[HOSTED_SESSION_HEADER] = options.hostedSessionToken
  }

  const payload: CreateInviteRequest = {
    folderId,
    folderName,
    ownerClientId,
    ownerDisplayName,
  }
  if (typeof options.expiresInHours === 'number') payload.expiresInHours = options.expiresInHours
  if (typeof options.maxUses === 'number') payload.maxUses = options.maxUses
  if (typeof options.inviteeLabel === 'string' && options.inviteeLabel.trim()) {
    payload.inviteeLabel = options.inviteeLabel.trim()
  }

  const response = await httpRequest(`${serverUrl}/api/invite`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  return response.json()
}

async function getFolderBearerToken(plugin: ObsidianTeamsPlugin, folderId: string): Promise<string> {
  const token = await getOrRefreshToken(plugin, folderId)
  if (!token) {
    throw new Error('Missing access token for this shared folder')
  }
  return token
}

/** List members in a folder from the server-authoritative membership table. */
export async function listFolderMembers(
  plugin: ObsidianTeamsPlugin,
  folderId: string
): Promise<FolderMemberRecord[]> {
  const token = await getFolderBearerToken(plugin, folderId)
  const response = await httpRequest(
    `${plugin.settings.serverUrl}/api/folders/${encodeURIComponent(folderId)}/members`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
    }
  )

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  const payload = (await response.json()) as RawFolderMembersResponse
  return payload.members.map((member) => ({
    clientId: member.client_id,
    displayName: member.display_name,
    inviteeLabel: member.invitee_label,
    role: member.role,
    tokenVersion: member.token_version,
    joinedAt: member.joined_at,
  }))
}

/** List invite records for a folder. Owner-only on the server. */
export async function listFolderInvites(
  plugin: ObsidianTeamsPlugin,
  folderId: string
): Promise<FolderInviteRecord[]> {
  const token = await getFolderBearerToken(plugin, folderId)
  const response = await httpRequest(
    `${plugin.settings.serverUrl}/api/folders/${encodeURIComponent(folderId)}/invites`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
    }
  )

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  const payload = (await response.json()) as { invites: FolderInviteRecord[] }
  return payload.invites
}

/** Revoke an invite token hash. Owner-only on the server. */
export async function revokeFolderInvite(
  plugin: ObsidianTeamsPlugin,
  folderId: string,
  tokenHash: string
): Promise<void> {
  const token = await getFolderBearerToken(plugin, folderId)
  const response = await httpRequest(
    `${plugin.settings.serverUrl}/api/folders/${encodeURIComponent(folderId)}/invites/${encodeURIComponent(tokenHash)}`,
    {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
    }
  )

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }
}

/** Remove a folder member while sending a rotate payload for secure rekeying. */
export async function removeFolderMember(
  plugin: ObsidianTeamsPlugin,
  folderId: string,
  clientId: string,
  rotate: RotateFolderKeyRequest
): Promise<RemoveMemberResponse> {
  const token = await getFolderBearerToken(plugin, folderId)
  const response = await httpRequest(
    `${plugin.settings.serverUrl}/api/folders/${encodeURIComponent(folderId)}/members/${encodeURIComponent(clientId)}`,
    {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
      body: JSON.stringify({ rotate }),
    }
  )

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  return (await response.json()) as RemoveMemberResponse
}

/** Redeem an invite token to join a shared folder */
export async function redeemInvite(
  serverUrl: string,
  inviteToken: string,
  clientId: string,
  displayName: string,
  hostedSessionToken?: string
): Promise<RedeemResponse> {
  const payload: RedeemInviteRequest = { inviteToken, clientId, displayName }
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    [PROTOCOL_HEADER]: PROTOCOL_V2,
  }
  if (hostedSessionToken) {
    payload.hostedSessionToken = hostedSessionToken
    headers[HOSTED_SESSION_HEADER] = hostedSessionToken
  }

  const response = await httpRequest(`${serverUrl}/api/invite/redeem`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  return response.json()
}

export async function createHostedSession(
  serverUrl: string,
  email: string,
  displayName: string
): Promise<HostedSessionResponse> {
  const response = await httpRequest(`${serverUrl}/api/hosted/auth/session`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      [PROTOCOL_HEADER]: PROTOCOL_V2,
    },
    body: JSON.stringify({ email, displayName }),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  return (await response.json()) as HostedSessionResponse
}

export async function createHostedCheckoutSession(
  serverUrl: string,
  hostedSessionToken: string,
  options: {
    successUrl?: string
    cancelUrl?: string
  } = {}
): Promise<HostedCheckoutSessionResponse> {
  const payload: { successUrl?: string; cancelUrl?: string } = {}
  const successUrl = options.successUrl?.trim()
  const cancelUrl = options.cancelUrl?.trim()
  if (successUrl) payload.successUrl = successUrl
  if (cancelUrl) payload.cancelUrl = cancelUrl

  const response = await httpRequest(`${serverUrl}/api/hosted/billing/checkout-session`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      [PROTOCOL_HEADER]: PROTOCOL_V2,
      [HOSTED_SESSION_HEADER]: hostedSessionToken,
    },
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  return (await response.json()) as HostedCheckoutSessionResponse
}

export async function createHostedPortalSession(
  serverUrl: string,
  hostedSessionToken: string,
  options: {
    returnUrl?: string
  } = {}
): Promise<HostedPortalSessionResponse> {
  const payload: { returnUrl?: string } = {}
  const returnUrl = options.returnUrl?.trim()
  if (returnUrl) payload.returnUrl = returnUrl

  const response = await httpRequest(`${serverUrl}/api/hosted/billing/portal-session`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      [PROTOCOL_HEADER]: PROTOCOL_V2,
      [HOSTED_SESSION_HEADER]: hostedSessionToken,
    },
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  return (await response.json()) as HostedPortalSessionResponse
}

export async function getHostedAuthMe(
  serverUrl: string,
  hostedSessionToken: string
): Promise<HostedAuthMeResponse> {
  const response = await httpRequest(`${serverUrl}/api/hosted/auth/me`, {
    headers: {
      [PROTOCOL_HEADER]: PROTOCOL_V2,
      [HOSTED_SESSION_HEADER]: hostedSessionToken,
    },
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }

  return (await response.json()) as HostedAuthMeResponse
}
