import type ObsidianTeamsPlugin from '../main'
import type {
  CreateInviteRequest,
  RedeemInviteRequest,
  RedeemResponse,
  InvitePreviewResponse,
  InviteResponse,
  CreateFileShareLinkRequest,
  CreateFileShareLinkResponse,
  FileShareLinkPreviewResponse,
  ResolveFileShareLinkRequest,
  ResolveFileShareLinkResponse,
  AccessTokenPayload,
  RefreshResponse,
  FolderMemberRecord,
  FolderInviteRecord,
  RemoveMemberResponse,
  RotateFolderKeyRequest,
  HostedSessionResponse,
  HostedOtpStartResponse,
  HostedAuthMeResponse,
  HostedCheckoutSessionResponse,
  HostedPortalSessionResponse,
} from '@obsidian-teams/shared'
import { PROTOCOL_HEADER, PROTOCOL_V2, HOSTED_SESSION_HEADER } from '@obsidian-teams/shared'
import { httpRequest, type HttpResponseLike } from './http'

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

function readErrorMessage(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null
  const data = payload as { error?: unknown; code?: unknown }
  const error = typeof data.error === 'string' ? data.error.trim() : ''
  const code = typeof data.code === 'string' ? data.code.trim() : ''
  if (code && error) return `${code}: ${error}`
  if (error) return error
  if (code) return code
  return null
}

async function readJson<T>(response: HttpResponseLike): Promise<T> {
  return (await response.json()) as T
}

async function readHttpErrorMessage(response: HttpResponseLike): Promise<string> {
  const payload = await response.json().catch(() => ({ error: 'Unknown error' } as const))
  return readErrorMessage(payload) ?? `HTTP ${response.status}`
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
    throw new Error(await readHttpErrorMessage(response))
  }

  const data = await readJson<RefreshResponse>(response)
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
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<InviteResponse>(response)
}

/** Request the server to generate a file share link for a specific file path. */
export async function createFileShareLink(
  plugin: ObsidianTeamsPlugin,
  folderId: string,
  payload: {
    fileId?: string | null
    relativePath: string
    fileName: string
    expiresInHours?: number
  }
): Promise<CreateFileShareLinkResponse> {
  const token = await getFolderBearerToken(plugin, folderId)
  const requestPayload: CreateFileShareLinkRequest = {
    relativePath: payload.relativePath,
    fileName: payload.fileName,
  }
  if (payload.fileId) requestPayload.fileId = payload.fileId
  if (typeof payload.expiresInHours === 'number') requestPayload.expiresInHours = payload.expiresInHours

  const response = await httpRequest(
    `${plugin.settings.serverUrl}/api/folders/${encodeURIComponent(folderId)}/file-links`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
      body: JSON.stringify(requestPayload),
    }
  )

  if (!response.ok) {
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<CreateFileShareLinkResponse>(response)
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
    throw new Error(await readHttpErrorMessage(response))
  }

  const payload = await readJson<RawFolderMembersResponse>(response)
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
    throw new Error(await readHttpErrorMessage(response))
  }

  const payload = await readJson<{ invites: FolderInviteRecord[] }>(response)
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
    throw new Error(await readHttpErrorMessage(response))
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
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<RemoveMemberResponse>(response)
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
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<RedeemResponse>(response)
}

/** Preview an invite token without consuming it. */
export async function previewInvite(
  serverUrl: string,
  inviteToken: string
): Promise<InvitePreviewResponse> {
  const normalizedToken = inviteToken.trim()
  if (!normalizedToken) {
    throw new Error('Missing token')
  }

  const response = await httpRequest(
    `${serverUrl}/api/invite/preview?token=${encodeURIComponent(normalizedToken)}`,
    {
      headers: {
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
    }
  )

  if (!response.ok) {
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<InvitePreviewResponse>(response)
}

/** Preview a file share link without revealing private path metadata. */
export async function previewFileShareLink(
  serverUrl: string,
  token: string
): Promise<FileShareLinkPreviewResponse> {
  const normalizedToken = token.trim()
  if (!normalizedToken) {
    throw new Error('Missing token')
  }

  const response = await httpRequest(
    `${serverUrl}/api/file-links/preview?token=${encodeURIComponent(normalizedToken)}`,
    {
      headers: {
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
    }
  )

  if (!response.ok) {
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<FileShareLinkPreviewResponse>(response)
}

/** Resolve a file share link into openable file target data for an authorized member. */
export async function resolveFileShareLink(
  plugin: ObsidianTeamsPlugin,
  folderId: string,
  token: string
): Promise<ResolveFileShareLinkResponse> {
  const normalizedToken = token.trim()
  if (!normalizedToken) {
    throw new Error('Missing token')
  }

  const bearerToken = await getFolderBearerToken(plugin, folderId)
  const payload: ResolveFileShareLinkRequest = {
    token: normalizedToken,
  }
  const response = await httpRequest(
    `${plugin.settings.serverUrl}/api/folders/${encodeURIComponent(folderId)}/file-links/resolve`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json',
        [PROTOCOL_HEADER]: PROTOCOL_V2,
      },
      body: JSON.stringify(payload),
    }
  )

  if (!response.ok) {
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<ResolveFileShareLinkResponse>(response)
}

function sessionExpiresSoon(expiresAt: string): boolean {
  if (!expiresAt) return true
  const expiryMs = new Date(expiresAt).getTime()
  if (!Number.isFinite(expiryMs)) return true
  return expiryMs - Date.now() <= 60_000
}

/** Refresh hosted billing snapshot for an existing hosted session. */
export async function silentHostedRelink(
  plugin: ObsidianTeamsPlugin,
  options: { force?: boolean } = {}
): Promise<boolean> {
  if (plugin.settings.deploymentMode !== 'hosted-service') {
    return false
  }

  const email = plugin.settings.hostedAccountEmail.trim().toLowerCase()
  if (!email) {
    return false
  }

  const hostedSessionToken = plugin.settings.hostedSessionToken
  if (!hostedSessionToken) {
    return false
  }

  const force = options.force ?? false
  const shouldRelink =
    force ||
    sessionExpiresSoon(plugin.settings.hostedSessionExpiresAt)

  if (!shouldRelink) {
    if (!plugin.settings.hostedSubscriptionStatus) {
      try {
        const snapshot = await getHostedAuthMe(plugin.settings.serverUrl, hostedSessionToken)
        plugin.settings.hostedSubscriptionStatus = snapshot.billing.subscriptionStatus || 'inactive'
        await plugin.saveSettings()
      } catch {
        // Ignore snapshot refresh failures for silent path.
      }
    }
    return true
  }

  try {
    const snapshot = await getHostedAuthMe(plugin.settings.serverUrl, hostedSessionToken)
    plugin.settings.hostedAccountEmail = snapshot.account.email
    plugin.settings.hostedSessionExpiresAt = snapshot.account.expiresAt
    plugin.settings.hostedSubscriptionStatus = snapshot.billing.subscriptionStatus || 'inactive'
    if (snapshot.account.displayName) {
      plugin.settings.hostedAccountDisplayName = snapshot.account.displayName
      if (!plugin.settings.displayName) {
        plugin.settings.displayName = snapshot.account.displayName
      }
    }
    await plugin.saveSettings()
    return true
  } catch {
    if (sessionExpiresSoon(plugin.settings.hostedSessionExpiresAt)) {
      plugin.settings.hostedSessionToken = ''
      plugin.settings.hostedSessionExpiresAt = ''
      plugin.settings.hostedSubscriptionStatus = ''
      await plugin.saveSettings()
    }
    return false
  }
}

export async function startHostedOtp(
  serverUrl: string,
  email: string
): Promise<HostedOtpStartResponse> {
  const response = await httpRequest(`${serverUrl}/api/hosted/auth/otp/start`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      [PROTOCOL_HEADER]: PROTOCOL_V2,
    },
    body: JSON.stringify({ email }),
  })

  if (!response.ok) {
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<HostedOtpStartResponse>(response)
}

export async function verifyHostedOtp(
  serverUrl: string,
  email: string,
  code: string,
  displayName: string
): Promise<HostedSessionResponse> {
  const response = await httpRequest(`${serverUrl}/api/hosted/auth/otp/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      [PROTOCOL_HEADER]: PROTOCOL_V2,
    },
    body: JSON.stringify({ email, code, displayName }),
  })

  if (!response.ok) {
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<HostedSessionResponse>(response)
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
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<HostedCheckoutSessionResponse>(response)
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
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<HostedPortalSessionResponse>(response)
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
    throw new Error(await readHttpErrorMessage(response))
  }

  return readJson<HostedAuthMeResponse>(response)
}
