/** Configuration stored in .shared.json inside each shared folder */
export interface SharedFolderConfig {
  folderId: string
  serverUrl: string
  displayName: string
  members: MemberInfo[]
  createdAt: string
}

/** A member of a shared folder */
export interface MemberInfo {
  clientId: string
  name: string
  role: 'owner' | 'editor'
}

/** An entry in the file tree Y.Map */
export interface FileTreeEntry {
  /** Stable ID for this logical file across path renames/moves */
  fileId: string
  path: string
  type: 'file' | 'directory'
  /** SHA-256 hash for blob-synced files */
  contentHash?: string
  /** File size in bytes */
  size?: number
  /** Last modified ISO 8601 timestamp */
  mtime: string
  /** How this file is synced */
  syncMode: 'crdt' | 'blob' | 'canvas'
}

/** JWT access token payload */
export interface AccessTokenPayload {
  clientId: string
  displayName: string
  folderId: string
  role: 'owner' | 'editor'
  type: 'access'
  /** JWT standard claim: audience */
  aud?: string | string[]
  /** JWT standard claim: issuer */
  iss?: string
  /** JWT standard claim: subject */
  sub?: string
  /** JWT standard claim: token identifier */
  jti?: string
  /** Server-authoritative member token version for forced invalidation */
  tokenVersion?: number
  /** JWT standard claim: expiration time (seconds since epoch) */
  exp?: number
  /** JWT standard claim: issued-at time (seconds since epoch) */
  iat?: number
}

/** Server response when creating an invite */
export interface InviteResponse {
  inviteToken: string
  inviteUrl: string
  ownerAccessToken?: string
  ownerRefreshToken?: string
}

/** Server request payload when creating an invite. */
export interface CreateInviteRequest {
  folderId: string
  folderName: string
  ownerClientId: string
  ownerDisplayName: string
  role?: 'editor'
  expiresInHours?: number
  maxUses?: number
  inviteeLabel?: string
}

/** Server request payload when redeeming an invite. */
export interface RedeemInviteRequest {
  inviteToken: string
  clientId: string
  displayName: string
  hostedSessionToken?: string
}

/** Server response when redeeming an invite */
export interface RedeemResponse {
  accessToken: string
  refreshToken: string
  folderId: string
  folderName: string
  serverUrl: string
}

/** Server response when previewing an invite without consuming it. */
export interface InvitePreviewResponse {
  folderName: string
  ownerDisplayName: string
  expiresAt: string | null
  remainingUses: number
}

/** Server request payload when creating a file share link. */
export interface CreateFileShareLinkRequest {
  fileId?: string
  relativePath: string
  fileName: string
  expiresInHours?: number
}

/** Server response payload when creating a file share link. */
export interface CreateFileShareLinkResponse {
  shareToken: string
  shareUrl: string
  expiresAt: string
}

/** Public metadata for a file share link without revealing file paths. */
export interface FileShareLinkPreviewResponse {
  folderId: string
  folderName: string
  fileName: string
  expiresAt: string
}

/** Server request payload when resolving a file share link inside a folder. */
export interface ResolveFileShareLinkRequest {
  token: string
}

/** Authenticated response payload used to open a shared file. */
export interface ResolveFileShareLinkResponse {
  folderId: string
  fileId: string | null
  relativePath: string
  fileName: string
}

export interface HostedAccountProfile {
  id: string
  email: string
  displayName: string
  status: string
}

export interface HostedSessionResponse {
  account: HostedAccountProfile
  sessionToken: string
  expiresAt: string
}

export interface HostedOtpStartResponse {
  success: true
}

export interface HostedAccountBillingRecord {
  subscriptionStatus: string
  priceCents: number
  storageCapBytes: number
  maxFileSizeBytes: number
  currentPeriodEnd: string | null
  cancelAtPeriodEnd: boolean
}

export interface HostedAccountUsageRecord {
  ownedFolderCount: number
  ownedStorageBytes: number
}

export interface HostedAuthMeResponse {
  account: HostedAccountProfile & {
    expiresAt: string
  }
  billing: HostedAccountBillingRecord
  usage: HostedAccountUsageRecord
}

export interface HostedCheckoutSessionResponse {
  checkoutSessionId: string
  checkoutUrl: string
}

export interface HostedPortalSessionResponse {
  portalUrl: string
}

export type HostedBillingErrorCode = 'subscription_already_active' | 'subscription_requires_portal'

export type HostedEntitlementCode =
  | 'hosted_session_required'
  | 'subscription_inactive'
  | 'subscription_past_due'
  | 'storage_limit_reached'
  | 'file_size_limit_exceeded'

/** Server response when refreshing an access token */
export interface RefreshResponse {
  accessToken: string
  refreshToken: string
}

/** Server response when issuing a one-time WebSocket ticket. */
export interface WsTicketResponse {
  ticket: string
  expiresAt: string
}

/** Member entry returned by folder member listing APIs. */
export interface FolderMemberRecord {
  clientId: string
  displayName: string
  inviteeLabel: string | null
  role: 'owner' | 'editor'
  tokenVersion: number
  joinedAt: string
}

/** Response payload for folder member listings. */
export interface FolderMembersResponse {
  members: FolderMemberRecord[]
}

/** Invite status derived from lifecycle fields on the server. */
export type FolderInviteStatus = 'active' | 'revoked' | 'consumed' | 'expired'

/** Invite entry returned by folder invite listing APIs. */
export interface FolderInviteRecord {
  tokenHash: string
  inviteeLabel: string | null
  role: 'editor'
  createdAt: string
  createdBy: string | null
  expiresAt: string | null
  maxUses: number
  useCount: number
  consumedAt: string | null
  consumedBy: string | null
  revokedAt: string | null
  revokedBy: string | null
  status: FolderInviteStatus
}

/** Response payload for folder invite listings. */
export interface FolderInvitesResponse {
  invites: FolderInviteRecord[]
}

/** Response payload for member removal requests. */
export interface RemoveMemberResponse {
  success: true
  closedWsSessions: number
  revokedAccessTokens: number
  revokedRefreshTokens: number
  rotatedEpoch: number | null
  rekeyRequired: boolean
}
