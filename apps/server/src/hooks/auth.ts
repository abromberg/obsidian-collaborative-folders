import jwt, { type JwtPayload, type SignOptions } from 'jsonwebtoken'
import crypto from 'crypto'
import { type AccessTokenPayload } from '@obsidian-teams/shared'

function resolveJwtSecret(): string {
  const value = process.env.JWT_SECRET?.trim() || ''
  if (!value) {
    throw new Error('JWT_SECRET is required')
  }
  if (value.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters')
  }
  return value
}

const JWT_SECRET = resolveJwtSecret()
const JWT_ISSUER = process.env.JWT_ISSUER || 'obsidian-teams'
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'obsidian-teams-client'
const ACCESS_TOKEN_TTL = (process.env.ACCESS_TOKEN_TTL || '30m') as SignOptions['expiresIn']
const INVITE_TOKEN_RANDOM_BYTES = 10
const INVITE_TOKEN_SLUG_MAX = 32

export function getJwtSecret(): string {
  return JWT_SECRET
}

export function getJwtIssuer(): string {
  return JWT_ISSUER
}

export function getJwtAudience(): string {
  return JWT_AUDIENCE
}

function requireAccessPayload(payload: string | JwtPayload): AccessTokenPayload {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid access token payload')
  }
  if (payload.type !== 'access') {
    throw new Error('Invalid token type')
  }
  if (
    typeof payload.folderId !== 'string' ||
    typeof payload.clientId !== 'string' ||
    typeof payload.displayName !== 'string' ||
    (payload.role !== 'owner' && payload.role !== 'editor') ||
    typeof payload.tokenVersion !== 'number'
  ) {
    throw new Error('Invalid access token fields')
  }

  return payload as AccessTokenPayload
}

function toInviteSlug(folderName: string): string {
  const slug = folderName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, INVITE_TOKEN_SLUG_MAX)
    .replace(/-+$/g, '')

  return slug || 'shared-folder'
}

export function verifyAccessToken(
  token: string,
  options: { ignoreExpiration?: boolean } = {}
): AccessTokenPayload {
  const payload = jwt.verify(token, JWT_SECRET, {
    audience: JWT_AUDIENCE,
    issuer: JWT_ISSUER,
    ignoreExpiration: options.ignoreExpiration ?? false,
  })
  const accessPayload = requireAccessPayload(payload)

  if (accessPayload.sub !== accessPayload.clientId) {
    throw new Error('Invalid token subject')
  }
  if (!accessPayload.jti) {
    throw new Error('Missing token ID')
  }

  return accessPayload
}

/** Generate an access token for a folder member */
export function generateAccessToken(
  clientId: string,
  displayName: string,
  folderId: string,
  role: 'owner' | 'editor',
  tokenVersion: number
): string {
  const payload: AccessTokenPayload = {
    clientId,
    displayName,
    folderId,
    role,
    tokenVersion,
    type: 'access',
  }
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    subject: clientId,
    jwtid: crypto.randomUUID(),
  })
}

/** Generate a single-use invite token */
export function generateInviteToken(
  folderName: string
): string {
  const slug = toInviteSlug(folderName)
  const randomHex = crypto.randomBytes(INVITE_TOKEN_RANDOM_BYTES).toString('hex')
  return `${slug}-${randomHex}`
}
