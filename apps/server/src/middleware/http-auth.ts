import type { NextFunction, Request, Response } from 'express'
import type { AccessTokenPayload } from '@obsidian-teams/shared'
import { verifyAccessToken } from '../hooks/auth.js'
import { incrementSecurityMetric } from '../security/metrics.js'

export interface RequestActor {
  clientId: string
  displayName: string
  folderId: string
  role: AccessTokenPayload['role']
  tokenVersion: number
  jti?: string
  exp?: number
}

export type AuthenticatedRequest = Request & {
  actor?: RequestActor
}

export function extractBearerToken(req: Request): string | null {
  const header = req.headers.authorization
  if (!header) return null
  const [scheme, token] = header.split(/\s+/, 2)
  if (!scheme || !token) return null
  if (scheme.toLowerCase() !== 'bearer') return null
  return token
}

export function actorFromToken(token: string): RequestActor {
  const payload = verifyAccessToken(token)
  return {
    clientId: payload.clientId,
    displayName: payload.displayName,
    folderId: payload.folderId,
    role: payload.role,
    tokenVersion: payload.tokenVersion || 0,
    jti: payload.jti,
    exp: payload.exp,
  }
}

export function requireHttpAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const token = extractBearerToken(req)
  if (!token) {
    incrementSecurityMetric('auth_denied_count')
    res.status(401).json({ error: 'Missing bearer token' })
    return
  }

  try {
    req.actor = actorFromToken(token)
    next()
  } catch {
    incrementSecurityMetric('auth_denied_count')
    res.status(401).json({ error: 'Invalid or expired access token' })
  }
}
