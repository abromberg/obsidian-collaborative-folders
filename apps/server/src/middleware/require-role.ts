import type { NextFunction, Response } from 'express'
import type { AuthenticatedRequest, RequestActor } from './http-auth.js'
import { getDb } from '../db/schema.js'
import { getMemberAuthRow, isTokenRevoked } from '../security/authz.js'
import { incrementSecurityMetric } from '../security/metrics.js'
import { writeAuditEvent } from '../security/audit.js'

type FolderRole = RequestActor['role']

const ROLE_RANK: Record<FolderRole, number> = {
  owner: 2,
  editor: 1,
}

function isRoleAllowed(actorRole: FolderRole, allowed: FolderRole[]): boolean {
  return allowed.some((role) => ROLE_RANK[actorRole] >= ROLE_RANK[role])
}

export function authorizeFolderRole(
  req: AuthenticatedRequest,
  res: Response,
  folderId: string,
  allowedRoles: FolderRole[]
): boolean {
  const actor = req.actor
  if (!actor) {
    incrementSecurityMetric('auth_denied_count')
    writeAuditEvent(getDb(), {
      folderId,
      eventType: 'auth_denied',
      metadata: { reason: 'missing_actor_context' },
    })
    res.status(401).json({ error: 'Missing authentication context' })
    return false
  }

  if (actor.folderId !== folderId) {
    incrementSecurityMetric('auth_denied_count')
    writeAuditEvent(getDb(), {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'auth_denied',
      metadata: { reason: 'folder_scope_mismatch' },
    })
    res.status(403).json({ error: 'Token does not grant access to this folder' })
    return false
  }

  const db = getDb()
  const member = getMemberAuthRow(db, folderId, actor.clientId)
  if (!member) {
    incrementSecurityMetric('auth_denied_count')
    writeAuditEvent(db, {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'auth_denied',
      metadata: { reason: 'no_active_membership' },
    })
    res.status(403).json({ error: 'No active membership for this folder' })
    return false
  }

  if (actor.tokenVersion !== member.token_version) {
    incrementSecurityMetric('auth_denied_count')
    writeAuditEvent(db, {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'auth_denied',
      metadata: { reason: 'token_version_mismatch' },
    })
    res.status(401).json({ error: 'Access token has been superseded' })
    return false
  }

  if (actor.jti && isTokenRevoked(db, actor.jti)) {
    incrementSecurityMetric('auth_denied_count')
    incrementSecurityMetric('revoked_token_use_attempt_count')
    writeAuditEvent(db, {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'auth_denied',
      metadata: { reason: 'token_revoked', jti: actor.jti },
    })
    res.status(401).json({ error: 'Access token has been revoked' })
    return false
  }

  actor.role = member.role
  actor.tokenVersion = member.token_version

  if (!isRoleAllowed(member.role, allowedRoles)) {
    incrementSecurityMetric('auth_denied_count')
    writeAuditEvent(db, {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'auth_denied',
      metadata: {
        reason: 'insufficient_role',
        required: allowedRoles,
        actual: member.role,
      },
    })
    res.status(403).json({ error: 'Insufficient role for this action' })
    return false
  }

  return true
}

export function requireFolderRole(allowedRoles: FolderRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const folderId = req.params.id
    if (!folderId) {
      res.status(400).json({ error: 'Missing folder ID in route' })
      return
    }

    if (!authorizeFolderRole(req, res, folderId, allowedRoles)) {
      return
    }

    next()
  }
}
