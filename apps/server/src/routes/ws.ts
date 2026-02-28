import { Router, type Response } from 'express'
import type { WsTicketResponse } from '@obsidian-teams/shared'
import { parseFolderId } from '@obsidian-teams/shared'
import { requireHttpAuth, type AuthenticatedRequest } from '../middleware/http-auth.js'
import { requireFolderRole } from '../middleware/require-role.js'
import { issueWsTicket } from '../security/ws-tickets.js'
import { writeAuditEvent } from '../security/audit.js'
import { getDb } from '../db/schema.js'

interface IssueWsTicketBody {
  roomName?: string
}

export const wsRouter: ReturnType<typeof Router> = Router()

/** POST /api/folders/:id/ws-ticket — issue one-time WebSocket auth ticket. */
wsRouter.post(
  '/:id/ws-ticket',
  requireHttpAuth,
  requireFolderRole(['editor']),
  (req: AuthenticatedRequest, res: Response<WsTicketResponse | { error: string }>) => {
    const actor = req.actor
    if (!actor) {
      res.status(401).json({ error: 'Missing actor context' })
      return
    }

    const body = (req.body || {}) as IssueWsTicketBody
    const roomName = body.roomName?.trim()
    if (!roomName) {
      res.status(400).json({ error: 'Missing required field: roomName' })
      return
    }

    const folderIdFromRoom = parseFolderId(roomName)
    if (!folderIdFromRoom || folderIdFromRoom !== req.params.id) {
      res.status(400).json({ error: 'roomName does not match folder ID' })
      return
    }

    const issued = issueWsTicket({
      folderId: req.params.id,
      clientId: actor.clientId,
      tokenVersion: actor.tokenVersion,
      roomName,
    })

    writeAuditEvent(getDb(), {
      folderId: req.params.id,
      actorClientId: actor.clientId,
      eventType: 'ws_ticket_issued',
      target: roomName,
      metadata: {
        expiresAt: issued.expiresAt,
      },
    })

    res.status(201).json(issued)
  }
)
