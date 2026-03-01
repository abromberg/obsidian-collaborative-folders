/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import type { IncomingMessage } from 'http'
import { WebSocketServer, WebSocket } from 'ws'
import {
  PROTOCOL_V2,
  type CiphertextEnvelope,
  type EncryptedRelayError,
  type EncryptedRelayMessage,
  type EncryptedRelaySnapshot,
  type EncryptedRelaySynced,
  type EncryptedRelayUpdate,
  parseFolderId,
} from '@obsidian-teams/shared'
import { getDb } from '../db/schema.js'
import { incrementSecurityMetric } from '../security/metrics.js'
import { writeAuditEvent } from '../security/audit.js'
import { consumeWsTicket } from '../security/ws-tickets.js'
import { registerActiveSession, unregisterSocketSessions } from '../security/session-registry.js'
import {
  appendEncryptedDocEvent,
  getEncryptedDocEventsAfter,
  getLatestEncryptedDocSnapshot,
  upsertEncryptedDocSnapshot,
} from '../repos/encrypted-snapshots.js'

interface RelayActor {
  clientId: string
  displayName: string
  role: 'owner' | 'editor'
  folderId: string
  tokenVersion: number
}

interface RelayConnection {
  socket: WebSocket
  socketId: string
  roomName: string
  folderId: string
  actor: RelayActor
}

interface DocUpdateClientMessage {
  type: 'doc_update'
  protocol: typeof PROTOCOL_V2
  roomName: string
  envelope: CiphertextEnvelope
}

interface DocSnapshotClientMessage {
  type: 'doc_snapshot'
  protocol: typeof PROTOCOL_V2
  roomName: string
  baseEventId: number
  envelope: CiphertextEnvelope
}

interface AwarenessClientMessage {
  type: 'awareness_update'
  protocol: typeof PROTOCOL_V2
  roomName: string
  awarenessBase64: string
}

interface PingClientMessage {
  type: 'ping'
  protocol: typeof PROTOCOL_V2
  roomName: string
}

type RelayClientMessage =
  | DocUpdateClientMessage
  | DocSnapshotClientMessage
  | AwarenessClientMessage
  | PingClientMessage

function safeSend(socket: WebSocket, payload: EncryptedRelayMessage | Record<string, unknown>): void {
  if (socket.readyState !== WebSocket.OPEN) return
  socket.send(JSON.stringify(payload))
}

function relayError(socket: WebSocket, payload: Omit<EncryptedRelayError, 'type' | 'protocol'>): void {
  safeSend(socket, {
    type: 'error',
    protocol: PROTOCOL_V2,
    ...payload,
  })
}

function getActiveEpoch(folderId: string): number | null {
  const db = getDb()
  const row = db
    .prepare(
      `
      SELECT epoch
      FROM folder_key_epochs
      WHERE folder_id = ? AND status = 'active'
      ORDER BY epoch DESC
      LIMIT 1
    `
    )
    .get(folderId) as { epoch: number } | undefined

  return row?.epoch ?? null
}

function ensureAuthorizedConnection(request: IncomingMessage):
  | {
      roomName: string
      folderId: string
      actor: RelayActor
      lastEventId: number
    }
  | { error: string; code: number } {
  const url = new URL(request.url || '/', 'http://localhost')
  const roomName = url.searchParams.get('room')?.trim() || ''
  const ticket = url.searchParams.get('ticket')?.trim() || ''
  const lastEventId = Number(url.searchParams.get('lastEventId') || '0')

  if (!roomName) {
    return { error: 'Missing room query parameter', code: 4400 }
  }
  if (!ticket) {
    return { error: 'Missing ticket query parameter', code: 4401 }
  }

  const consumedTicket = consumeWsTicket(ticket)
  if (!consumedTicket) {
    return { error: 'Invalid or expired ticket', code: 4401 }
  }

  const folderId = parseFolderId(roomName)
  if (!folderId || consumedTicket.folderId !== folderId) {
    return { error: 'Ticket does not grant access to room folder', code: 4403 }
  }
  if (consumedTicket.roomName !== roomName) {
    return { error: 'Ticket does not grant access to this room', code: 4403 }
  }

  const db = getDb()
  const member = db
    .prepare(
      `
      SELECT role, token_version, display_name
      FROM members
      WHERE folder_id = ? AND client_id = ?
      LIMIT 1
    `
    )
    .get(folderId, consumedTicket.clientId) as
    | { role: 'owner' | 'editor'; token_version: number; display_name: string }
    | undefined

  if (!member) {
    return { error: 'No active membership for folder', code: 4403 }
  }
  if (member.token_version !== consumedTicket.tokenVersion) {
    return { error: 'Ticket token version superseded', code: 4401 }
  }

  return {
    roomName,
    folderId,
    lastEventId: Number.isFinite(lastEventId) && lastEventId >= 0 ? Math.trunc(lastEventId) : 0,
    actor: {
      clientId: consumedTicket.clientId,
      displayName: member.display_name,
      role: member.role,
      folderId,
      tokenVersion: member.token_version,
    },
  }
}

function parseClientMessage(raw: WebSocket.RawData): RelayClientMessage | null {
  try {
    const text = (() => {
      if (typeof raw === 'string') return raw
      if (Buffer.isBuffer(raw)) return raw.toString('utf8')
      if (raw instanceof ArrayBuffer) return Buffer.from(raw).toString('utf8')
      if (Array.isArray(raw)) return Buffer.concat(raw).toString('utf8')
      return ''
    })()
    if (!text) return null
    const parsed = JSON.parse(text) as RelayClientMessage
    if (!parsed || typeof parsed !== 'object') return null
    if (parsed.protocol !== PROTOCOL_V2) return null
    if (typeof parsed.type !== 'string') return null
    return parsed
  } catch {
    return null
  }
}

function closeWith(socket: WebSocket, code: number, reason: string): void {
  try {
    socket.close(code, reason)
  } catch {
    socket.terminate()
  }
}

export class EncryptedRelay {
  private rooms = new Map<string, Set<RelayConnection>>()
  private bySocket = new Map<WebSocket, RelayConnection>()
  private nextSocketId = 1

  attach(wsServer: WebSocketServer): void {
    wsServer.on('connection', (socket, request) => {
      this.handleConnection(socket, request)
    })
  }

  private handleConnection(socket: WebSocket, request: IncomingMessage): void {
    const auth = ensureAuthorizedConnection(request)
    if ('error' in auth) {
      incrementSecurityMetric('auth_denied_count')
      closeWith(socket, auth.code, auth.error)
      return
    }

    const { actor, folderId, roomName, lastEventId } = auth
    const socketId = `relay-${this.nextSocketId++}`

    const connection: RelayConnection = {
      socket,
      socketId,
      roomName,
      folderId,
      actor,
    }

    const room = this.rooms.get(roomName) || new Set<RelayConnection>()
    room.add(connection)
    this.rooms.set(roomName, room)
    this.bySocket.set(socket, connection)
    registerActiveSession({
      socketId,
      documentName: roomName,
      folderId,
      clientId: actor.clientId,
      connection: {
        close({ code, reason }) {
          closeWith(socket, code, reason)
        },
      },
    })

    writeAuditEvent(getDb(), {
      folderId,
      actorClientId: actor.clientId,
      eventType: 'encrypted_relay_connect',
      target: roomName,
      metadata: { roomPopulation: room.size },
    })

    safeSend(socket, {
      type: 'hello',
      protocol: PROTOCOL_V2,
      roomName,
      folderId,
      actorClientId: actor.clientId,
      actorDisplayName: actor.displayName,
      actorRole: actor.role,
      serverTime: new Date().toISOString(),
    })

    let syncBase = lastEventId
    const snapshot = getLatestEncryptedDocSnapshot({ folderId, roomName })
    if (snapshot && lastEventId < snapshot.baseEventId) {
      const snapshotMessage: EncryptedRelaySnapshot = {
        type: 'doc_snapshot',
        protocol: PROTOCOL_V2,
        roomName,
        senderClientId: 'server',
        baseEventId: snapshot.baseEventId,
        envelope: snapshot.envelope,
        sentAt: snapshot.createdAt,
      }
      safeSend(socket, snapshotMessage)
      syncBase = snapshot.baseEventId
    }

    const pendingEvents = getEncryptedDocEventsAfter({
      folderId,
      roomName,
      afterEventId: syncBase,
      limit: 10_000,
    })

    for (const event of pendingEvents) {
      const updateMessage: EncryptedRelayUpdate = {
        type: 'doc_update',
        protocol: PROTOCOL_V2,
        roomName,
        senderClientId: event.senderClientId,
        eventId: event.eventId,
        envelope: event.envelope,
        sentAt: event.sentAt,
      }
      safeSend(socket, updateMessage)
      syncBase = event.eventId
    }

    const syncedMessage: EncryptedRelaySynced = {
      type: 'synced',
      protocol: PROTOCOL_V2,
      roomName,
      lastEventId: syncBase,
    }
    safeSend(socket, syncedMessage)

    socket.on('message', (raw) => {
      const message = parseClientMessage(raw)
      if (!message) {
        relayError(socket, {
          code: 'invalid_message',
          message: 'Malformed relay message',
          roomName,
        })
        return
      }
      this.handleClientMessage(connection, message)
    })

    socket.on('close', () => {
      this.unregister(connection)
    })

    socket.on('error', (error) => {
      console.error('[relay] websocket error', error)
      this.unregister(connection)
    })
  }

  private unregister(connection: RelayConnection): void {
    unregisterSocketSessions(connection.socketId)
    this.bySocket.delete(connection.socket)
    const room = this.rooms.get(connection.roomName)
    if (!room) return
    room.delete(connection)
    if (room.size === 0) {
      this.rooms.delete(connection.roomName)
    }
  }

  private broadcast(roomName: string, payload: EncryptedRelayMessage | Record<string, unknown>, options: { exclude?: WebSocket } = {}): void {
    const room = this.rooms.get(roomName)
    if (!room) return
    for (const peer of room) {
      if (options.exclude && peer.socket === options.exclude) continue
      safeSend(peer.socket, payload)
    }
  }

  private handleClientMessage(connection: RelayConnection, message: RelayClientMessage): void {
    if (message.roomName !== connection.roomName) {
      relayError(connection.socket, {
        code: 'forbidden',
        message: 'roomName mismatch',
        roomName: connection.roomName,
      })
      return
    }

    if (message.type === 'ping') {
      safeSend(connection.socket, {
        type: 'pong',
        protocol: PROTOCOL_V2,
        roomName: connection.roomName,
        serverTime: new Date().toISOString(),
      })
      return
    }

    if (message.type === 'awareness_update') {
      this.broadcast(
        connection.roomName,
        {
          type: 'awareness_update',
          protocol: PROTOCOL_V2,
          roomName: connection.roomName,
          senderClientId: connection.actor.clientId,
          awarenessBase64: message.awarenessBase64,
          sentAt: new Date().toISOString(),
        },
        { exclude: connection.socket }
      )
      return
    }

    const activeEpoch = getActiveEpoch(connection.folderId)
    if (!activeEpoch) {
      relayError(connection.socket, {
        code: 'stale_epoch',
        message: 'No active folder key epoch is configured',
        roomName: connection.roomName,
      })
      return
    }

    if (message.envelope.keyEpoch !== activeEpoch) {
      relayError(connection.socket, {
        code: 'stale_epoch',
        message: `Active key epoch is ${activeEpoch}; received ${message.envelope.keyEpoch}`,
        roomName: connection.roomName,
      })
      return
    }

    if (message.type === 'doc_update') {
      const eventId = appendEncryptedDocEvent({
        folderId: connection.folderId,
        roomName: connection.roomName,
        senderClientId: connection.actor.clientId,
        envelope: message.envelope,
      })

      const updateMessage: EncryptedRelayUpdate = {
        type: 'doc_update',
        protocol: PROTOCOL_V2,
        roomName: connection.roomName,
        senderClientId: connection.actor.clientId,
        eventId,
        envelope: message.envelope,
        sentAt: new Date().toISOString(),
      }

      this.broadcast(connection.roomName, updateMessage, { exclude: connection.socket })
      safeSend(connection.socket, {
        type: 'ack',
        protocol: PROTOCOL_V2,
        roomName: connection.roomName,
        eventId,
      })
      return
    }

    if (message.type === 'doc_snapshot') {
      upsertEncryptedDocSnapshot({
        folderId: connection.folderId,
        roomName: connection.roomName,
        envelope: message.envelope,
        baseEventId: Math.max(0, Math.trunc(message.baseEventId || 0)),
      })

      safeSend(connection.socket, {
        type: 'ack',
        protocol: PROTOCOL_V2,
        roomName: connection.roomName,
        eventId: Math.max(0, Math.trunc(message.baseEventId || 0)),
      })
      return
    }

    relayError(connection.socket, {
      code: 'invalid_message',
      message: 'Unsupported message type',
      roomName: connection.roomName,
    })
  }
}
