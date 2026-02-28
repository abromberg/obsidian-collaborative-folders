import crypto from 'crypto'

interface TicketRecord {
  folderId: string
  clientId: string
  tokenVersion: number
  roomName: string
  expiresAtMs: number
  createdAtMs: number
}

const WS_TICKET_TTL_MS = Number(process.env.WS_TICKET_TTL_MS || 60_000)
const WS_TICKET_MAX_ACTIVE = Number(process.env.WS_TICKET_MAX_ACTIVE || 10_000)
const ticketsByHash = new Map<string, TicketRecord>()

function hashTicket(ticket: string): string {
  return crypto.createHash('sha256').update(ticket).digest('hex')
}

function nowMs(): number {
  return Date.now()
}

function sweepExpiredTickets(): void {
  const now = nowMs()
  for (const [ticketHash, record] of ticketsByHash.entries()) {
    if (record.expiresAtMs <= now) {
      ticketsByHash.delete(ticketHash)
    }
  }
}

export function issueWsTicket(input: {
  folderId: string
  clientId: string
  tokenVersion: number
  roomName: string
}): { ticket: string; expiresAt: string } {
  sweepExpiredTickets()
  if (ticketsByHash.size >= WS_TICKET_MAX_ACTIVE) {
    throw new Error('WebSocket ticket capacity exceeded')
  }

  const ticket = crypto.randomBytes(32).toString('base64url')
  const ticketHash = hashTicket(ticket)
  const expiresAtMs = nowMs() + WS_TICKET_TTL_MS

  ticketsByHash.set(ticketHash, {
    folderId: input.folderId,
    clientId: input.clientId,
    tokenVersion: input.tokenVersion,
    roomName: input.roomName,
    expiresAtMs,
    createdAtMs: nowMs(),
  })

  return {
    ticket,
    expiresAt: new Date(expiresAtMs).toISOString(),
  }
}

export function consumeWsTicket(ticket: string): TicketRecord | null {
  if (!ticket) return null

  const ticketHash = hashTicket(ticket)
  const record = ticketsByHash.get(ticketHash)
  if (!record) return null

  ticketsByHash.delete(ticketHash)
  if (record.expiresAtMs <= nowMs()) {
    return null
  }

  return record
}

export function clearWsTicketsForTests(): void {
  ticketsByHash.clear()
}

export function getWsTicketStatsForTests(): { active: number } {
  sweepExpiredTickets()
  return { active: ticketsByHash.size }
}
