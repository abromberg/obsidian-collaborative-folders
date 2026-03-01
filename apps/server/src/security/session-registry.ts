interface ClosableSessionConnection {
  close(args: { code: number; reason: string }): void
}

interface ActiveSession {
  sessionId: string
  socketId: string
  documentName: string
  folderId: string
  clientId: string
  jti?: string
  connection: ClosableSessionConnection
}

const sessionsById = new Map<string, ActiveSession>()
const sessionIdsBySocket = new Map<string, Set<string>>()
const sessionIdsByMember = new Map<string, Set<string>>()

function buildSessionId(socketId: string, documentName: string): string {
  return `${socketId}:${documentName}`
}

function memberKey(folderId: string, clientId: string): string {
  return `${folderId}:${clientId}`
}

export function registerActiveSession(input: {
  socketId: string
  documentName: string
  folderId: string
  clientId: string
  jti?: string
  connection: ClosableSessionConnection
}): void {
  const sessionId = buildSessionId(input.socketId, input.documentName)
  const member = memberKey(input.folderId, input.clientId)

  const session: ActiveSession = { ...input, sessionId }
  sessionsById.set(sessionId, session)

  const socketSessions = sessionIdsBySocket.get(input.socketId) || new Set<string>()
  socketSessions.add(sessionId)
  sessionIdsBySocket.set(input.socketId, socketSessions)

  const memberSessions = sessionIdsByMember.get(member) || new Set<string>()
  memberSessions.add(sessionId)
  sessionIdsByMember.set(member, memberSessions)
}

export function unregisterSocketSessions(socketId: string): void {
  const sessionIds = sessionIdsBySocket.get(socketId)
  if (!sessionIds) return

  for (const sessionId of sessionIds) {
    const session = sessionsById.get(sessionId)
    if (!session) continue

    sessionsById.delete(sessionId)

    const memberSessions = sessionIdsByMember.get(memberKey(session.folderId, session.clientId))
    if (memberSessions) {
      memberSessions.delete(sessionId)
      if (memberSessions.size === 0) {
        sessionIdsByMember.delete(memberKey(session.folderId, session.clientId))
      }
    }
  }

  sessionIdsBySocket.delete(socketId)
}

export function revokeMemberSessions(
  folderId: string,
  clientId: string,
  reason = 'membership-revoked'
): { closedCount: number; revokedJtis: string[] } {
  const ids = sessionIdsByMember.get(memberKey(folderId, clientId))
  if (!ids || ids.size === 0) {
    return { closedCount: 0, revokedJtis: [] }
  }

  const revokedJtis = new Set<string>()
  let closedCount = 0

  for (const sessionId of ids) {
    const session = sessionsById.get(sessionId)
    if (!session) continue

    if (session.jti) revokedJtis.add(session.jti)
    session.connection.close({ code: 4401, reason })
    closedCount += 1
  }

  return { closedCount, revokedJtis: [...revokedJtis] }
}

export function listMemberSessionJtis(folderId: string, clientId: string): string[] {
  const ids = sessionIdsByMember.get(memberKey(folderId, clientId))
  if (!ids || ids.size === 0) {
    return []
  }

  const revokedJtis = new Set<string>()
  for (const sessionId of ids) {
    const session = sessionsById.get(sessionId)
    if (!session?.jti) continue
    revokedJtis.add(session.jti)
  }

  return [...revokedJtis]
}
