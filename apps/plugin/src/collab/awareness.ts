import type { Awareness } from 'y-protocols/awareness'
import { colorFromClientId, type AwarenessUserState } from '@obsidian-teams/shared'

/** Re-broadcast interval (ms). Must be well under the 30s awareness timeout. */
const AWARENESS_REFRESH_MS = 15_000

function readRemoteUser(state: unknown): { name: string; color: string } | null {
  if (!state || typeof state !== 'object') return null
  const user = (state as { user?: unknown }).user
  if (!user || typeof user !== 'object') return null

  const name = (user as { name?: unknown }).name
  const color = (user as { color?: unknown }).color
  if (typeof name !== 'string' || typeof color !== 'string') return null
  return { name, color }
}

/**
 * Initialize the local awareness state with user identity.
 * This broadcasts the user's name and cursor color to all peers.
 *
 * Also starts a periodic re-broadcast so the awareness protocol's 30-second
 * inactivity timeout never expires while the user is connected.
 * Returns a cleanup function that stops the interval.
 */
export function initAwareness(
  awareness: Awareness,
  clientId: string,
  displayName: string
): () => void {
  const { color, colorLight } = colorFromClientId(clientId)

  const userState: AwarenessUserState = {
    name: displayName,
    color,
    colorLight,
  }

  awareness.setLocalStateField('user', userState)

  // Periodically re-broadcast local state to prevent the 30s awareness timeout
  // from removing our cursor on remote peers.
  const interval = setInterval(() => {
    if (awareness.getLocalState() !== null) {
      awareness.setLocalStateField('user', userState)
    }
  }, AWARENESS_REFRESH_MS)

  return () => clearInterval(interval)
}

/** Get all remote users currently connected to this document */
export function getRemoteUsers(awareness: Awareness): Array<{
  clientId: number
  name: string
  color: string
}> {
  const users: Array<{ clientId: number; name: string; color: string }> = []

  awareness.getStates().forEach((state, clientId) => {
    const user = readRemoteUser(state)
    if (clientId !== awareness.clientID && user) {
      users.push({
        clientId,
        name: user.name,
        color: user.color,
      })
    }
  })

  return users
}

/**
 * Listen for awareness changes and call back with the updated user list.
 * Returns an unsubscribe function.
 */
export function onAwarenessChange(
  awareness: Awareness,
  callback: (users: Array<{ clientId: number; name: string; color: string }>) => void
): () => void {
  const handler = () => {
    callback(getRemoteUsers(awareness))
  }

  awareness.on('change', handler)
  return () => awareness.off('change', handler)
}
