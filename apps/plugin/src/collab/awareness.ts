import type { Awareness } from 'y-protocols/awareness'
import { colorFromClientId, type AwarenessUserState } from '@obsidian-teams/shared'

/** Re-broadcast interval (ms). Must be well under the 30s awareness timeout. */
const AWARENESS_REFRESH_MS = 15_000

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
    if (clientId !== awareness.clientID && state.user) {
      users.push({
        clientId,
        name: state.user.name,
        color: state.user.color,
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
