/** Shape of the awareness state broadcast to all peers in a room */
export interface AwarenessUserState {
  /** Display name shown on cursor label */
  name: string
  /** Cursor/selection color (e.g., "#ff6b6b") */
  color: string
  /** Selection highlight color (e.g., "#ff6b6b33") */
  colorLight: string
}

/** Full awareness local state */
export interface AwarenessState {
  user: AwarenessUserState
}

/**
 * Generate a deterministic color from a client ID.
 * Ensures the same user always gets the same cursor color.
 */
export function colorFromClientId(clientId: string): { color: string; colorLight: string } {
  const PALETTE = [
    '#ff6b6b', '#ffa94d', '#ffd43b', '#69db7c',
    '#38d9a9', '#4dabf7', '#748ffc', '#da77f2',
    '#f783ac', '#e599f7', '#66d9e8', '#a9e34b',
  ]

  let hash = 0
  for (let i = 0; i < clientId.length; i++) {
    hash = ((hash << 5) - hash + clientId.charCodeAt(i)) | 0
  }
  const index = Math.abs(hash) % PALETTE.length
  const color = PALETTE[index]
  return { color, colorLight: color + '33' }
}
