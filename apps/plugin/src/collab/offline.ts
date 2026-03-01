import * as Y from 'yjs'
import { IndexeddbPersistence } from 'y-indexeddb'
import { debugLog } from '../utils/logger'

/**
 * Create an IndexedDB persistence provider for a Y.Doc.
 * This stores Yjs state locally so edits survive offline/restart.
 *
 * The dual-provider pattern:
 * 1. IndexeddbPersistence — loads instantly from local storage
 * 2. WebsocketProvider — syncs with the server
 * Both connect to the same Y.Doc. Changes flow to both automatically.
 */
export function createOfflinePersistence(
  roomName: string,
  ydoc: Y.Doc
): IndexeddbPersistence {
  const persistence = new IndexeddbPersistence(roomName, ydoc)

  void persistence.whenSynced
    .then(() => {
      debugLog(`[offline] Loaded local state for ${roomName}`)
    })
    .catch(() => {
      debugLog(`[offline] Failed to load local state for ${roomName}`)
    })

  return persistence
}
