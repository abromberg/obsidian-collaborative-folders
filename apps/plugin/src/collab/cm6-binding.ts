import { yCollab } from 'y-codemirror.next'
import * as Y from 'yjs'
import type { Awareness } from 'y-protocols/awareness'
import type { Extension } from '@codemirror/state'

/**
 * Create a CM6 extension for collaborative editing using Yjs.
 *
 * yCollab provides three things in one extension:
 * 1. Text sync (ySync) — binds Y.Text to CM6 document
 * 2. Remote cursors (yRemoteSelections) — renders other users' cursors/selections
 * 3. Collaborative undo (yUndoManagerKeymap) — undo only local changes
 */
export function createCollabExtension(
  ytext: Y.Text,
  awareness: Awareness
): { extension: Extension; undoManager: Y.UndoManager } {
  const undoManager = new Y.UndoManager(ytext, {
    // Group undo operations within a 500ms window
    captureTimeout: 500,
  })

  const extension = yCollab(ytext, awareness, { undoManager })

  return { extension, undoManager }
}
