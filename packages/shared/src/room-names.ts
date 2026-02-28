/**
 * Room naming conventions for encrypted relay sync.
 * Each Yjs document gets its own room. Doc/canvas room names encode folder + immutable file ID.
 */

/** Room for a markdown file's content (Yjs Y.Text CRDT) */
export function docRoomName(folderId: string, relativePath: string): string {
  return `folder:${folderId}:doc:${relativePath}`
}

/** Room for a shared folder's file tree index (Yjs Y.Map) */
export function treeRoomName(folderId: string): string {
  return `folder:${folderId}:tree`
}

/** Room for a canvas file's structure (Yjs Y.Map / Y.Array) */
export function canvasRoomName(folderId: string, fileId: string): string {
  return `folder:${folderId}:canvas:${fileId}`
}

/** Extract folder ID from any room name */
export function parseFolderId(roomName: string): string | null {
  const match = roomName.match(/^folder:([^:]+):/)
  return match ? match[1] : null
}

/** Extract the room type from a room name */
export function parseRoomType(roomName: string): 'doc' | 'tree' | 'canvas' | null {
  if (roomName.includes(':doc:')) return 'doc'
  if (roomName.includes(':tree')) return 'tree'
  if (roomName.includes(':canvas:')) return 'canvas'
  return null
}

/** Extract the immutable file ID from a doc or canvas room name */
export function parseFileId(roomName: string): string | null {
  const docMatch = roomName.match(/^folder:[^:]+:doc:(.+)$/)
  if (docMatch) return docMatch[1]
  const canvasMatch = roomName.match(/^folder:[^:]+:canvas:(.+)$/)
  if (canvasMatch) return canvasMatch[1]
  return null
}
