import { PROTOCOL_V2 } from './protocol-v2.js'

/** Runtime protocol version. */
export const PROTOCOL_VERSION = PROTOCOL_V2

/** Name of the dotfile in each shared folder */
export const SHARED_CONFIG_FILENAME = '.shared.json'

/** Default server URL (HTTP base — WS derived automatically) */
export const DEFAULT_SERVER_URL = 'https://collaborativefolders.com'

/** Convert an HTTP(S) base URL to its WebSocket equivalent */
export function toWsUrl(httpUrl: string): string {
  if (httpUrl.startsWith('wss://') || httpUrl.startsWith('ws://')) return httpUrl
  return httpUrl.replace(/^https:\/\//, 'wss://').replace(/^http:\/\//, 'ws://')
}

/** JWT expiry durations */
export const ACCESS_TOKEN_EXPIRY = '30d'
export const INVITE_TOKEN_EXPIRY = '7d'

/** Maximum binary file upload size (100MB) */
export const MAX_BLOB_SIZE_BYTES = 100 * 1024 * 1024
/** Hosted-mode hard file upload size limit (25MB) */
export const HOSTED_MAX_BLOB_SIZE_BYTES = 25 * 1024 * 1024
/** Header carrying hosted account session token */
export const HOSTED_SESSION_HEADER = 'x-obsidian-teams-hosted-session'

/** Y.Doc shared type names */
export const YTEXT_NAME = 'content'
export const FILETREE_MAP_NAME = 'files'

/** File extensions considered markdown (CRDT sync) */
export const CRDT_EXTENSIONS = new Set(['.md', '.markdown'])

/** File extensions for canvas files */
export const CANVAS_EXTENSIONS = new Set(['.canvas'])
