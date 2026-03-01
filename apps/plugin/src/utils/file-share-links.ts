import type { AccessTokenPayload } from '@obsidian-teams/shared'

export function decodeProtocolTokenValue(rawValue: unknown): string | null {
  if (typeof rawValue !== 'string') return null
  const trimmed = rawValue.trim()
  if (!trimmed) return null

  try {
    const decoded = decodeURIComponent(trimmed).trim()
    return decoded.length > 0 ? decoded : null
  } catch {
    return trimmed
  }
}

/** Accept common token parameter aliases from Obsidian deep-links. */
export function resolveFileShareTokenParam(params: Record<string, unknown>): string | null {
  const candidates = [params.token, params.fileToken, params.shareToken]
  for (const candidate of candidates) {
    const normalized = decodeProtocolTokenValue(candidate)
    if (normalized) return normalized
  }
  return null
}

/** Return path within a shared folder, or null when file is outside the folder root. */
export function relativePathWithinSharedFolder(sharedFolderPath: string, filePath: string): string | null {
  const prefix = `${sharedFolderPath}/`
  if (!filePath.startsWith(prefix)) return null
  const relativePath = filePath.slice(prefix.length)
  return relativePath.length > 0 ? relativePath : null
}

export function hasFileSharePermission(role: AccessTokenPayload['role'] | null | undefined): boolean {
  return role === 'owner' || role === 'editor'
}
