/**
 * Normalize a collaborator-provided relative path into a safe canonical form.
 * Returns null when the path is unsafe or malformed.
 */
export function normalizeRelativePath(input: string): string | null {
  const value = input.trim()
  if (!value) return null
  if (value.startsWith('/')) return null
  if (value.includes('\\')) return null
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return null
  }

  const segments = value.split('/')
  if (segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')) {
    return null
  }

  return segments.join('/')
}

/** Build a full path under a shared root from a validated relative path. */
export function resolveSharedPath(sharedRoot: string, relativePath: string): string | null {
  const normalizedRelative = normalizeRelativePath(relativePath)
  if (!normalizedRelative) return null

  const root = sharedRoot.trim().replace(/^\/+/, '').replace(/\/+$/, '')
  if (!root) return null

  return `${root}/${normalizedRelative}`
}
