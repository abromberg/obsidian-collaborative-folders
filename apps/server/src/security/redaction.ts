const JWT_LIKE_PATTERN = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
const LONG_SECRET_PATTERN = /\b[A-Za-z0-9_-]{24,}\b/g

function shouldRedactKey(key: string): boolean {
  const normalized = key.toLowerCase()
  return (
    normalized.includes('authorization') ||
    normalized.includes('token') ||
    normalized.includes('secret') ||
    normalized.includes('password')
  )
}

export function redactText(input: string): string {
  return input
    .replace(JWT_LIKE_PATTERN, '[REDACTED_JWT]')
    .replace(LONG_SECRET_PATTERN, (candidate) => {
      if (candidate.length < 32) return candidate
      return '[REDACTED_SECRET]'
    })
}

export function redactValue(value: unknown): unknown {
  if (value == null) return value
  if (typeof value === 'string') return redactText(value)
  if (Array.isArray(value)) return value.map((item) => redactValue(item))
  if (typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
      result[key] = shouldRedactKey(key) ? '[REDACTED]' : redactValue(nestedValue)
    }
    return result
  }
  return value
}
