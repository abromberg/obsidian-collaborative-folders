let debugLoggingEnabled = false

export function setDebugLogging(enabled: boolean): void {
  debugLoggingEnabled = enabled
}

export function debugLog(...args: unknown[]): void {
  if (!debugLoggingEnabled) return
  console.debug(...args)
}

export function debugWarn(...args: unknown[]): void {
  if (!debugLoggingEnabled) return
  console.warn(...args)
}
