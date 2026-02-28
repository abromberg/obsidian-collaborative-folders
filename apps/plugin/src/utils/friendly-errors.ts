const ERROR_MAP: Array<{ pattern: RegExp; message: string }> = [
  {
    pattern: /subscription_inactive|subscription is not active/i,
    message: 'Your subscription is inactive. Open billing in settings to reactivate.',
  },
  {
    pattern: /subscription_past_due|past due/i,
    message: 'Your subscription payment failed. Update your payment method in billing settings.',
  },
  {
    pattern: /hosted_session_required|hosted session|hosted account link is required/i,
    message: 'Account setup required. Add your email and subscribe in plugin settings.',
  },
  {
    pattern: /needs owner rekey|rekey required|envelope is unavailable/i,
    message: 'The folder owner needs to update encryption keys. Ask them to open Obsidian.',
  },
  {
    pattern: /missing local key|missing key/i,
    message: 'Encryption keys are out of sync. Try leaving and rejoining the folder.',
  },
  {
    pattern: /already.?member|cannot redeem invites for this folder/i,
    message: 'You are already a member of this folder.',
  },
  {
    pattern: /invite.*(expired|revoked|consumed)|invite not found|invite already used|no longer valid/i,
    message: 'This invite is no longer valid. Ask the folder owner for a new one.',
  },
  {
    pattern: /rate.?limit|quota.?exceeded|too many requests/i,
    message: 'Too many requests. Please wait a moment and try again.',
  },
]

export function rawErrorMessage(raw: unknown, fallback = 'Unknown error'): string {
  if (raw instanceof Error && raw.message) return raw.message
  if (typeof raw === 'string' && raw.trim()) return raw.trim()
  return fallback
}

export function friendlyError(raw: string): string {
  for (const { pattern, message } of ERROR_MAP) {
    if (pattern.test(raw)) return message
  }
  return raw
}

export function friendlyErrorFromUnknown(raw: unknown, fallback = 'Unknown error'): string {
  return friendlyError(rawErrorMessage(raw, fallback))
}

export function isHostedSessionError(raw: string): boolean {
  return /hosted_session_required|hosted session|hosted account link is required/i.test(raw)
}

export function isSubscriptionInactiveError(raw: string): boolean {
  return /subscription_inactive|subscription is not active/i.test(raw)
}

export function isSubscriptionPastDueError(raw: string): boolean {
  return /subscription_past_due|past due/i.test(raw)
}

export function isNetworkError(raw: string): boolean {
  return /failed to fetch|network|enotfound|name_not_resolved|err_name_not_resolved|cors/i.test(raw)
}

export function isInviteLifecycleError(raw: string): boolean {
  return /invite.*(expired|revoked|consumed|not found|already used)|no longer valid/i.test(raw)
}

export function isConfigError(raw: string): boolean {
  if (isInviteLifecycleError(raw)) return false
  return (
    isHostedSessionError(raw) ||
    isSubscriptionInactiveError(raw) ||
    isSubscriptionPastDueError(raw) ||
    isNetworkError(raw)
  )
}
