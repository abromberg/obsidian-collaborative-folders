export type SecurityMetricName =
  | 'auth_denied_count'
  | 'rate_limited_count'
  | 'revoked_token_use_attempt_count'

const counters: Record<SecurityMetricName, number> = {
  auth_denied_count: 0,
  rate_limited_count: 0,
  revoked_token_use_attempt_count: 0,
}

export function incrementSecurityMetric(name: SecurityMetricName, delta = 1): void {
  counters[name] += delta
}

export function getSecurityMetrics(): Record<SecurityMetricName, number> {
  return { ...counters }
}
