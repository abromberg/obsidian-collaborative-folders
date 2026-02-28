export type KeyHealthState = 'healthy' | 'missing-key' | 'rekey-required'

export function keyHealthLabel(state: KeyHealthState): string {
  if (state === 'healthy') return 'Keys: healthy'
  if (state === 'missing-key') return 'Keys: syncing...'
  return 'Keys: owner action needed'
}
