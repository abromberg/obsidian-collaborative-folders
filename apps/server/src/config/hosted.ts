const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on'])

function readBool(value: string | undefined, fallback = false): boolean {
  if (!value) return fallback
  return TRUE_VALUES.has(value.trim().toLowerCase())
}

function readInt(value: string | undefined, fallback: number): number {
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return fallback
  return Math.trunc(parsed)
}

function normalizeOptional(value: string | undefined): string | null {
  const trimmed = value?.trim()
  return trimmed ? trimmed : null
}

export function isHostedModeEnabled(): boolean {
  return readBool(process.env.HOSTED_MODE, false)
}

export function hostedSeatPriceCents(): number {
  return readInt(process.env.HOSTED_DEFAULT_SEAT_PRICE_CENTS, 900)
}

export function hostedStorageCapBytes(): number {
  return readInt(process.env.HOSTED_DEFAULT_STORAGE_CAP_BYTES, 3 * 1024 * 1024 * 1024)
}

export function hostedMaxFileSizeBytes(): number {
  return readInt(process.env.HOSTED_DEFAULT_MAX_FILE_SIZE_BYTES, 25 * 1024 * 1024)
}

export function hostedStripeSecretKey(): string | null {
  return normalizeOptional(process.env.STRIPE_SECRET_KEY)
}

export function hostedStripeWebhookSecret(): string | null {
  return normalizeOptional(process.env.STRIPE_WEBHOOK_SECRET)
}

export function hostedBaseUrl(defaultValue = 'https://collaborativefolders.com'): string {
  return normalizeOptional(process.env.PUBLIC_HTTP_URL) || normalizeOptional(process.env.SERVER_URL) || defaultValue
}

export function isHostedBillingConfigured(): boolean {
  if (!isHostedModeEnabled()) return false
  return Boolean(hostedStripeSecretKey() && hostedStripeWebhookSecret())
}

export function readHostedConfig() {
  const hostedMode = isHostedModeEnabled()
  return {
    hostedMode,
    stripeSecretKey: hostedStripeSecretKey(),
    stripeWebhookSecret: hostedStripeWebhookSecret(),
    defaultSeatPriceCents: hostedSeatPriceCents(),
    defaultStorageCapBytes: hostedStorageCapBytes(),
    defaultMaxFileSizeBytes: hostedMaxFileSizeBytes(),
    billingConfigured: isHostedBillingConfigured(),
  }
}
