import type { Request, Response } from 'express'

const RESET_VERIFICATION_TOKEN = process.env.RESET_VERIFICATION_TOKEN || ''

/**
 * Checks that the request provides a valid admin token via
 * `x-reset-verification-token` header or `?token=` query param.
 *
 * Returns `true` if the request is authorized. On failure it sends an
 * error response and returns `false` — callers should `return` early.
 */
export function requireAdminToken(req: Request, res: Response): boolean {
  if (!RESET_VERIFICATION_TOKEN) {
    res.status(403).json({ error: 'Admin endpoint is disabled (no token configured)' })
    return false
  }
  const tokenFromQuery = typeof req.query.token === 'string' ? req.query.token : null
  const provided = req.header('x-reset-verification-token') || tokenFromQuery
  if (provided !== RESET_VERIFICATION_TOKEN) {
    res.status(401).json({ error: 'Invalid or missing admin token' })
    return false
  }
  return true
}
