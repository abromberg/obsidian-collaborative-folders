import type { Request, Response, NextFunction } from 'express'
import { incrementSecurityMetric } from './metrics.js'
import { getDb } from '../db/schema.js'
import { writeAuditEvent } from './audit.js'

interface WindowCounter {
  startedAt: number
  count: number
  amount: number
}

const counters = new Map<string, WindowCounter>()

function nowMs(): number {
  return Date.now()
}

function getWindowCounter(key: string, windowMs: number): WindowCounter {
  const existing = counters.get(key)
  const now = nowMs()
  if (!existing || now - existing.startedAt >= windowMs) {
    const fresh: WindowCounter = { startedAt: now, count: 0, amount: 0 }
    counters.set(key, fresh)
    return fresh
  }
  return existing
}

function retryAfterSeconds(counter: WindowCounter, windowMs: number): number {
  const elapsed = nowMs() - counter.startedAt
  const remainingMs = Math.max(windowMs - elapsed, 0)
  return Math.max(1, Math.ceil(remainingMs / 1000))
}

export function createRateLimiter(options: {
  name: string
  windowMs: number
  maxRequests: number
  keyFn: (req: Request) => string
}) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = `${options.name}:${options.keyFn(req)}`
    const bucket = getWindowCounter(key, options.windowMs)

    if (bucket.count >= options.maxRequests) {
      const retryAfter = retryAfterSeconds(bucket, options.windowMs)
      incrementSecurityMetric('rate_limited_count')
      const actor = (req as { actor?: { clientId?: string } }).actor
      const body = (req.body || {}) as Record<string, unknown>
      const folderId =
        (typeof req.params.id === 'string' && req.params.id) ||
        (typeof body.folderId === 'string' ? body.folderId : null)
      writeAuditEvent(getDb(), {
        folderId: folderId || null,
        actorClientId:
          actor?.clientId || (typeof body.clientId === 'string' ? body.clientId : null),
        eventType: 'rate_limit_violation',
        target: options.name,
        metadata: {
          retryAfterSeconds: retryAfter,
          ip: req.ip,
        },
      })
      res.setHeader('Retry-After', String(retryAfter))
      res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfterSeconds: retryAfter,
      })
      return
    }

    bucket.count += 1
    next()
  }
}

export function consumeWindowedQuota(options: {
  name: string
  key: string
  windowMs: number
  maxAmount: number
  amount: number
}): { allowed: boolean; retryAfterSeconds: number } {
  const bucket = getWindowCounter(`${options.name}:${options.key}`, options.windowMs)
  if (bucket.amount + options.amount > options.maxAmount) {
    const retryAfter = retryAfterSeconds(bucket, options.windowMs)
    incrementSecurityMetric('rate_limited_count')
    return { allowed: false, retryAfterSeconds: retryAfter }
  }

  bucket.amount += options.amount
  return { allowed: true, retryAfterSeconds: 0 }
}
