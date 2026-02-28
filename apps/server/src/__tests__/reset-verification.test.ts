import test from 'node:test'
import assert from 'node:assert/strict'
import type { Router } from 'express'

delete process.env.RESET_VERIFICATION_TOKEN
const { resetVerificationRouter } = await import('../routes/reset-verification.js')

function createMockResponse() {
  return {
    statusCode: 200,
    body: null as unknown,
    status(code: number) {
      this.statusCode = code
      return this
    },
    json(payload: unknown) {
      this.body = payload
      return this
    },
  }
}

function routeHandler(router: Router, pathTemplate: string, method: 'get' | 'post' | 'delete') {
  const layer = (router as any).stack.find(
    (candidate: any) => candidate.route?.path === pathTemplate && candidate.route?.methods?.[method]
  )
  if (!layer) {
    throw new Error(`Unable to locate route ${method.toUpperCase()} ${pathTemplate}`)
  }
  return layer.route.stack[layer.route.stack.length - 1].handle as (
    req: any,
    res: any,
    next: (error?: unknown) => void
  ) => unknown
}

const resetVerificationHandler = routeHandler(
  resetVerificationRouter as unknown as Router,
  '/reset-verification',
  'get'
)

test('reset verification endpoint is disabled by default when token is not configured', async () => {
  const req = {
    query: {},
    headers: {},
    header(_name: string) {
      return undefined
    },
  }
  const res = createMockResponse()

  await Promise.resolve(resetVerificationHandler(req, res, () => {}))

  assert.equal(res.statusCode, 403)
  const payload = res.body as { error: string }
  assert.match(payload.error, /disabled/i)
})
