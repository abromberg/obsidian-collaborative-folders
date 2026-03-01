import test from 'node:test'
import assert from 'node:assert/strict'

test('auth module rejects missing JWT_SECRET', async () => {
  const original = process.env.JWT_SECRET
  try {
    delete process.env.JWT_SECRET
    await assert.rejects(
      import(`../hooks/auth.js?missing-secret=${Date.now()}`),
      /JWT_SECRET is required/
    )
  } finally {
    if (typeof original === 'string') {
      process.env.JWT_SECRET = original
    } else {
      delete process.env.JWT_SECRET
    }
  }
})
