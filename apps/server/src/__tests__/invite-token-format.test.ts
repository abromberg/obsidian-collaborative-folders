import test from 'node:test'
import assert from 'node:assert/strict'

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef0123456789abcdef'

const { generateInviteToken } = await import('../hooks/auth.js')

test('invite token uses a readable slug plus fixed-length random suffix', () => {
  const token = generateInviteToken('Company Docs')
  assert.match(token, /^company-docs-[a-f0-9]{20}$/)
})

test('invite token falls back to shared-folder slug when name has no letters or numbers', () => {
  const token = generateInviteToken('***')
  assert.match(token, /^shared-folder-[a-f0-9]{20}$/)
})

test('invite token random suffix changes across calls', () => {
  const first = generateInviteToken('Company Docs')
  const second = generateInviteToken('Company Docs')
  assert.notEqual(first, second)
})
