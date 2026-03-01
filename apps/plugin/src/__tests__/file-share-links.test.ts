import test from 'node:test'
import assert from 'node:assert/strict'
import {
  hasFileSharePermission,
  relativePathWithinSharedFolder,
  resolveFileShareTokenParam,
} from '../utils/file-share-links.js'

test('resolveFileShareTokenParam accepts token aliases and decodes URI input', () => {
  assert.equal(resolveFileShareTokenParam({ token: 'abc123' }), 'abc123')
  assert.equal(resolveFileShareTokenParam({ fileToken: 'file%2Dtoken%2D1' }), 'file-token-1')
  assert.equal(resolveFileShareTokenParam({ shareToken: '  spaced-token  ' }), 'spaced-token')
})

test('resolveFileShareTokenParam returns null when token params are missing', () => {
  assert.equal(resolveFileShareTokenParam({}), null)
  assert.equal(resolveFileShareTokenParam({ token: '' }), null)
  assert.equal(resolveFileShareTokenParam({ token: '   ' }), null)
})

test('relativePathWithinSharedFolder returns relative file paths only for files inside folder', () => {
  assert.equal(relativePathWithinSharedFolder('Shared/Team', 'Shared/Team/notes/today.md'), 'notes/today.md')
  assert.equal(relativePathWithinSharedFolder('Shared/Team', 'Shared/Other/today.md'), null)
  assert.equal(relativePathWithinSharedFolder('Shared/Team', 'Shared/Team'), null)
})

test('hasFileSharePermission allows owners and editors and blocks missing role', () => {
  assert.equal(hasFileSharePermission('owner'), true)
  assert.equal(hasFileSharePermission('editor'), true)
  assert.equal(hasFileSharePermission(null), false)
})
