import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeRelativePath, resolveSharedPath } from '@obsidian-teams/shared'

test('normalizeRelativePath accepts simple relative paths', () => {
  assert.equal(normalizeRelativePath('notes/a.md'), 'notes/a.md')
  assert.equal(normalizeRelativePath('dir/sub/file.md'), 'dir/sub/file.md')
})

test('normalizeRelativePath rejects unsafe paths', () => {
  assert.equal(normalizeRelativePath(''), null)
  assert.equal(normalizeRelativePath('/abs.md'), null)
  assert.equal(normalizeRelativePath('../x.md'), null)
  assert.equal(normalizeRelativePath('a/../b.md'), null)
  assert.equal(normalizeRelativePath('a\\b.md'), null)
  assert.equal(normalizeRelativePath('bad\x01name.md'), null)
})

test('resolveSharedPath resolves valid paths and blocks unsafe input', () => {
  assert.equal(resolveSharedPath('Agents', 'vc/notes.md'), 'Agents/vc/notes.md')
  assert.equal(resolveSharedPath('/Agents/', 'vc/notes.md'), 'Agents/vc/notes.md')

  assert.equal(resolveSharedPath('Agents', '../escape.md'), null)
  assert.equal(resolveSharedPath('', 'vc/notes.md'), null)
})
