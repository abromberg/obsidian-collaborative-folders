import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'fs'
import path from 'path'

const MAIN = path.resolve(process.cwd(), 'src/main.ts')
const WATCHER = path.resolve(process.cwd(), 'src/collab/file-watcher.ts')

test('shared root rename local-only guard is wired from main to watcher', () => {
  const main = fs.readFileSync(MAIN, 'utf8')
  const watcher = fs.readFileSync(WATCHER, 'utf8')

  assert.equal(main.includes('private pendingRootRebinds = new Map<string, { newPath: string; expiresAt: number }>()'), true)
  assert.equal(main.includes('private isRootRebindRename(oldPath: string, newPath: string): boolean'), true)
  assert.equal(main.includes('(oldPath, newPath) => this.isRootRebindRename(oldPath, newPath)'), true)

  assert.equal(watcher.includes('private isRootRebindRename: ((oldPath: string, newPath: string) => boolean) | null = null'), true)
  assert.equal(watcher.includes('Ignored local rename during shared-root rebind'), true)
})
