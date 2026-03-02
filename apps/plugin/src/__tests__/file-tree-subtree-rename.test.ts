import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'fs'
import path from 'path'

const FILE_TREE_SYNC = path.resolve(process.cwd(), 'src/collab/file-tree-sync.ts')
const WATCHER = path.resolve(process.cwd(), 'src/collab/file-watcher.ts')

test('directory rename uses subtree remap support', () => {
  const fileTreeSync = fs.readFileSync(FILE_TREE_SYNC, 'utf8')
  const watcher = fs.readFileSync(WATCHER, 'utf8')

  assert.equal(fileTreeSync.includes('renameSubtree(oldDir: string, newDir: string): void'), true)
  assert.equal(fileTreeSync.includes('relativePath.startsWith(oldPrefix)'), true)

  assert.equal(watcher.includes('if (file instanceof TFolder) {'), true)
  assert.equal(watcher.includes('this.fileTree.renameSubtree(oldRelative, newRelative)'), true)
})
