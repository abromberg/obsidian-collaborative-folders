import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'fs'
import path from 'path'

const MAIN = path.resolve(process.cwd(), 'src/main.ts')

test('shared root rename triggers shared-folder reindex and session path restart', () => {
  const main = fs.readFileSync(MAIN, 'utf8')

  assert.equal(main.includes('refreshSharedFoldersOnRootRename(file, oldPath)'), true)
  assert.equal(main.includes('private refreshSharedFoldersOnRootRename'), true)
  assert.equal(main.includes('sharedFolderPath: sf.path'), true)
  assert.equal(main.includes('Restarting file tree sync after folder move'), true)
})
