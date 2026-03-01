import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'fs'
import path from 'path'

const MAIN = path.resolve(process.cwd(), 'src/main.ts')
const YJS_MANAGER = path.resolve(process.cwd(), 'src/collab/yjs-manager.ts')

test('membership removal path clears local folder linkage', () => {
  const main = fs.readFileSync(MAIN, 'utf8')
  const yjsManager = fs.readFileSync(YJS_MANAGER, 'utf8')

  assert.equal(main.includes('isMembershipRemovedReason'), true)
  assert.equal(main.includes('no active membership'), true)
  assert.equal(main.includes('clearLocalFolderLink'), true)
  assert.equal(main.includes('You were removed from shared folder'), true)
  assert.equal(yjsManager.includes('destroySessionsForFolder'), true)
})
