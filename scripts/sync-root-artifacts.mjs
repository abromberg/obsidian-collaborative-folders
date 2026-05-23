import { promises as fs } from 'node:fs'
import path from 'node:path'

// Obsidian's automated build verification expects the plugin's build outputs at
// the repository root. In this monorepo the plugin bundles to apps/plugin/main.js,
// so after `turbo build` we copy the artifacts up to the root. main.js is a build
// product (gitignored); this keeps the repo layout looking like a standard plugin.
const repoRoot = process.cwd()
const pluginDir = path.join(repoRoot, 'apps', 'plugin')
const artifacts = ['main.js', 'styles.css']

async function copyIfPresent(name) {
  const from = path.join(pluginDir, name)
  const to = path.join(repoRoot, name)
  if (from === to) return false
  try {
    await fs.copyFile(from, to)
    return true
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') return false
    throw error
  }
}

let copied = 0
for (const name of artifacts) {
  if (await copyIfPresent(name)) copied += 1
}

if (copied === 0) {
  console.log('sync-root-artifacts: no plugin artifacts found; run the plugin build first.')
} else {
  console.log(`sync-root-artifacts: copied ${copied} artifact(s) to ${repoRoot}`)
}
