import { promises as fs } from 'node:fs'
import path from 'node:path'

const repoRoot = process.cwd()
const pluginDir = path.join(repoRoot, 'apps', 'plugin')
const pluginManifestPath = path.join(pluginDir, 'manifest.json')
const rootManifestPath = path.join(repoRoot, 'manifest.json')
const versionsPath = path.join(repoRoot, 'versions.json')
const releaseDir = path.join(repoRoot, 'release', 'obsidian-plugin')

function assertPluginManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('apps/plugin/manifest.json must contain a JSON object')
  }
  for (const key of ['id', 'name', 'version', 'minAppVersion']) {
    if (typeof manifest[key] !== 'string' || manifest[key].trim() === '') {
      throw new Error(`apps/plugin/manifest.json is missing required field: ${key}`)
    }
  }
}

function parseVersion(version) {
  return version.split('.').map((part) => Number.parseInt(part, 10) || 0)
}

function compareSemverAsc(left, right) {
  const a = parseVersion(left)
  const b = parseVersion(right)
  const maxLength = Math.max(a.length, b.length)
  for (let index = 0; index < maxLength; index += 1) {
    const delta = (a[index] ?? 0) - (b[index] ?? 0)
    if (delta !== 0) return delta
  }
  return 0
}

async function readJson(filePath, fallback) {
  try {
    const raw = await fs.readFile(filePath, 'utf8')
    return JSON.parse(raw)
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return fallback
    }
    throw error
  }
}

async function copyFileIfPresent(fromPath, toPath) {
  try {
    await fs.copyFile(fromPath, toPath)
    return true
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return false
    }
    throw error
  }
}

async function main() {
  const pluginManifest = await readJson(pluginManifestPath, null)
  assertPluginManifest(pluginManifest)

  await fs.writeFile(rootManifestPath, `${JSON.stringify(pluginManifest, null, 2)}\n`)

  const versions = await readJson(versionsPath, {})
  versions[pluginManifest.version] = pluginManifest.minAppVersion
  const sortedVersions = Object.fromEntries(
    Object.entries(versions).sort(([left], [right]) => compareSemverAsc(left, right))
  )
  await fs.writeFile(versionsPath, `${JSON.stringify(sortedVersions, null, 2)}\n`)

  await fs.mkdir(releaseDir, { recursive: true })
  await fs.copyFile(rootManifestPath, path.join(releaseDir, 'manifest.json'))

  const copiedMain = await copyFileIfPresent(
    path.join(pluginDir, 'main.js'),
    path.join(releaseDir, 'main.js')
  )
  const copiedStyles = await copyFileIfPresent(
    path.join(pluginDir, 'styles.css'),
    path.join(releaseDir, 'styles.css')
  )

  const missingArtifacts = []
  if (!copiedMain) missingArtifacts.push('apps/plugin/main.js')
  if (!copiedStyles) missingArtifacts.push('apps/plugin/styles.css')

  console.log(`Synced root manifest.json and versions.json for ${pluginManifest.id}@${pluginManifest.version}.`)
  console.log(`Release directory prepared at ${path.relative(repoRoot, releaseDir)}/`)
  if (missingArtifacts.length > 0) {
    console.log(`Missing build artifacts: ${missingArtifacts.join(', ')}`)
    console.log('Run `pnpm plugin:build` before creating a GitHub release.')
  }
}

await main()
