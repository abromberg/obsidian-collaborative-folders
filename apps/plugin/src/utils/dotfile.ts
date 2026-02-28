import { Vault, TFolder } from 'obsidian'
import { SHARED_CONFIG_FILENAME, type SharedFolderConfig } from '@obsidian-teams/shared'

/** A shared folder found in the vault */
export interface SharedFolderLocation {
  path: string
  config: SharedFolderConfig
}

/** Read .shared.json from a folder path. Returns null if not found or invalid. */
export function readSharedConfig(vault: Vault, folderPath: string): SharedFolderConfig | null {
  const configPath = `${folderPath}/${SHARED_CONFIG_FILENAME}`
  const file = vault.getAbstractFileByPath(configPath)
  if (!file) return null

  try {
    // Use cachedRead for performance (sync-ish via cache)
    // For async contexts, use vault.read()
    return null // Will be implemented with async read
  } catch {
    return null
  }
}

/** Async read of .shared.json */
export async function readSharedConfigAsync(
  vault: Vault,
  folderPath: string
): Promise<SharedFolderConfig | null> {
  const configPath = `${folderPath}/${SHARED_CONFIG_FILENAME}`
  const exists = await vault.adapter.exists(configPath)
  if (!exists) return null

  try {
    const content = await vault.adapter.read(configPath)
    return JSON.parse(content) as SharedFolderConfig
  } catch {
    return null
  }
}

/** Write .shared.json to a folder */
export async function writeSharedConfig(
  vault: Vault,
  folderPath: string,
  config: SharedFolderConfig
): Promise<void> {
  const configPath = `${folderPath}/${SHARED_CONFIG_FILENAME}`
  const content = JSON.stringify(config, null, 2)
  await vault.adapter.write(configPath, content)
}

/** Remove .shared.json from a folder */
export async function removeSharedConfig(
  vault: Vault,
  folderPath: string
): Promise<void> {
  const configPath = `${folderPath}/${SHARED_CONFIG_FILENAME}`
  const exists = await vault.adapter.exists(configPath)
  if (exists) {
    await vault.adapter.remove(configPath)
  }
}

/** Recursively collect all folders in the vault */
function getAllFolders(vault: Vault): TFolder[] {
  const result: TFolder[] = []
  function walk(folder: TFolder) {
    result.push(folder)
    for (const child of folder.children) {
      if (child instanceof TFolder) {
        walk(child)
      }
    }
  }
  walk(vault.getRoot())
  return result
}

/** Scan the vault for all folders containing .shared.json */
export async function findSharedFolders(
  vault: Vault
): Promise<SharedFolderLocation[]> {
  const results: SharedFolderLocation[] = []

  const allFolders = getAllFolders(vault)
  for (const folder of allFolders) {
    const config = await readSharedConfigAsync(vault, folder.path)
    if (config) {
      results.push({ path: folder.path, config })
    }
  }

  return results
}
