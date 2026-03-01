/* eslint-disable import/no-nodejs-modules -- Server runtime intentionally depends on Node.js built-in modules. */
import fs from 'fs'
import path from 'path'

const DEFAULT_BLOB_DIR = process.env.BLOB_DIR || './data/blobs'

export interface EncryptedBlobLocation {
  folderId: string
  epoch: number
  blobId: string
}

export function encryptedBlobPath(location: EncryptedBlobLocation): string {
  const safeFolder = encodeURIComponent(location.folderId)
  const safeBlobId = encodeURIComponent(location.blobId)
  return path.join(DEFAULT_BLOB_DIR, safeFolder, `epoch-${location.epoch}`, safeBlobId)
}

export function writeEncryptedBlob(location: EncryptedBlobLocation, ciphertext: Buffer): string {
  const destination = encryptedBlobPath(location)
  const dir = path.dirname(destination)

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }

  fs.writeFileSync(destination, ciphertext)
  return destination
}

export function readEncryptedBlob(location: EncryptedBlobLocation): Buffer | null {
  const source = encryptedBlobPath(location)
  if (!fs.existsSync(source)) return null
  return fs.readFileSync(source)
}
