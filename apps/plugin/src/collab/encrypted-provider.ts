import * as Y from 'yjs'
import {
  Awareness,
  applyAwarenessUpdate,
  encodeAwarenessUpdate,
  removeAwarenessStates,
} from 'y-protocols/awareness'
import {
  PROTOCOL_V2,
  toWsUrl,
  type CiphertextEnvelope,
  type EncryptedRelayMessage,
  type WsTicketResponse,
  PROTOCOL_HEADER,
} from '@obsidian-teams/shared'
import { CryptoEngine, fromBase64, toBase64 } from '../crypto/engine'
import { FolderKeyManager } from '../crypto/folder-key-manager'
import { httpRequest } from '../utils/http'

const REMOTE_ORIGIN = 'encrypted-provider-remote'
const STATUS_CONNECTING = 'connecting'
const STATUS_CONNECTED = 'connected'
const STATUS_DISCONNECTED = 'disconnected'

const SNAPSHOT_UPDATE_INTERVAL = 25

type ProviderStatus = typeof STATUS_CONNECTED | typeof STATUS_CONNECTING | typeof STATUS_DISCONNECTED

interface ProviderOptions {
  serverUrl: string
  roomName: string
  folderId: string
  ydoc: Y.Doc
  getAuthToken: (folderId: string, options?: { forceRefresh?: boolean }) => Promise<string | null>
  keyManager: FolderKeyManager
}

interface StatusPayload {
  status: ProviderStatus
}

interface AuthFailedPayload {
  reason: string
}

interface SyncedPayload {
  state: boolean
}

type EventMap = {
  status: (payload: StatusPayload) => void
  authenticationFailed: (payload: AuthFailedPayload) => void
  synced: (payload: SyncedPayload) => void
}

function typedTextEncoder(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

function safeParseMessage(raw: string): EncryptedRelayMessage | null {
  try {
    const message = JSON.parse(raw) as unknown
    if (!message || typeof message !== 'object') return null
    const protocol = (message as { protocol?: unknown }).protocol
    if (typeof protocol === 'string' && protocol !== PROTOCOL_V2) return null
    return message as EncryptedRelayMessage
  } catch {
    return null
  }
}

function readErrorMessage(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null
  const value = (payload as { error?: unknown }).error
  return typeof value === 'string' && value.length > 0 ? value : null
}

function readWsTicket(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null
  const ticket = (payload as { ticket?: unknown }).ticket
  return typeof ticket === 'string' && ticket.length > 0 ? ticket : null
}

export class EncryptedProvider {
  readonly awareness: Awareness
  isSynced = false

  private ws: WebSocket | null = null
  private destroyed = false
  private reconnectTimer: number | null = null
  private reconnectAttempt = 0
  private outbox: Uint8Array[] = []
  private lastEventId = 0
  private pendingSnapshot = 0
  private listeners: {
    status: Set<EventMap['status']>
    authenticationFailed: Set<EventMap['authenticationFailed']>
    synced: Set<EventMap['synced']>
  } = {
    status: new Set(),
    authenticationFailed: new Set(),
    synced: new Set(),
  }

  constructor(
    private readonly options: ProviderOptions,
    private readonly engine = new CryptoEngine()
  ) {
    this.awareness = new Awareness(options.ydoc)

    this.options.ydoc.on('update', this.onDocUpdate)
    this.awareness.on('update', this.onAwarenessUpdate)

    void this.connect()
  }

  on<E extends keyof EventMap>(event: E, callback: EventMap[E]): void {
    if (event === 'status') {
      this.listeners.status.add(callback as EventMap['status'])
      return
    }
    if (event === 'authenticationFailed') {
      this.listeners.authenticationFailed.add(callback as EventMap['authenticationFailed'])
      return
    }
    this.listeners.synced.add(callback as EventMap['synced'])
  }

  off<E extends keyof EventMap>(event: E, callback: EventMap[E]): void {
    if (event === 'status') {
      this.listeners.status.delete(callback as EventMap['status'])
      return
    }
    if (event === 'authenticationFailed') {
      this.listeners.authenticationFailed.delete(callback as EventMap['authenticationFailed'])
      return
    }
    this.listeners.synced.delete(callback as EventMap['synced'])
  }

  disconnect(): void {
    this.closeSocket()
    this.updateStatus(STATUS_DISCONNECTED)
    this.updateSynced(false)
  }

  destroy(): void {
    this.destroyed = true
    this.disconnect()
    this.options.ydoc.off('update', this.onDocUpdate)
    this.awareness.off('update', this.onAwarenessUpdate)
    removeAwarenessStates(this.awareness, [this.awareness.clientID], 'destroy')
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }

  private emit<E extends keyof EventMap>(event: E, payload: Parameters<EventMap[E]>[0]): void {
    if (event === 'status') {
      for (const cb of this.listeners.status) {
        cb(payload as StatusPayload)
      }
      return
    }
    if (event === 'authenticationFailed') {
      for (const cb of this.listeners.authenticationFailed) {
        cb(payload as AuthFailedPayload)
      }
      return
    }
    for (const cb of this.listeners.synced) {
      cb(payload as SyncedPayload)
    }
  }

  private updateStatus(status: ProviderStatus): void {
    this.emit('status', { status })
  }

  private updateSynced(state: boolean): void {
    this.isSynced = state
    this.emit('synced', { state })
  }

  private failAuth(reason: string): void {
    this.emit('authenticationFailed', { reason })
  }

  private buildAad(kind: 'doc-update' | 'doc-snapshot'): Uint8Array {
    return typedTextEncoder(`${this.options.folderId}:${this.options.roomName}:${kind}`)
  }

  private async getKeyForEpoch(epoch: number): Promise<CryptoKey | null> {
    const cached = await this.options.keyManager.getCachedContentKey(this.options.folderId, epoch)
    if (cached) return cached

    const active = await this.options.keyManager.getActiveContentKey(this.options.folderId, { forceRefresh: true })
    if (active.epoch === epoch) return active.key

    return this.options.keyManager.getCachedContentKey(this.options.folderId, epoch)
  }

  private onDocUpdate = (update: Uint8Array, origin: unknown) => {
    if (origin === REMOTE_ORIGIN || this.destroyed) return

    this.outbox.push(update)
    this.pendingSnapshot += 1

    if (this.pendingSnapshot >= SNAPSHOT_UPDATE_INTERVAL) {
      this.pendingSnapshot = 0
      void this.sendSnapshot()
      return
    }

    void this.flushOutbox()
  }

  private onAwarenessUpdate = ({ added, updated, removed }: { added: number[]; updated: number[]; removed: number[] }, origin: unknown) => {
    if (origin === REMOTE_ORIGIN || this.destroyed) return
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return

    const changed = [...added, ...updated, ...removed]
    if (changed.length === 0) return

    const update = encodeAwarenessUpdate(this.awareness, changed)
    this.sendJson({
      type: 'awareness_update',
      protocol: PROTOCOL_V2,
      roomName: this.options.roomName,
      awarenessBase64: toBase64(update),
    })
  }

  private closeSocket(): void {
    if (this.ws) {
      this.ws.onopen = null
      this.ws.onclose = null
      this.ws.onerror = null
      this.ws.onmessage = null
      if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
        this.ws.close()
      }
      this.ws = null
    }
  }

  private scheduleReconnect(): void {
    if (this.destroyed) return
    if (this.reconnectTimer !== null) return

    const attempt = this.reconnectAttempt
    const backoff = Math.min(10_000, 500 * Math.pow(2, attempt))
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null
      void this.connect()
    }, backoff)
  }

  private async issueWsTicket(accessToken: string): Promise<string> {
    const response = await httpRequest(
      `${this.options.serverUrl}/api/folders/${encodeURIComponent(this.options.folderId)}/ws-ticket`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          [PROTOCOL_HEADER]: PROTOCOL_V2,
        },
        body: JSON.stringify({ roomName: this.options.roomName }),
      }
    )

    if (!response.ok) {
      const body = await response.json().catch(() => null)
      const message = readErrorMessage(body) ?? `HTTP ${response.status}`
      throw new Error(`Failed to issue WebSocket ticket: ${message}`)
    }

    const payload = (await response.json()) as WsTicketResponse
    const ticket = readWsTicket(payload)
    if (!ticket) {
      throw new Error('Failed to issue WebSocket ticket: missing ticket')
    }
    return ticket
  }

  private async connect(): Promise<void> {
    if (this.destroyed) return

    this.closeSocket()
    this.updateStatus(STATUS_CONNECTING)

    const token = await this.options.getAuthToken(this.options.folderId)
    if (!token) {
      this.failAuth('Missing access token')
      this.updateStatus(STATUS_DISCONNECTED)
      this.reconnectAttempt += 1
      this.scheduleReconnect()
      return
    }

    try {
      await this.options.keyManager.getActiveContentKey(this.options.folderId)
    } catch (error: unknown) {
      const reason = error instanceof Error && error.message
        ? error.message
        : 'Failed to initialize folder key'
      this.failAuth(reason)
      this.updateStatus(STATUS_DISCONNECTED)
      this.reconnectAttempt += 1
      this.scheduleReconnect()
      return
    }

    let ticket: string
    try {
      ticket = await this.issueWsTicket(token)
    } catch (error: unknown) {
      const reason = error instanceof Error && error.message
        ? error.message
        : 'Failed to issue WebSocket ticket'
      this.failAuth(reason)
      this.updateStatus(STATUS_DISCONNECTED)
      this.reconnectAttempt += 1
      this.scheduleReconnect()
      return
    }

    const wsBase = toWsUrl(this.options.serverUrl)
    const wsUrl = new URL('/ws', wsBase)
    wsUrl.searchParams.set('protocol', PROTOCOL_V2)
    wsUrl.searchParams.set('room', this.options.roomName)
    wsUrl.searchParams.set('ticket', ticket)
    wsUrl.searchParams.set('lastEventId', String(this.lastEventId))

    const ws = new WebSocket(wsUrl.toString())
    this.ws = ws

    ws.onopen = () => {
      this.reconnectAttempt = 0
      this.updateStatus(STATUS_CONNECTED)
      this.broadcastLocalAwareness()
      void this.flushOutbox()
    }

    ws.onmessage = (event) => {
      if (typeof event.data !== 'string') return
      void this.handleMessage(event.data)
    }

    ws.onclose = async (event) => {
      this.ws = null
      this.updateStatus(STATUS_DISCONNECTED)
      this.updateSynced(false)

      if (this.destroyed) return
      if (event.code === 4401 || event.code === 4403) {
        try {
          await this.options.getAuthToken(this.options.folderId, { forceRefresh: true })
        } catch {
          this.failAuth(event.reason || 'Authentication failed')
        }
      }

      this.reconnectAttempt += 1
      this.scheduleReconnect()
    }

    ws.onerror = () => {
      this.updateStatus(STATUS_DISCONNECTED)
    }
  }

  private async handleMessage(raw: string): Promise<void> {
    const message = safeParseMessage(raw)
    if (!message) return

    if (message.type === 'synced') {
      this.lastEventId = Math.max(this.lastEventId, message.lastEventId)
      this.updateSynced(true)
      void this.flushOutbox()
      return
    }

    if (message.type === 'ack') {
      this.lastEventId = Math.max(this.lastEventId, message.eventId)
      return
    }

    if (message.type === 'error') {
      if (message.code === 'auth_failed' || message.code === 'forbidden') {
        this.failAuth(message.message)
      }
      return
    }

    if (message.type === 'awareness_update') {
      const decoded = fromBase64(message.awarenessBase64)
      applyAwarenessUpdate(this.awareness, decoded, REMOTE_ORIGIN)
      return
    }

    if (message.type === 'doc_snapshot') {
      await this.applyEncryptedUpdate(message.envelope)
      this.lastEventId = Math.max(this.lastEventId, message.baseEventId)
      return
    }

    if (message.type === 'doc_update') {
      await this.applyEncryptedUpdate(message.envelope)
      this.lastEventId = Math.max(this.lastEventId, message.eventId)
      return
    }
  }

  private async applyEncryptedUpdate(envelope: CiphertextEnvelope): Promise<void> {
    const key = await this.getKeyForEpoch(envelope.keyEpoch)
    if (!key) {
      console.warn(`[encrypted-provider] Missing key for epoch ${envelope.keyEpoch}`)
      return
    }

    try {
      const update = await this.engine.decrypt(envelope, key, {
        aad: this.buildAad(envelope.kind === 'doc-snapshot' ? 'doc-snapshot' : 'doc-update'),
      })
      Y.applyUpdate(this.options.ydoc, update, REMOTE_ORIGIN)
    } catch (error) {
      console.error('[encrypted-provider] Failed to decrypt/update document', error)
    }
  }

  private sendJson(payload: Record<string, unknown>): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return
    this.ws.send(JSON.stringify(payload))
  }

  private async flushOutbox(): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return
    if (this.outbox.length === 0) return

    const { key, epoch } = await this.options.keyManager.getActiveContentKey(this.options.folderId)

    while (this.outbox.length > 0) {
      const update = this.outbox.shift()
      if (!update) continue

      const envelope = await this.engine.encrypt(update, key, {
        kind: 'doc-update',
        target: this.options.roomName,
        keyEpoch: epoch,
        aad: this.buildAad('doc-update'),
      })

      this.sendJson({
        type: 'doc_update',
        protocol: PROTOCOL_V2,
        roomName: this.options.roomName,
        envelope,
      })
    }
  }

  private async sendSnapshot(): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return

    const { key, epoch } = await this.options.keyManager.getActiveContentKey(this.options.folderId)
    const fullState = Y.encodeStateAsUpdate(this.options.ydoc)

    const envelope = await this.engine.encrypt(fullState, key, {
      kind: 'doc-snapshot',
      target: this.options.roomName,
      keyEpoch: epoch,
      aad: this.buildAad('doc-snapshot'),
    })

    this.sendJson({
      type: 'doc_snapshot',
      protocol: PROTOCOL_V2,
      roomName: this.options.roomName,
      baseEventId: this.lastEventId,
      envelope,
    })
  }

  private broadcastLocalAwareness(): void {
    const update = encodeAwarenessUpdate(this.awareness, [this.awareness.clientID])
    this.sendJson({
      type: 'awareness_update',
      protocol: PROTOCOL_V2,
      roomName: this.options.roomName,
      awarenessBase64: toBase64(update),
    })
  }
}
