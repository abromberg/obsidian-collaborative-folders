type ObsidianRequestUrlFn = (request: {
  url: string
  method?: string
  contentType?: string
  body?: string | ArrayBuffer
  headers?: Record<string, string>
  throw?: boolean
}) => Promise<{
  status: number
  headers: Record<string, string>
  arrayBuffer: ArrayBuffer
  json: unknown
  text: string
}>

interface HttpHeaders {
  get(name: string): string | null
}

export interface HttpResponseLike {
  ok: boolean
  status: number
  headers: HttpHeaders
  json(): Promise<unknown>
  text(): Promise<string>
  arrayBuffer(): Promise<ArrayBuffer>
}

interface HttpRequestInit {
  method?: string
  headers?: Record<string, string>
  body?: string | ArrayBuffer
}

// Set by the plugin runtime so modules that do not import `obsidian` can still prefer
// requestUrl. A module-level binding is shared across all windows in the same JS context,
// so it works for popout windows without reaching for any ambient global object.
let injectedRequestUrl: ObsidianRequestUrlFn | null = null

class HeaderMap implements HttpHeaders {
  private readonly normalized = new Map<string, string>()

  constructor(headers: Record<string, string>) {
    for (const [key, value] of Object.entries(headers)) {
      this.normalized.set(key.toLowerCase(), value)
    }
  }

  get(name: string): string | null {
    return this.normalized.get(name.toLowerCase()) ?? null
  }
}

function jsonParse(text: string): unknown {
  if (!text.trim()) {
    throw new Error('Response body is empty')
  }
  return JSON.parse(text)
}

function asArrayBuffer(value: ArrayBuffer): ArrayBuffer {
  return value.slice(0)
}

function makeResponseFromRequestUrl(payload: {
  status: number
  headers: Record<string, string>
  arrayBuffer: ArrayBuffer
  json: unknown
  text: string
}): HttpResponseLike {
  const headers = new HeaderMap(payload.headers || {})
  const status = payload.status
  const ok = status >= 200 && status < 300
  const textValue = typeof payload.text === 'string' ? payload.text : ''
  const arrayBufferValue = asArrayBuffer(payload.arrayBuffer)
  let jsonResolved = false
  let jsonCached: unknown

  return {
    ok,
    status,
    headers,
    text() {
      return Promise.resolve(textValue)
    },
    arrayBuffer() {
      return Promise.resolve(asArrayBuffer(arrayBufferValue))
    },
    json() {
      if (!jsonResolved) {
        // Obsidian's requestUrl response may expose `json` via a getter that throws
        // for non-JSON bodies (for example, encrypted blob bytes). Keep this lazy so
        // binary/text callers can still use `arrayBuffer()`/`text()` safely.
        try {
          jsonCached = payload.json
        } catch (error) {
          const reason = error instanceof Error ? error : new Error('Failed to parse JSON response')
          return Promise.reject(reason)
        }
        jsonResolved = true
      }

      if (typeof jsonCached !== 'undefined' && jsonCached !== null) {
        return Promise.resolve(jsonCached)
      }
      return Promise.resolve(jsonParse(textValue))
    },
  }
}

export function registerObsidianRequestUrl(requestUrl: ObsidianRequestUrlFn | null): void {
  injectedRequestUrl = requestUrl
}

export async function httpRequest(url: string, init: HttpRequestInit = {}): Promise<HttpResponseLike> {
  if (injectedRequestUrl) {
    const response = await injectedRequestUrl({
      url,
      method: init.method,
      headers: init.headers,
      body: init.body,
      throw: false,
    })
    return makeResponseFromRequestUrl(response)
  }

  if (typeof fetch !== 'function') {
    throw new Error('No HTTP implementation is available')
  }
  return fetch(url, init as RequestInit) as Promise<HttpResponseLike>
}
