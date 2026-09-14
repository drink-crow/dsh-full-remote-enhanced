/**
 * Backend browser-authentication bridge.
 *
 * DeepSeek Harness 0.1.5 authenticates every Web GUI request with a cookie
 * minted from a per-process launch token: the token is printed by `dsh web`,
 * never persisted, and changes on every restart. A reverse proxy that owns the
 * remote authentication boundary — and that deliberately strips client cookies
 * and upstream `set-cookie` — can therefore never complete that handshake, so
 * every remote browser would receive `401 dsh web authentication required`.
 *
 * This bridge runs the handshake **server-side** through the Host `connection`
 * service (`authenticatedUrl()`), caches the resulting cookie, and replays it
 * on proxied HTTP requests and WebSocket upgrades. The launch token never
 * reaches the browser, and the plugin gate stays the only boundary a remote
 * client has to pass.
 *
 * The bridge is inert on Harness releases without that service (0.1.1 and
 * earlier): `token()` then returns `undefined`, no handshake is attempted, and
 * proxying behaves exactly as before.
 */
import { request as httpRequest } from 'node:http'
import type { ClientRequest, IncomingMessage } from 'node:http'

/** Handshake deadline before the bridge gives up on one attempt. */
export const DEFAULT_HANDSHAKE_TIMEOUT_MS = 5_000

/**
 * The single Host `connection` member this bundle consumes. Declared
 * structurally so the bridge typechecks against Harness releases that predate
 * `authenticatedUrl()` and without importing client declarations.
 */
export interface AuthenticatedUrlProvider {
  /** Add the fresh process token to an ordinary Web application URL. */
  authenticatedUrl(baseUrl: string): string
}

/** Bridge inputs; `token()` runs on every handshake attempt. */
export interface BackendAuthSpec {
  backendHost: string
  backendPort: number
  /** Host/Origin authority the proxy rewrites to; the cookie is bound to it. */
  rewriteAuthority: string
  /** Fresh launch-token provider, backed by `ctx.get('connection')`. */
  token: () => string | undefined
  /** Handshake deadline in milliseconds. Default {@link DEFAULT_HANDSHAKE_TIMEOUT_MS}. */
  timeoutMs?: number
  /** Receives every handshake failure so the host can log it. */
  onFailure?: (error: unknown) => void
}

/** Cached backend cookie with single-flight handshake. */
export interface BackendAuth {
  /** Cached cookie pair, or `undefined` before the first successful handshake. */
  header: () => string | undefined
  /** Drop the cached cookie so the next {@link BackendAuth.ensure} re-handshakes. */
  invalidate: () => void
  /** Cached cookie, handshaking once when absent. Never rejects. */
  ensure: () => Promise<string | undefined>
}

/** `Set-Cookie` attribute names that must never be mistaken for a cookie pair. */
const COOKIE_ATTRIBUTES = new Set([
  'expires',
  'max-age',
  'domain',
  'path',
  'secure',
  'httponly',
  'samesite',
  'priority',
  'partitioned',
])

/**
 * First `name=value` pair of a handshake response, or `undefined` when the
 * response carried no cookie. The name is authority-derived by the backend, so
 * the pair is replayed verbatim instead of being parsed apart. Attribute
 * segments are skipped, so a header that opens with `Max-Age=…` yields no
 * cookie instead of a bogus one.
 * @param setCookie - `set-cookie` header value(s) of the handshake response.
 * @returns the cookie pair to replay, without attributes.
 */
export function extractHandshakeCookie(setCookie: string[] | string | undefined): string | undefined {
  const list = Array.isArray(setCookie) ? setCookie : setCookie === undefined ? [] : [setCookie]
  for (const entry of list) {
    for (const segment of entry.split(';')) {
      const pair = segment.trim()
      const separator = pair.indexOf('=')
      if (separator <= 0) continue
      if (COOKIE_ATTRIBUTES.has(pair.slice(0, separator).trim().toLowerCase())) continue
      return pair
    }
  }
  return undefined
}

/**
 * Build a bridge over one Harness backend.
 * @param spec - backend location, rewritten authority, and token provider.
 * @returns a cache whose `ensure()` performs at most one handshake at a time.
 */
export function createBackendAuth(spec: BackendAuthSpec): BackendAuth {
  let cached: string | undefined
  let inflight: Promise<string | undefined> | undefined

  const handshake = (): Promise<string | undefined> => new Promise((resolve) => {
    let token: string | undefined
    try {
      token = spec.token()
    } catch (error) {
      spec.onFailure?.(error)
      resolve(undefined)
      return
    }
    if (typeof token !== 'string' || token.length === 0) {
      // Pre-0.1.5 Harness, or a tree without the connection service: nothing to
      // bridge, and no reason to warn on every request.
      resolve(undefined)
      return
    }
    const up: ClientRequest = httpRequest({
      hostname: spec.backendHost,
      port: spec.backendPort,
      path: `/?token=${encodeURIComponent(token)}`,
      method: 'GET',
      headers: {
        host: spec.rewriteAuthority,
        origin: `http://${spec.rewriteAuthority}`,
        'cache-control': 'no-store',
        'x-dsh-reverse-proxy': '1',
      },
    }, (incoming: IncomingMessage) => {
      clearTimeout(timer)
      const status = incoming.statusCode ?? 0
      const cookie = extractHandshakeCookie(incoming.headers['set-cookie'])
      incoming.resume()
      if (status === 303 && cookie !== undefined) {
        cached = cookie
        resolve(cookie)
        return
      }
      spec.onFailure?.(new Error(`backend browser-auth handshake returned HTTP ${String(status)}`))
      resolve(undefined)
    })
    const timer = setTimeout(() => {
      up.destroy(new Error('backend browser-auth handshake timeout'))
    }, spec.timeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS)
    timer.unref()
    up.on('error', (error) => {
      clearTimeout(timer)
      spec.onFailure?.(error)
      resolve(undefined)
    })
    // Node buffers the request until end(); without it the handshake would
    // never leave the process and every attempt would time out.
    up.end()
  })

  return {
    header: () => cached,
    invalidate: () => {
      cached = undefined
    },
    ensure: () => {
      if (cached !== undefined) return Promise.resolve(cached)
      if (inflight === undefined) {
        const settle = () => {
          inflight = undefined
        }
        inflight = handshake().then((value) => {
          settle()
          return value
        }, (error: unknown) => {
          settle()
          throw error
        })
      }
      return inflight
    },
  }
}
