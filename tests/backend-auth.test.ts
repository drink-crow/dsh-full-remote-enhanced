/**
 * Backend browser-auth bridge tests.
 *
 * The unit half drives `createBackendAuth` against a scripted backend; the
 * integration half runs the real proxy with the bridge wired in and asserts
 * that a remote client which passed the plugin gate reaches a backend that
 * requires the Harness 0.1.5 browser-auth cookie — over both HTTP and a
 * WebSocket upgrade — and that a stale cookie is re-handshaked after a 401.
 */
import { afterEach, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, request } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { createConnection } from 'node:net'
import type { Socket } from 'node:net'
import type { Duplex } from 'node:stream'
import { createBackendAuth, extractHandshakeCookie } from '../src/backend-auth.ts'
import { listenProxy } from '../src/proxy.ts'
import { generateAccessToken } from '../src/security.ts'

interface HttpResponse {
  status: number | undefined
  headers: Record<string, string | string[] | undefined>
  body: string
}

/** The bound TCP port of a server started with `listen(0, host)`. */
function portOf(server: Server): number {
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('expected a TCP bind')
  return address.port
}

const cleanups: Array<() => unknown> = []
afterEach(async () => {
  for (const fn of cleanups.splice(0).reverse()) await fn()
})

function listen(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
}

function closeServer(server: Server, upgraded: Iterable<Duplex> = []): Promise<void> {
  // An upgraded socket leaves the HTTP server's connection tracking, so it
  // must be destroyed explicitly or `close()` never calls back.
  for (const socket of upgraded) socket.destroy()
  return new Promise((resolve) => {
    server.closeAllConnections()
    const timer = setTimeout(() => {
      server.closeAllConnections()
      resolve()
    }, 1000)
    server.close(() => {
      clearTimeout(timer)
      resolve()
    })
  })
}

function http(options: {
  port: number
  path?: string
  method?: string
  headers?: Record<string, string>
  body?: string
}): Promise<HttpResponse> {
  const { port, path = '/', method = 'GET', headers = {}, body } = options
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', chunk => chunks.push(chunk as Buffer))
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }))
    })
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

/** Raw WebSocket handshake against the proxy; resolves with the status line. */
function wsHandshake(options: { port: number, path: string, cookie?: string }): Promise<string> {
  const { port, path, cookie } = options
  return new Promise((resolve, reject) => {
    const socket: Socket = createConnection(port, '127.0.0.1')
    const chunks: Buffer[] = []
    let settled = false
    const settle = (error: Error | null, status?: string) => {
      if (settled) return
      settled = true
      socket.destroy()
      if (error !== null) reject(error)
      else resolve(status!)
    }
    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk)
      const at = Buffer.concat(chunks).indexOf('\r\n\r\n')
      if (at === -1) return
      settle(null, Buffer.concat(chunks).slice(0, at).toString('utf8').split('\r\n')[0] ?? '')
    })
    socket.on('error', error => settle(error))
    socket.on('close', () => settle(new Error('socket closed before the handshake completed')))
    socket.on('connect', () => {
      socket.write([
        `GET ${path} HTTP/1.1`,
        `Host: 127.0.0.1:${String(port)}`,
        ...(cookie === undefined ? [] : [`Cookie: ${cookie}`]),
        'Connection: Upgrade',
        'Upgrade: websocket',
        'Sec-WebSocket-Version: 13',
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
        '',
        '',
      ].join('\r\n'))
    })
  })
}

/**
 * Backend that behaves like a Harness Web server with browser-auth enabled:
 * `/?token=<token>` mints the cookie for that token, and every other request
 * is refused with the Harness 401 body unless it carries the current cookie.
 */
function startAuthBackend(tokens: { current: string, secret: string }) {
  const seen: Array<{ path: string, cookie: string | undefined }> = []
  const handshakes: string[] = []
  const upgraded = new Set<Duplex>()
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const token = url.searchParams.get('token')
    if (token !== null) {
      handshakes.push(token)
      if (token !== tokens.current) {
        res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('token rejected\n')
        return
      }
      res.writeHead(303, {
        location: '/',
        'set-cookie': `dsh-auth=secret-${tokens.secret}; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict`,
      })
      res.end()
      return
    }
    const cookie = req.headers.cookie
    seen.push({ path: url.pathname, cookie })
    if (cookie !== `dsh-auth=secret-${tokens.secret}`) {
      res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('dsh web authentication required; reopen the URL printed by dsh web.\n')
      return
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ path: url.pathname, cookie }))
  })
  // Upgrades face the same cookie requirement as the real stream server.
  server.on('upgrade', (req, socket) => {
    upgraded.add(socket)
    socket.once('close', () => upgraded.delete(socket))
    if (req.headers.cookie !== `dsh-auth=secret-${tokens.secret}`) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
      socket.destroy()
      return
    }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
  })
  return { server, seen, handshakes, upgraded }
}

describe('extractHandshakeCookie', () => {
  it('returns the first name=value pair without cookie attributes', () => {
    assert.equal(
      extractHandshakeCookie(['dsh-auth-abc=v1.payload; Max-Age=60; Path=/; HttpOnly']),
      'dsh-auth-abc=v1.payload',
    )
    assert.equal(extractHandshakeCookie('other=x; Path=/'), 'other=x')
  })

  it('ignores absent and malformed headers', () => {
    assert.equal(extractHandshakeCookie(undefined), undefined)
    assert.equal(extractHandshakeCookie([]), undefined)
    assert.equal(extractHandshakeCookie(['Max-Age=60; Path=/']), undefined)
  })
})

describe('createBackendAuth', () => {
  it('handshakes once, caches the cookie, and re-handshakes after invalidate', async () => {
    const tokens = { current: 'token-1', secret: 'one' }
    const backend = startAuthBackend(tokens)
    await listen(backend.server)
    cleanups.push(() => closeServer(backend.server, backend.upgraded))

    const auth = createBackendAuth({
      backendHost: '127.0.0.1',
      backendPort: portOf(backend.server),
      rewriteAuthority: `127.0.0.1:${String(portOf(backend.server))}`,
      token: () => tokens.current,
    })

    assert.equal(auth.header(), undefined)
    assert.equal(await auth.ensure(), 'dsh-auth=secret-one')
    assert.equal(auth.header(), 'dsh-auth=secret-one')
    assert.equal(await auth.ensure(), 'dsh-auth=secret-one')
    assert.deepEqual(backend.handshakes, ['token-1'])

    auth.invalidate()
    assert.equal(auth.header(), undefined)
    tokens.secret = 'two'
    assert.equal(await auth.ensure(), 'dsh-auth=secret-two')
    assert.deepEqual(backend.handshakes, ['token-1', 'token-1'])
  })

  it('shares one in-flight handshake between concurrent callers', async () => {
    const tokens = { current: 'token-1', secret: 'one' }
    const backend = startAuthBackend(tokens)
    await listen(backend.server)
    cleanups.push(() => closeServer(backend.server, backend.upgraded))

    const auth = createBackendAuth({
      backendHost: '127.0.0.1',
      backendPort: portOf(backend.server),
      rewriteAuthority: `127.0.0.1:${String(portOf(backend.server))}`,
      token: () => tokens.current,
    })

    const cookies = await Promise.all([auth.ensure(), auth.ensure(), auth.ensure()])
    assert.deepEqual(cookies, ['dsh-auth=secret-one', 'dsh-auth=secret-one', 'dsh-auth=secret-one'])
    assert.equal(backend.handshakes.length, 1)
  })

  it('stays inert when the host exposes no launch token', async () => {
    const tokens = { current: 'token-1', secret: 'one' }
    const backend = startAuthBackend(tokens)
    await listen(backend.server)
    cleanups.push(() => closeServer(backend.server, backend.upgraded))
    const failures: unknown[] = []

    const auth = createBackendAuth({
      backendHost: '127.0.0.1',
      backendPort: portOf(backend.server),
      rewriteAuthority: `127.0.0.1:${String(portOf(backend.server))}`,
      token: () => undefined,
      onFailure: error => failures.push(error),
    })

    assert.equal(await auth.ensure(), undefined)
    assert.equal(backend.handshakes.length, 0)
    assert.deepEqual(failures, [])
  })

  it('reports a rejected handshake and caches nothing', async () => {
    const tokens = { current: 'token-1', secret: 'one' }
    const backend = startAuthBackend(tokens)
    await listen(backend.server)
    cleanups.push(() => closeServer(backend.server, backend.upgraded))
    const failures: string[] = []

    const auth = createBackendAuth({
      backendHost: '127.0.0.1',
      backendPort: portOf(backend.server),
      rewriteAuthority: `127.0.0.1:${String(portOf(backend.server))}`,
      token: () => 'stale-token',
      onFailure: error => failures.push(error instanceof Error ? error.message : String(error)),
    })

    assert.equal(await auth.ensure(), undefined)
    assert.equal(auth.header(), undefined)
    assert.equal(failures.length, 1)
    assert.match(failures[0]!, /HTTP 401/)
  })

  it('reports a timeout and never leaves ensure() pending', async () => {
    // A backend that accepts the connection and never answers.
    const silent = createServer(() => {})
    await listen(silent)
    cleanups.push(() => closeServer(silent))
    const failures: string[] = []

    const auth = createBackendAuth({
      backendHost: '127.0.0.1',
      backendPort: portOf(silent),
      rewriteAuthority: `127.0.0.1:${String(portOf(silent))}`,
      token: () => 'token-1',
      timeoutMs: 50,
      onFailure: error => failures.push(error instanceof Error ? error.message : String(error)),
    })

    assert.equal(await auth.ensure(), undefined)
    assert.equal(failures.length, 1)
    assert.match(failures[0]!, /timeout/)
  })

  it('reports a token provider that throws', async () => {
    const failures: string[] = []
    const auth = createBackendAuth({
      backendHost: '127.0.0.1',
      backendPort: 1,
      rewriteAuthority: '127.0.0.1:1',
      token: () => { throw new Error('connection service missing authenticatedUrl') },
      onFailure: error => failures.push(error instanceof Error ? error.message : String(error)),
    })

    assert.equal(await auth.ensure(), undefined)
    assert.deepEqual(failures, ['connection service missing authenticatedUrl'])
  })
})

describe('proxy with the backend browser-auth bridge', () => {
  it('serves remote clients and recovers from a stale bridged cookie', async () => {
    const tokens = { current: 'token-1', secret: 'one' }
    const backend = startAuthBackend(tokens)
    await listen(backend.server)
    cleanups.push(() => closeServer(backend.server, backend.upgraded))
    const accessToken = generateAccessToken()
    const handshakes: string[] = []

    const proxy = await listenProxy({
      listenHost: '127.0.0.1',
      listenPort: 0,
      backendHost: '127.0.0.1',
      backendPort: portOf(backend.server),
      accessToken,
      cookieName: 'session',
      controlPrefix: '/dsh-reverse-proxy',
      maxRequestBytes: 1024 * 1024,
      upstreamTimeoutMs: 2000,
      sessionMaxAgeSeconds: 3600,
      loginDelayMs: 0,
      backendAuth: createBackendAuth({
        backendHost: '127.0.0.1',
        backendPort: portOf(backend.server),
        rewriteAuthority: `127.0.0.1:${String(portOf(backend.server))}`,
        token: () => {
          handshakes.push(tokens.current)
          return tokens.current
        },
      }),
    })
    cleanups.push(proxy.close)

    // A remote client must still pass the plugin gate first.
    const anonymous = await http({ port: proxy.port, path: '/' })
    assert.equal(anonymous.status, 303)
    assert.equal(anonymous.headers.location, '/_dsh_reverse_proxy/login')

    const login = await http({
      port: proxy.port,
      path: '/_dsh_reverse_proxy/login',
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(accessToken)}`,
    })
    assert.equal(login.status, 303)
    const sessionCookie = (login.headers['set-cookie'] as string[])[0]!.split(';', 1)[0]!

    // The backend requires Harness browser auth; the bridge supplies it.
    const proxied = await http({ port: proxy.port, path: '/api/example', headers: { cookie: sessionCookie } })
    assert.equal(proxied.status, 200)
    assert.deepEqual(JSON.parse(proxied.body), {
      path: '/api/example',
      cookie: 'dsh-auth=secret-one',
    })
    // The browser's own cookie is still stripped: only the bridged one arrives.
    assert.equal(backend.seen[0]!.cookie, 'dsh-auth=secret-one')
    assert.deepEqual(handshakes, ['token-1'])

    // WebSocket upgrades carry the same cookie (the stream server 401s without it).
    const upgrade = await wsHandshake({ port: proxy.port, path: '/api/remote.mux', cookie: sessionCookie })
    assert.match(upgrade, /101/)

    // Backend restart: new launch token, new cookie. The first request fails
    // with the stale cookie and must invalidate it, the next one re-handshakes.
    tokens.current = 'token-2'
    tokens.secret = 'two'
    const stale = await http({ port: proxy.port, path: '/api/example', headers: { cookie: sessionCookie } })
    assert.equal(stale.status, 401)
    const recovered = await http({ port: proxy.port, path: '/api/example', headers: { cookie: sessionCookie } })
    assert.equal(recovered.status, 200)
    assert.deepEqual(JSON.parse(recovered.body), {
      path: '/api/example',
      cookie: 'dsh-auth=secret-two',
    })
    assert.deepEqual(handshakes, ['token-1', 'token-2'])
  })

  it('proxies unchanged when no bridge is configured', async () => {
    const backend = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('ok')
    })
    await listen(backend)
    cleanups.push(() => closeServer(backend))
    const accessToken = generateAccessToken()

    const proxy = await listenProxy({
      listenHost: '127.0.0.1',
      listenPort: 0,
      backendHost: '127.0.0.1',
      backendPort: portOf(backend),
      accessToken,
      cookieName: 'session',
      controlPrefix: '/dsh-reverse-proxy',
      maxRequestBytes: 1024 * 1024,
      upstreamTimeoutMs: 2000,
      sessionMaxAgeSeconds: 3600,
      loginDelayMs: 0,
    })
    cleanups.push(proxy.close)

    const login = await http({
      port: proxy.port,
      path: '/_dsh_reverse_proxy/login',
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(accessToken)}`,
    })
    assert.equal(login.status, 303)
    const sessionCookie = (login.headers['set-cookie'] as string[])[0]!.split(';', 1)[0]!

    const proxied = await http({ port: proxy.port, path: '/', headers: { cookie: sessionCookie } })
    assert.equal(proxied.status, 200)
    assert.equal(proxied.body, 'ok')
  })
})
