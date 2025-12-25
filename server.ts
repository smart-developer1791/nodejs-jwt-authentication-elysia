import { Elysia, t } from 'elysia'
import { node } from '@elysiajs/node'
import { html } from '@elysiajs/html'
import jwt from 'jsonwebtoken'

// =============================================================================
// CONFIGURATION
// =============================================================================

/** Secret key for JWT signing - use env variable in production */
const JWT_SECRET = 'super-secret-key'

/** Access token expiration time (short-lived for security) */
const ACCESS_TOKEN_TTL = '15m'

/** Refresh token expiration time (long-lived for UX) */
const REFRESH_TOKEN_TTL = '7d'

/** Rate limit: max requests per window */
const RATE_LIMIT_MAX = 30

/** Rate limit: window duration in milliseconds */
const RATE_LIMIT_WINDOW_MS = 60_000

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

type Role = 'user' | 'admin'

/** Full user record stored in database */
interface User {
  id: string
  email: string
  password: string // In production: store hashed password only
  role: Role
}

/** Authenticated user payload extracted from JWT */
interface AuthUser {
  id: string
  role: Role
}

/** JWT access token payload structure */
interface AccessTokenPayload {
  sub: string
  role: Role
  iat: number
  exp: number
}

// =============================================================================
// IN-MEMORY STORAGE
// Replace with persistent database in production
// =============================================================================

/** User store: email -> User */
const users = new Map<string, User>()

/** Valid refresh tokens: token -> userId */
const refreshTokens = new Map<string, string>()

// Seed default admin and user for testing
users.set('admin@local', {
  id: '1',
  email: 'admin@local',
  password: 'admin',
  role: 'admin'
})
users.set('user@local', {
  id: '2',
  email: 'user@local',
  password: 'user',
  role: 'user'
})

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Creates a short-lived access token containing user identity and role.
 * Used for authenticating API requests.
 */
const signAccessToken = (user: User): string =>
  jwt.sign(
    { sub: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  )

/**
 * Creates a long-lived refresh token for obtaining new access tokens.
 * Token is stored server-side to enable revocation.
 */
const signRefreshToken = (user: User): string => {
  const token = jwt.sign(
    { sub: user.id },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_TTL }
  )
  refreshTokens.set(token, user.id)
  return token
}

/**
 * Parses HTTP Cookie header into key-value pairs.
 * Handles edge cases like values containing '=' characters.
 */
const parseCookie = (cookie?: string | null): Record<string, string> => {
  if (!cookie) return {}
  return Object.fromEntries(
    cookie.split(';').map(part => {
      const [key, ...valueParts] = part.trim().split('=')
      return [key, valueParts.join('=')]
    })
  )
}

/**
 * Finds user by ID from in-memory store.
 * Returns undefined if user not found.
 */
const findUserById = (id: string): User | undefined =>
  [...users.values()].find(u => u.id === id)

/**
 * Extracts AuthUser from request cookies.
 * Returns null if token is missing or invalid.
 */
const extractUser = (request: Request): AuthUser | null => {
  const cookies = parseCookie(request.headers.get('cookie'))
  const accessToken = cookies.accessToken

  if (!accessToken) return null

  try {
    const payload = jwt.verify(accessToken, JWT_SECRET) as AccessTokenPayload
    return { id: payload.sub, role: payload.role }
  } catch {
    return null
  }
}

// =============================================================================
// RATE LIMITING PLUGIN
// Simple sliding window rate limiter based on client IP
// =============================================================================

const rateLimitPlugin = new Elysia({ name: 'plugin:rate-limit' })
  .state('hits', new Map<string, { count: number; timestamp: number }>())
  .onBeforeHandle(({ request, store, set }) => {
    // Extract client IP from proxy header or fallback to 'local'
    const clientIp = request.headers.get('x-forwarded-for') ?? 'local'
    const now = Date.now()
    const record = store.hits.get(clientIp)

    // Reset counter if outside time window
    if (!record || now - record.timestamp > RATE_LIMIT_WINDOW_MS) {
      store.hits.set(clientIp, { count: 1, timestamp: now })
      return
    }

    // Increment counter and check limit
    record.count++
    if (record.count > RATE_LIMIT_MAX) {
      set.status = 429
      return { error: 'Too many requests', retryAfter: RATE_LIMIT_WINDOW_MS / 1000 }
    }
  })

// =============================================================================
// HTML FRONTEND
// Simple SPA for testing authentication flow
// =============================================================================

const frontendHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Elysia Auth Playground</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">

<div class="bg-white p-8 rounded-xl shadow-xl w-full max-w-md space-y-4">
  <h1 class="text-2xl font-bold text-center">🔐 Auth Playground</h1>

  <input id="email" placeholder="Email" value="admin@local"
    class="w-full border px-3 py-2 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" />
  <input id="password" placeholder="Password" value="admin" type="password"
    class="w-full border px-3 py-2 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" />

  <button onclick="login()"
    class="w-full bg-blue-500 text-white py-2 rounded hover:bg-blue-600 transition">
    Login
  </button>

  <div class="flex gap-2">
    <button onclick="callApi('/me')" class="flex-1 bg-gray-200 py-2 rounded hover:bg-gray-300 transition">
      /me
    </button>
    <button onclick="callApi('/admin')" class="flex-1 bg-gray-200 py-2 rounded hover:bg-gray-300 transition">
      /admin
    </button>
    <button onclick="logout()" class="flex-1 bg-red-100 py-2 rounded hover:bg-red-200 transition text-red-600">
      Logout
    </button>
  </div>

  <pre id="output" class="bg-gray-900 text-green-400 p-3 rounded text-sm h-40 overflow-auto whitespace-pre-wrap"></pre>
</div>

<script>
  const output = document.getElementById('output')
  const emailInput = document.getElementById('email')
  const passwordInput = document.getElementById('password')

  async function login() {
    try {
      const res = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          email: emailInput.value,
          password: passwordInput.value
        })
      })
      const data = await res.json()
      output.textContent = JSON.stringify(data, null, 2)
    } catch (err) {
      output.textContent = 'Error: ' + err.message
    }
  }

  async function callApi(path) {
    try {
      const res = await fetch(path, { credentials: 'include' })
      const text = await res.text()
      try {
        output.textContent = JSON.stringify(JSON.parse(text), null, 2)
      } catch {
        output.textContent = text
      }
    } catch (err) {
      output.textContent = 'Error: ' + err.message
    }
  }

  async function logout() {
    try {
      const res = await fetch('/auth/logout', {
        method: 'POST',
        credentials: 'include'
      })
      const data = await res.json()
      output.textContent = JSON.stringify(data, null, 2)
    } catch (err) {
      output.textContent = 'Error: ' + err.message
    }
  }
</script>

</body>
</html>
`

// =============================================================================
// APPLICATION SETUP
// =============================================================================

const app = new Elysia({ adapter: node() })
  .use(html())
  .use(rateLimitPlugin)

// =============================================================================
// PUBLIC ROUTES (no authentication required)
// =============================================================================

/** Serve frontend HTML */
app.get('/', () => frontendHtml)

/**
 * POST /auth/login
 * Authenticates user and sets HTTP-only cookies with tokens.
 */
app.post('/auth/login', ({ body, set }) => {
  const user = users.get(body.email)

  if (!user || user.password !== body.password) {
    set.status = 401
    return { error: 'Invalid credentials' }
  }

  set.headers['set-cookie'] = [
    `accessToken=${signAccessToken(user)}; HttpOnly; Path=/; SameSite=Lax`,
    `refreshToken=${signRefreshToken(user)}; HttpOnly; Path=/auth/refresh; SameSite=Strict`
  ]

  return { ok: true, role: user.role }
}, {
  body: t.Object({
    email: t.String(),
    password: t.String()
  })
})

/**
 * POST /auth/refresh
 * Issues new access token using valid refresh token.
 */
app.post('/auth/refresh', ({ request, set }) => {
  const cookies = parseCookie(request.headers.get('cookie'))
  const refreshToken = cookies.refreshToken

  if (!refreshToken) {
    set.status = 401
    return { error: 'No refresh token provided' }
  }

  const userId = refreshTokens.get(refreshToken)
  if (!userId) {
    set.status = 401
    return { error: 'Invalid or expired refresh token' }
  }

  const user = findUserById(userId)
  if (!user) {
    refreshTokens.delete(refreshToken)
    set.status = 401
    return { error: 'User not found' }
  }

  set.headers['set-cookie'] =
    `accessToken=${signAccessToken(user)}; HttpOnly; Path=/; SameSite=Lax`

  return { ok: true }
})

/**
 * POST /auth/logout
 * Clears auth cookies and revokes refresh token.
 */
app.post('/auth/logout', ({ request, set }) => {
  const cookies = parseCookie(request.headers.get('cookie'))
  const refreshToken = cookies.refreshToken

  if (refreshToken) {
    refreshTokens.delete(refreshToken)
  }

  set.headers['set-cookie'] = [
    'accessToken=; HttpOnly; Path=/; Max-Age=0',
    'refreshToken=; HttpOnly; Path=/auth/refresh; Max-Age=0'
  ]

  return { ok: true, message: 'Logged out successfully' }
})

// =============================================================================
// PROTECTED ROUTES
// Using .derive() in chain ensures proper type propagation
// =============================================================================

const protectedApp = new Elysia()
  // Derive user from JWT cookie - this adds 'user' to context with proper types
  .derive(({ request }): { user: AuthUser | null } => ({
    user: extractUser(request)
  }))
  // Global auth guard for all routes in this group
  .onBeforeHandle(({ user, set }) => {
    if (!user) {
      set.status = 401
      return { error: 'Unauthorized', message: 'Authentication required' }
    }
  })
  /**
   * GET /me
   * Returns authenticated user info.
   */
  .get('/me', ({ user }) => ({
    message: '✅ Authenticated',
    userId: user!.id,
    role: user!.role
  }))
  /**
   * GET /admin
   * Admin-only endpoint with role check.
   */
  .get('/admin', ({ user, set }) => {
    if (user!.role !== 'admin') {
      set.status = 403
      return { error: 'Forbidden', message: "Role 'admin' required" }
    }
    return {
      message: '👑 Admin access granted',
      userId: user!.id,
      role: user!.role
    }
  })

// Mount protected routes
app.use(protectedApp)

// =============================================================================
// SERVER STARTUP
// =============================================================================

const PORT = Number(process.env.PORT) || 8080

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`)
  console.log(`📝 Test credentials: admin@local / admin`)
  console.log(`📝 Test credentials: user@local / user`)
})