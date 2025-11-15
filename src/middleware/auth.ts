/**
 * Authentication middleware for validating Google SSO sessions
 * Validates JWT cookies and verifies Google access tokens
 */

import type { Context, Next } from 'hono'
import { getCookie } from 'hono/cookie'
import { SignJWT, jwtVerify } from 'jose'
import type { HonoEnv } from '../../_worker'
import { unauthenticatedRoutes } from '../shared/routes'

const SESSION_COOKIE_NAME = 'session'
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 // 7 days in seconds

/**
 * Generate a JWT token for a session
 */
export async function generateSessionJWT(sessionId: string, secret: string): Promise<string> {
    const encoder = new TextEncoder()
    const secretKey = encoder.encode(secret)

    const token = await new SignJWT({ sessionId })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(secretKey)

    return token
}

/**
 * Verify a JWT token and extract session ID
 */
export async function verifySessionJWT(token: string, secret: string): Promise<string | null> {
    try {
        const encoder = new TextEncoder()
        const secretKey = encoder.encode(secret)

        const { payload } = await jwtVerify(token, secretKey)
        return payload.sessionId as string
    } catch (error) {
        return null
    }
}

/**
 * Validate Google access token by calling Google's tokeninfo endpoint
 * This provides opaque token validation against Google's servers
 */
export async function validateGoogleToken(accessToken: string): Promise<boolean> {
    try {
        const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${accessToken}`)

        if (!response.ok) {
            return false
        }

        const tokenInfo = await response.json() as any

        // Verify token has required fields and is not expired
        if (!tokenInfo.email || !tokenInfo.exp) {
            return false
        }

        // Check if token is expired (exp is in seconds)
        const expiryTime = parseInt(tokenInfo.exp) * 1000 // Convert to milliseconds
        if (Date.now() >= expiryTime) {
            return false
        }

        return true
    } catch (error) {
        return false
    }
}

/**
 * Check if the route is unauthenticated (doesn't require auth)
 */
export function isUnauthenticatedRoute(path: string): boolean {
    // Check static routes
    if (unauthenticatedRoutes.static.includes(path)) {
        return true
    }

    // Check route prefixes
    for (const prefix of unauthenticatedRoutes.prefixes) {
        if (path.startsWith(prefix)) {
            return true
        }
    }

    return false
}

/**
 * Authentication middleware
 * Validates JWT session cookie and Google access token for protected routes
 */
export async function authMiddleware(c: Context<HonoEnv>, next: Next) {
    const path = new URL(c.req.url).pathname
    const logger = c.get('logger')

    // Skip authentication for unauthenticated routes
    if (isUnauthenticatedRoute(path)) {
        return await next()
    }

    // Extract session cookie
    const sessionToken = getCookie(c, SESSION_COOKIE_NAME)

    if (!sessionToken) {
        logger?.debug('No session cookie found', { path })
        return c.json({ error: 'Unauthorized', message: 'No session cookie' }, 401)
    }

    // Verify JWT and extract session ID
    const jwtSecret = c.env.JWT_SECRET
    if (!jwtSecret) {
        logger?.error('JWT_SECRET not configured')
        return c.json({ error: 'Server configuration error' }, 500)
    }

    const sessionId = await verifySessionJWT(sessionToken, jwtSecret)

    if (!sessionId) {
        logger?.debug('Invalid session token', { path })
        return c.json({ error: 'Unauthorized', message: 'Invalid session token' }, 401)
    }

    // Load session from database
    const prisma = c.get('prisma')
    const session = await prisma.session.findUnique({
        where: { id: sessionId },
        include: { user: true }
    })

    if (!session) {
        logger?.debug('Session not found in database', { sessionId })
        return c.json({ error: 'Unauthorized', message: 'Session not found' }, 401)
    }

    // Check if session is expired
    if (session.expiresAt < new Date()) {
        logger?.debug('Session expired', { sessionId, expiresAt: session.expiresAt })

        // Clean up expired session
        await prisma.session.delete({ where: { id: sessionId } }).catch(() => {})

        return c.json({ error: 'Unauthorized', message: 'Session expired' }, 401)
    }

    // Validate Google access token (opaque validation)
    const isValidToken = await validateGoogleToken(session.accessToken)

    if (!isValidToken) {
        logger?.debug('Google access token invalid or expired', { sessionId })

        // TODO: Implement token refresh logic if refresh token is available
        // For now, just invalidate the session
        await prisma.session.delete({ where: { id: sessionId } }).catch(() => {})

        return c.json({ error: 'Unauthorized', message: 'Access token invalid or expired' }, 401)
    }

    // Set user and session in context for downstream handlers
    c.set('user', session.user)
    c.set('session', session)

    return await next()
}
