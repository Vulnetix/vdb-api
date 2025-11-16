/**
 * JWT Authentication Middleware
 * Validates JWT Bearer tokens issued by /v1/auth/token endpoint
 */
import type { Context, Next } from 'hono'
import { jwtVerify } from 'jose'
import type { HonoEnv } from '@worker'

export interface JWTPayload {
    iss: string
    sub: string
    orgId: string
    accessKey: string
    iat: number
    exp: number
}

/**
 * JWT Authentication Middleware
 * Validates Bearer token and extracts claims
 */
export async function jwtAuth(c: Context<HonoEnv>, next: Next) {
    const logger = c.get('logger')

    try {
        const authHeader = c.req.header('Authorization')

        if (!authHeader) {
            return c.json({
                success: false,
                error: 'Missing Authorization header. Please provide a Bearer token.'
            }, 401)
        }

        if (!authHeader.startsWith('Bearer ')) {
            return c.json({
                success: false,
                error: 'Invalid Authorization header format. Expected "Bearer <token>".'
            }, 401)
        }

        const token = authHeader.substring(7) // Remove 'Bearer ' prefix

        if (!token) {
            return c.json({
                success: false,
                error: 'Missing JWT token'
            }, 401)
        }

        // Get JWT secret from environment
        const jwtSecret = c.env.JWT_SECRET
        if (!jwtSecret) {
            logger.error('JWT_SECRET environment variable not configured')
            return c.json({
                success: false,
                error: 'Server configuration error'
            }, 500)
        }

        // Verify JWT token
        const { payload } = await jwtVerify(
            token,
            new TextEncoder().encode(jwtSecret),
            {
                issuer: 'urn:vulnetix:vdb',
                algorithms: ['HS512']
            }
        )

        // Validate required claims
        if (!payload.sub || !payload.orgId || !payload.accessKey) {
            logger.warn('JWT token missing required claims', {
                hasSub: !!payload.sub,
                hasOrgId: !!payload.orgId,
                hasAccessKey: !!payload.accessKey
            })
            return c.json({
                success: false,
                error: 'Invalid token claims'
            }, 401)
        }

        // Extract orgId from sub claim (format: urn:uuid:{orgId})
        const subMatch = (payload.sub as string).match(/^urn:uuid:(.+)$/)
        if (!subMatch) {
            logger.warn('Invalid sub claim format', { sub: payload.sub })
            return c.json({
                success: false,
                error: 'Invalid token subject'
            }, 401)
        }

        const orgIdFromSub = subMatch[1]
        if (orgIdFromSub !== payload.orgId) {
            logger.warn('Org ID mismatch between sub and orgId claims', {
                subOrgId: orgIdFromSub,
                orgId: payload.orgId
            })
            return c.json({
                success: false,
                error: 'Invalid token claims'
            }, 401)
        }

        // Store JWT payload in context for use by route handlers
        c.set('jwt', payload as JWTPayload)
        c.set('orgId', payload.orgId as string)
        c.set('accessKey', payload.accessKey as string)

        await next()
    } catch (error) {
        // JWT verification failed
        if (error instanceof Error) {
            logger.warn('JWT verification failed', {
                error: error.message,
                name: error.name
            })

            // Provide specific error messages
            if (error.name === 'JWTExpired') {
                return c.json({
                    success: false,
                    error: 'Token has expired. Please obtain a new token from /v1/auth/token.'
                }, 401)
            }

            if (error.name === 'JWTClaimValidationFailed') {
                return c.json({
                    success: false,
                    error: 'Invalid token claims'
                }, 401)
            }

            if (error.name === 'JWTInvalid') {
                return c.json({
                    success: false,
                    error: 'Invalid token signature'
                }, 401)
            }
        }

        logger.error('JWT authentication error', error)
        return c.json({
            success: false,
            error: 'Authentication failed',
            details: error instanceof Error ? error.message : String(error)
        }, 401)
    }
}

/**
 * Optional JWT Authentication Middleware
 * Allows requests with or without JWT tokens, but validates if present
 */
export async function optionalJwtAuth(c: Context<HonoEnv>, next: Next) {
    const authHeader = c.req.header('Authorization')

    // If no auth header, proceed without authentication
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        await next()
        return
    }

    // If auth header present, validate it
    await jwtAuth(c, next)
}
