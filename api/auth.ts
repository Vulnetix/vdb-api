/**
 * Authentication API
 * AWS SigV4 client credential authentication with JWT token exchange
 */
import type { PrismaClient } from '@prisma/client'
import type { HonoEnv } from '@worker'
import { Hono } from 'hono'
import { SignJWT } from 'jose'
import { parseAuthorizationHeader, validateSigV4Signature, normalizeHeaders } from '@/shared/sigv4'

const app = new Hono<HonoEnv>()

/**
 * Decrypt secret key (placeholder - implement based on your encryption method)
 * For now, assuming secretKey is stored in plain text or you have a decryption utility
 */
function decryptSecretKey(encryptedKey: string): string {
    // TODO: Implement actual decryption if secretKey is encrypted
    // For now, return as-is assuming it's stored in plain text
    return encryptedKey
}

/**
 * Check IP whitelist
 */
function isIpAllowed(clientIp: string, ipWhitelist: any): boolean {
    if (!ipWhitelist || !Array.isArray(ipWhitelist) || ipWhitelist.length === 0) {
        return true // No whitelist means all IPs allowed
    }

    // Simple exact match for now
    // TODO: Implement CIDR range matching if needed
    return ipWhitelist.includes(clientIp)
}

/**
 * GET /auth/token
 * Exchange client credentials (via AWS SigV4) for JWT token
 */
app.get('/token', async (c) => {
    const prisma: PrismaClient = c.get('prisma')
    const logger = c.get('logger')

    try {
        const authHeader = c.req.header('Authorization')
        if (!authHeader || !authHeader.startsWith('AWS4-HMAC-SHA512')) {
            return c.json({
                success: false,
                error: 'Missing or invalid Authorization header. Expected AWS4-HMAC-SHA512 signature.'
            }, 401)
        }

        // Parse Authorization header
        const parsedAuth = parseAuthorizationHeader(authHeader)
        if (!parsedAuth) {
            return c.json({
                success: false,
                error: 'Invalid AWS SigV4 Authorization header format'
            }, 401)
        }

        const { accessKey } = parsedAuth

        // Look up client credentials in Organization table
        const organization = await prisma.organization.findUnique({
            where: { uuid: accessKey },
            select: {
                uuid: true,
                secret: true,
                isActive: true,
                accessLogs: true,
            }
        })

        if (!organization) {
            logger.warn('Authentication failed: Invalid access key', { accessKey })
            return c.json({
                success: false,
                error: 'Invalid credentials'
            }, 401)
        }

        // Check if credentials are active
        if (!organization.isActive) {
            logger.warn('Authentication failed: Inactive credentials', { accessKey, uuid: organization.uuid })
            return c.json({
                success: false,
                error: 'Credentials are inactive'
            }, 401)
        }

        //TODO: Check expiration from JWT in Session

        // Validate SigV4 signature
        const secretKey = decryptSecretKey(organization.secret)
        const method = c.req.method
        const url = new URL(c.req.url)
        const path = url.pathname
        const queryString = url.search.slice(1) // Remove leading '?'
        const headers = normalizeHeaders(c.req.raw)
        const body = '' // GET request has no body

        const isValid = await validateSigV4Signature(
            method,
            path,
            queryString,
            headers,
            body,
            secretKey,
            parsedAuth
        )

        if (!isValid) {
            logger.warn('Authentication failed: Invalid signature', { accessKey, uuid: organization.uuid })
            return c.json({
                success: false,
                error: 'Invalid signature'
            }, 401)
        }

        // Generate JWT token
        const jwtSecret = c.env.JWT_SECRET
        if (!jwtSecret) {
            logger.error('JWT_SECRET environment variable not configured')
            return c.json({
                success: false,
                error: 'Server configuration error'
            }, 500)
        }

        const expiresIn = 15 * 60 // 15 minutes in seconds
        const now = Math.floor(Date.now() / 1000) // Current Unix timestamp in seconds
        const exp = now + expiresIn

        const token = await new SignJWT({
            iss: 'urn:vulnetix:vdb',
            sub: `urn:uuid:${organization.uuid}`,
            orgId: organization.uuid,
            accessKey: accessKey
        })
            .setProtectedHeader({ alg: 'HS512', typ: 'JWT' })
            .setIssuedAt(now)
            .setExpirationTime(exp)
            .sign(new TextEncoder().encode(jwtSecret))

        logger.info('JWT token issued', {
            accessKey,
            orgId: organization.uuid,
            clientIp: c.req.header['CF-Connecting-IP'] || 'unknown',
            expiresAt: exp
        })

        return c.json({
            token,
            iss: 'urn:vulnetix:vdb',
            sub: `urn:uuid:${organization.uuid}`,
            exp
        })
    } catch (error) {
        logger.error('Error during authentication:', error)
        return c.json({
            success: false,
            error: 'Authentication failed',
            details: error instanceof Error ? error.message : String(error)
        }, 500)
    }
})

export default app
