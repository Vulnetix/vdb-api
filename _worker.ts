/**
 * Cloudflare Workers - VDB Manager (Simplified)
 * Main worker that sets up Hono with middleware and routes
 */

import { PrismaPg } from '@prisma/adapter-pg'
import { PrismaClient } from '@prisma/client'
import anylogger from 'anylogger'
import 'anylogger-console'
import { Hono } from 'hono'
import { Pool } from 'pg'
import { v4 as uuidv4 } from 'uuid'
import { DEFAULT_CACHE_OPTIONS } from './src/cache/cache-options'
import { createPsqlClient, type PsqlClient } from './src/cache/psql-client'

// Import route handlers that actually exist
import catchAllHandler from './api/[[catchall]]'
import oasAPI from './api/oas'
import swaggerUI from './api/swagger'
import infoAPI from './api/info'
import vulnAPI from './api/vuln'
import exploitsAPI from './api/exploits'
import authAPI from './api/auth'

import { authMiddleware } from './src/middleware/auth'

// Export JWTPayload type
export interface JWTPayload {
    iss: string
    sub: string
    orgId: string
    accessKey: string
    iat: number
    exp: number
}

// Export HonoEnv type for use in Functions
export type HonoEnv = {
    Bindings: Env
    Variables: {
        prisma: PrismaClient
        psql: PsqlClient
        logger: any
        correlationId: string
        json?: any
        jwt?: JWTPayload
        orgId?: string
        accessKey?: string
        user?: any
        session?: any
    }
}

const app = new Hono<HonoEnv>()

// Global middleware - runs for all requests
app.use('*', async (c, next) => {
    const correlationId = uuidv4()
    c.set('correlationId', correlationId)

    // Set up logger
    const log = anylogger('worker')
    const logLevel = c.env.LOG_LEVEL || 'INFO'
    const levels: Record<string, number> = {
        'TRACE': 10, 'DEBUG': 20, 'INFO': 30, 'WARN': 40, 'ERROR': 50
    }
    log.enabledFor = (level: string) => (levels[level] || 30) >= (levels[logLevel] || 30)
    c.set('logger', log)

    // Set up Prisma with Postgres adapter via Hyperdrive
    const pool = new Pool({ connectionString: c.env.vdb.connectionString })
    const adapter = new PrismaPg(pool)
    const prisma = new PrismaClient({ adapter })
    c.set('prisma', prisma)

    // Set up psql caching client
    const psql = createPsqlClient(prisma, c.env.QUERY_CACHE, DEFAULT_CACHE_OPTIONS)
    c.set('psql', psql)

    await next()
})

// Authentication middleware - validates JWT sessions for protected routes
app.use('*', authMiddleware)

// API Version 1 Routes
// Mount OpenAPI specification route (public - no auth required)
app.route('/v1/spec', oasAPI)
app.route('/v1/swagger', swaggerUI)

// Mount CVE info API route (requires JWT auth and rate limiting)
app.route('/v1/info', infoAPI)

// Mount vulnerability API route (requires JWT auth and rate limiting)
app.route('/v1/vuln', vulnAPI)

// Mount exploits API route (requires JWT auth and rate limiting)
app.route('/v1/exploits', exploitsAPI)

// Mount authentication API route (public - used to GET JWT tokens)
app.route('/auth', authAPI)

// Catch-all handler for assets, artifacts, blog SSR, and SPA fallback (public - no auth required)
// This must be last to ensure it doesn't intercept API routes
app.route('/', catchAllHandler)

// The actual worker export
export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        return app.fetch(request, env, ctx)
    }
}
