/**
 * Catch-all handler for API-only mode
 * Returns API information for non-matching routes
 */

import { Hono } from 'hono'
import type { HonoEnv } from '../_worker'

const app = new Hono<HonoEnv>()

// Handle all routes that aren't API endpoints
app.all('*', async (c) => {
    return c.json({
        message: 'VDB API - Invalid endpoint',
        documentation: '/v1/swagger',
        openapi: '/v1/spec',
        availableEndpoints: [
            'GET /v1/spec - OpenAPI specification',
            'GET /v1/swagger - Swagger UI',
            'GET /auth/token - Exchange SigV4-signed request for JWT token',
            'GET /v1/info/{identifier} - CVE metadata and data source information',
            'GET /v1/vuln/{identifier} - Vulnerability records in CVEListV5 format',
            'GET /v1/exploits/{identifier} - Exploit intelligence and sightings'
        ]
    }, 404)
})

export default app
