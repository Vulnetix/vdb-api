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
        documentation: '/v1/spec/ui',
        openapi: '/v1/spec',
        availableEndpoints: [
            'GET /v1/spec - OpenAPI specification',
            'GET /v1/spec/ui - Swagger UI',
            'GET /v1/auth/token - Exchange SigV4-signed request for JWT token',
            'GET /v1/info/{identifier} - CVE metadata and data source information',
            'GET /v1/vuln/{identifier} - Vulnerability records in CVEListV5 format',
            'GET /v1/exploits/{identifier} - Exploit intelligence and sightings',
            'GET /v1/product/{name} - Product information by package name',
            'GET /v1/product/{name}/{version} - Product information for specific version',
            'GET /v1/product/{name}/{version}/{ecosystem} - Product information for version and ecosystem',
            'GET /v1/ecosystems - List all ecosystems with package counts',
            'GET /v1/{package}/versions - All versions for a package',
            'GET /v1/{package}/vulns - All vulnerabilities affecting a package'
        ]
    }, 404)
})

export default app
