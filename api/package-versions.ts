/**
 * Package Versions API
 * Provides all versions for a specific package across all data sources
 */
import type { PsqlClient } from '@/cache/psql-client'
import type { HonoEnv } from '@worker'
import { Hono } from 'hono'

const app = new Hono<HonoEnv>()

// Pagination defaults
const DEFAULT_LIMIT = 100
const MAX_LIMIT = 500

interface VersionRecord {
    version: string
    ecosystem: string
    sources: string[]
}

interface PackageVersionsResponse {
    packageName: string
    timestamp: number
    total: number
    limit: number
    offset: number
    hasMore: boolean
    versions: VersionRecord[]
}

/**
 * GET /:package/versions - Get all versions for a package
 */
app.get('/:package/versions', async (c) => {
    const packageName = c.req.param('package').toLowerCase()
    const psql: PsqlClient = c.get('psql')
    const logger = c.get('logger')

    const limit = Math.min(
        parseInt(c.req.query('limit') || String(DEFAULT_LIMIT)),
        MAX_LIMIT
    )
    const offset = parseInt(c.req.query('offset') || '0')

    try {
        // Query all versions with source table aggregation
        const query = `
            SELECT 
                version,
                ecosystem,
                ARRAY_AGG(DISTINCT source_table) as sources
            FROM v_product_index
            WHERE package_name = $1
                AND version IS NOT NULL
            GROUP BY version, ecosystem
            ORDER BY version DESC, ecosystem
            LIMIT $2 OFFSET $3
        `

        const rows = await psql.$queryRaw<any[]>(
            query,
            { cacheKey: `package_versions:${packageName}:${limit}:${offset}`, ttl: 900, cache: true },
            packageName,
            limit,
            offset
        )

        // Get total count of versions
        const countQuery = `
            SELECT COUNT(DISTINCT version || ':' || ecosystem) as total
            FROM v_product_index
            WHERE package_name = $1
                AND version IS NOT NULL
        `

        const countResult = await psql.$queryRaw<any[]>(
            countQuery,
            { cacheKey: `package_versions:${packageName}:count`, ttl: 900, cache: true },
            packageName
        )

        const total = parseInt(countResult[0]?.total || '0')

        const versions: VersionRecord[] = rows.map((row) => ({
            version: row.version,
            ecosystem: row.ecosystem,
            sources: row.sources
        }))

        const response: PackageVersionsResponse = {
            packageName,
            timestamp: Math.floor(Date.now() / 1000),
            total,
            limit,
            offset,
            hasMore: (offset + limit) < total,
            versions
        }

        return c.json(response)
    } catch (error) {
        logger.error('Error fetching package versions:', error)
        return c.json({ error: 'Internal Server Error' }, 500)
    }
})

export default app
