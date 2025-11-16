/**
 * Product/Package API
 * Provides normalized product/package information across all data sources
 * Uses v_product_index view for efficient querying
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
    sources: Array<{
        sourceTable: string
        sourceId: string
        metadata?: Record<string, any>
    }>
    cveIds?: string[]
}

interface ProductResponse {
    packageName: string
    ecosystem?: string
    timestamp: number
    total: number
    limit: number
    offset: number
    hasMore: boolean
    versions: VersionRecord[]
}

/**
 * Build version records from raw query results
 */
function buildVersionRecords(rows: any[]): Map<string, VersionRecord> {
    const versionMap = new Map<string, VersionRecord>()

    for (const row of rows) {
        const versionKey = `${row.version || 'unknown'}:${row.ecosystem}`

        if (!versionMap.has(versionKey)) {
            versionMap.set(versionKey, {
                version: row.version || 'unknown',
                ecosystem: row.ecosystem,
                sources: []
            })
        }

        const record = versionMap.get(versionKey)!
        record.sources.push({
            sourceTable: row.source_table,
            sourceId: row.source_id
        })
    }

    return versionMap
}

/**
 * GET /:name - All versions and ecosystems for a package name
 */
app.get('/:name', async (c) => {
    const packageName = c.req.param('name').toLowerCase()
    const psql: PsqlClient = c.get('psql')
    const logger = c.get('logger')

    const limit = Math.min(
        parseInt(c.req.query('limit') || String(DEFAULT_LIMIT)),
        MAX_LIMIT
    )
    const offset = parseInt(c.req.query('offset') || '0')

    try {
        // Query the product index view with pagination
        const query = `
            SELECT 
                package_name,
                ecosystem,
                source_table,
                source_id,
                version
            FROM v_product_index
            WHERE package_name = $1
            ORDER BY 
                CASE 
                    WHEN version IS NOT NULL THEN 0 
                    ELSE 1 
                END,
                version DESC NULLS LAST,
                ecosystem,
                source_table
            LIMIT $2 OFFSET $3
        `

        const rows = await psql.$queryRaw<any[]>(
            query,
            { cacheKey: `product:${packageName}:${limit}:${offset}`, ttl: 900, cache: true },
            packageName,
            limit,
            offset
        )

        // Get total count for pagination
        const countQuery = `
            SELECT COUNT(*) as total
            FROM v_product_index
            WHERE package_name = $1
        `

        const countResult = await psql.$queryRaw<any[]>(
            countQuery,
            { cacheKey: `product:${packageName}:count`, ttl: 900, cache: true },
            packageName
        )

        const total = parseInt(countResult[0]?.total || '0')

        // Build version records
        const versionMap = buildVersionRecords(rows)
        const versions = Array.from(versionMap.values())

        const response: ProductResponse = {
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
        logger.error('Error fetching product information:', error)
        return c.json({ error: 'Internal Server Error' }, 500)
    }
})

/**
 * GET /:name/:version - Specific version filtered
 */
app.get('/:name/:version', async (c) => {
    const packageName = c.req.param('name').toLowerCase()
    const version = c.req.param('version')
    const psql: PsqlClient = c.get('psql')
    const logger = c.get('logger')

    const limit = Math.min(
        parseInt(c.req.query('limit') || String(DEFAULT_LIMIT)),
        MAX_LIMIT
    )
    const offset = parseInt(c.req.query('offset') || '0')

    try {
        // Query the product index view filtered by version
        const query = `
            SELECT 
                package_name,
                ecosystem,
                source_table,
                source_id,
                version
            FROM v_product_index
            WHERE package_name = $1
                AND version = $2
            ORDER BY ecosystem, source_table
            LIMIT $3 OFFSET $4
        `

        const rows = await psql.$queryRaw<any[]>(
            query,
            { cacheKey: `product:${packageName}:${version}:${limit}:${offset}`, ttl: 900, cache: true },
            packageName,
            version,
            limit,
            offset
        )

        // Get total count
        const countQuery = `
            SELECT COUNT(*) as total
            FROM v_product_index
            WHERE package_name = $1 AND version = $2
        `

        const countResult = await psql.$queryRaw<any[]>(
            countQuery,
            { cacheKey: `product:${packageName}:${version}:count`, ttl: 900, cache: true },
            packageName,
            version
        )

        const total = parseInt(countResult[0]?.total || '0')

        // Build version records
        const versionMap = buildVersionRecords(rows)
        const versions = Array.from(versionMap.values())

        const response: ProductResponse = {
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
        logger.error('Error fetching product version:', error)
        return c.json({ error: 'Internal Server Error' }, 500)
    }
})

/**
 * GET /:name/:version/:ecosystem - Version and ecosystem filtered
 */
app.get('/:name/:version/:ecosystem', async (c) => {
    const packageName = c.req.param('name').toLowerCase()
    const version = c.req.param('version')
    const ecosystem = c.req.param('ecosystem').toLowerCase()
    const psql: PsqlClient = c.get('psql')
    const logger = c.get('logger')

    const limit = Math.min(
        parseInt(c.req.query('limit') || String(DEFAULT_LIMIT)),
        MAX_LIMIT
    )
    const offset = parseInt(c.req.query('offset') || '0')

    try {
        // Query the product index view filtered by version and ecosystem
        const query = `
            SELECT 
                package_name,
                ecosystem,
                source_table,
                source_id,
                version
            FROM v_product_index
            WHERE package_name = $1
                AND version = $2
                AND ecosystem = $3
            ORDER BY source_table
            LIMIT $4 OFFSET $5
        `

        const rows = await psql.$queryRaw<any[]>(
            query,
            { cacheKey: `product:${packageName}:${version}:${ecosystem}:${limit}:${offset}`, ttl: 900, cache: true },
            packageName,
            version,
            ecosystem,
            limit,
            offset
        )

        // Get total count
        const countQuery = `
            SELECT COUNT(*) as total
            FROM v_product_index
            WHERE package_name = $1 AND version = $2 AND ecosystem = $3
        `

        const countResult = await psql.$queryRaw<any[]>(
            countQuery,
            { cacheKey: `product:${packageName}:${version}:${ecosystem}:count`, ttl: 900, cache: true },
            packageName,
            version,
            ecosystem
        )

        const total = parseInt(countResult[0]?.total || '0')

        // Build version records
        const versionMap = buildVersionRecords(rows)
        const versions = Array.from(versionMap.values())

        const response: ProductResponse = {
            packageName,
            ecosystem,
            timestamp: Math.floor(Date.now() / 1000),
            total,
            limit,
            offset,
            hasMore: (offset + limit) < total,
            versions
        }

        return c.json(response)
    } catch (error) {
        logger.error('Error fetching product version with ecosystem:', error)
        return c.json({ error: 'Internal Server Error' }, 500)
    }
})

export default app
