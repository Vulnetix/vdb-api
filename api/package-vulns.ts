/**
 * Package Vulnerabilities API
 * Provides all versions with associated CVE IDs for a specific package
 */
import type { PsqlClient } from '@/cache/psql-client'
import type { HonoEnv } from '@worker'
import { Hono } from 'hono'

const app = new Hono<HonoEnv>()

// Pagination defaults
const DEFAULT_LIMIT = 100
const MAX_LIMIT = 500

interface VulnVersionRecord {
    version: string
    ecosystem: string
    sources: string[]
    cveIds: string[]
}

interface PackageVulnsResponse {
    packageName: string
    timestamp: number
    totalCVEs: number
    total: number
    limit: number
    offset: number
    hasMore: boolean
    versions: VulnVersionRecord[]
}

/**
 * GET /:package/vulns - Get all versions with CVE IDs for a package
 */
app.get('/:package/vulns', async (c) => {
    const packageName = c.req.param('package').toLowerCase()
    const psql: PsqlClient = c.get('psql')
    const logger = c.get('logger')

    const limit = Math.min(
        parseInt(c.req.query('limit') || String(DEFAULT_LIMIT)),
        MAX_LIMIT
    )
    const offset = parseInt(c.req.query('offset') || '0')

    try {
        // Query all versions with CVE associations
        // We need to join with CVEAffected to get CVE IDs for each version
        const query = `
            WITH version_sources AS (
                SELECT 
                    package_name,
                    version,
                    ecosystem,
                    ARRAY_AGG(DISTINCT source_table) as sources
                FROM v_product_index
                WHERE package_name = $1
                    AND version IS NOT NULL
                GROUP BY package_name, version, ecosystem
            ),
            version_cves AS (
                SELECT DISTINCT
                    vpi.package_name,
                    vpi.version,
                    vpi.ecosystem,
                    cm."cveId"
                FROM v_product_index vpi
                LEFT JOIN "CVEAffected" ca 
                    ON LOWER(COALESCE(ca."packageName", ca.product)) = vpi.package_name
                LEFT JOIN "CVEMetadata" cm 
                    ON cm."cveId" = ca."cveId" AND cm.source = ca.source
                WHERE vpi.package_name = $1
                    AND vpi.version IS NOT NULL
                    AND cm."cveId" IS NOT NULL
            )
            SELECT 
                vs.version,
                vs.ecosystem,
                vs.sources,
                COALESCE(ARRAY_AGG(DISTINCT vc."cveId") FILTER (WHERE vc."cveId" IS NOT NULL), ARRAY[]::text[]) as cve_ids
            FROM version_sources vs
            LEFT JOIN version_cves vc 
                ON vs.package_name = vc.package_name 
                AND vs.version = vc.version 
                AND vs.ecosystem = vc.ecosystem
            GROUP BY vs.version, vs.ecosystem, vs.sources
            ORDER BY vs.version DESC, vs.ecosystem
            LIMIT $2 OFFSET $3
        `

        const rows = await psql.$queryRaw<any[]>(
            query,
            { cacheKey: `package_vulns:${packageName}:${limit}:${offset}`, ttl: 900, cache: true },
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
            { cacheKey: `package_vulns:${packageName}:count`, ttl: 900, cache: true },
            packageName
        )

        const total = parseInt(countResult[0]?.total || '0')

        // Get total unique CVEs
        const cveCountQuery = `
            SELECT COUNT(DISTINCT cm."cveId") as total_cves
            FROM v_product_index vpi
            LEFT JOIN "CVEAffected" ca 
                ON LOWER(COALESCE(ca."packageName", ca.product)) = vpi.package_name
            LEFT JOIN "CVEMetadata" cm 
                ON cm."cveId" = ca."cveId" AND cm.source = ca.source
            WHERE vpi.package_name = $1
                AND cm."cveId" IS NOT NULL
        `

        const cveCountResult = await psql.$queryRaw<any[]>(
            cveCountQuery,
            { cacheKey: `package_vulns:${packageName}:cve_count`, ttl: 900, cache: true },
            packageName
        )

        const totalCVEs = parseInt(cveCountResult[0]?.total_cves || '0')

        const versions: VulnVersionRecord[] = rows.map((row) => ({
            version: row.version,
            ecosystem: row.ecosystem,
            sources: row.sources,
            cveIds: row.cve_ids || []
        }))

        const response: PackageVulnsResponse = {
            packageName,
            timestamp: Math.floor(Date.now() / 1000),
            totalCVEs,
            total,
            limit,
            offset,
            hasMore: (offset + limit) < total,
            versions
        }

        return c.json(response)
    } catch (error) {
        logger.error('Error fetching package vulnerabilities:', error)
        return c.json({ error: 'Internal Server Error' }, 500)
    }
})

export default app
