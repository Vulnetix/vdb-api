/**
 * Ecosystems API
 * Provides list of supported package ecosystems with usage counts
 */
import type { PsqlClient } from '@/cache/psql-client'
import type { HonoEnv } from '@worker'
import { Hono } from 'hono'

const app = new Hono<HonoEnv>()

interface EcosystemRecord {
    name: string
    count: number
}

interface EcosystemsResponse {
    timestamp: number
    ecosystems: EcosystemRecord[]
}

/**
 * GET / - List all ecosystems with usage counts
 */
app.get('/', async (c) => {
    const psql: PsqlClient = c.get('psql')
    const logger = c.get('logger')

    try {
        // Query distinct ecosystems from the product index view with counts
        const query = `
            SELECT 
                ecosystem,
                COUNT(DISTINCT package_name) as count
            FROM v_product_index
            WHERE ecosystem IS NOT NULL
                AND ecosystem != ''
            GROUP BY ecosystem
            ORDER BY count DESC, ecosystem ASC
        `

        const rows = await psql.$queryRaw<any[]>(
            query,
            { cacheKey: 'ecosystems:all', ttl: 1800, cache: true }
        )

        const ecosystems: EcosystemRecord[] = rows.map((row) => ({
            name: row.ecosystem,
            count: parseInt(row.count)
        }))

        const response: EcosystemsResponse = {
            timestamp: Math.floor(Date.now() / 1000),
            ecosystems
        }

        return c.json(response)
    } catch (error) {
        logger.error('Error fetching ecosystems:', error)
        return c.json({ error: 'Internal Server Error' }, 500)
    }
})

export default app
