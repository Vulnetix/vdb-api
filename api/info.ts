/**
 * CVE Information API
 * Provides unified CVE metadata and R2 file tracking across all data sources
 */
import { PsqlClient } from '@/cache/psql-client'
import type { PrismaClient } from '@prisma/client'
import type { HonoEnv } from '@worker'
import { Hono } from 'hono'

const app = new Hono<HonoEnv>()

/**
 * Data source configuration for R2 file matching
 */
interface DataSourceConfig {
    name: string
    table: string
    schema: string // Schema format for the data (e.g., 'cvelistV5', 'osv', 'nvd-json')
    r2BaseUrl: string
}

const DATA_SOURCES: DataSourceConfig[] = [
    { name: 'mitre', table: 'mitreCveFile', schema: 'cvelistV5', r2BaseUrl: 'https://artifacts.vulnetix.com' },
    { name: 'nist-nvd', table: 'nistNvdFile', schema: 'nvd-json-2.0', r2BaseUrl: 'https://artifacts.vulnetix.com' },
    { name: 'vulncheck-nvd', table: 'vulnCheckNvdFile', schema: 'nvd-json-2.0', r2BaseUrl: 'https://artifacts.vulnetix.com' },
    { name: 'vulncheck-kev', table: 'vulnCheckKevFile', schema: 'vulncheck-kev', r2BaseUrl: 'https://artifacts.vulnetix.com' },
    { name: 'cisa-kev', table: 'cisaKevFile', schema: 'cisa-kev', r2BaseUrl: 'https://artifacts.vulnetix.com' },
    { name: 'ghsa', table: 'ghsaFile', schema: 'osv', r2BaseUrl: 'https://artifacts.vulnetix.com' },
    { name: 'osv', table: 'osvFile', schema: 'osv', r2BaseUrl: 'https://artifacts.vulnetix.com' },
    { name: 'euvd', table: 'euvdFile', schema: 'euvd', r2BaseUrl: 'https://artifacts.vulnetix.com' }
]

/**
 * Match CVE ID in R2 files for MITRE source
 * MITRE files are structured as cves/YYYY/Nxxx/CVE-YYYY-NNNNN.json
 */
async function findMitreR2File(prisma: PrismaClient, cveId: string) {
    // Extract year from CVE ID (e.g., CVE-2024-1234 -> 2024)
    const yearMatch = cveId.match(/CVE-(\d{4})-/)
    if (!yearMatch) return null

    const year = yearMatch[1]
    const pattern = `%/cves/${year}/%/${cveId}.json`

    const file = await prisma.mitreCveFile.findFirst({
        where: {
            r2Path: { contains: pattern.replace('%', '') }
        },
        orderBy: { createdAt: 'desc' }
    })

    return file
}

/**
 * Match CVE ID in R2 files for NIST NVD source
 */
async function findNistNvdR2File(prisma: PrismaClient, cveId: string) {
    // NIST files contain multiple CVEs, so we need to check if this CVE was processed from a file
    const file = await prisma.nistNvdFile.findFirst({
        where: {
            status: { in: ['completed', 'processing', 'ready'] },
            r2Path: { not: null }
        },
        orderBy: { createdAt: 'desc' }
    })

    return file
}

/**
 * Match CVE ID in R2 files for VulnCheck NVD source
 */
async function findVulnCheckNvdR2File(prisma: PrismaClient, cveId: string) {
    const file = await prisma.vulnCheckNvdFile.findFirst({
        where: {
            status: { in: ['completed', 'processing', 'ready'] },
            r2Path: { not: null }
        },
        orderBy: { createdAt: 'desc' }
    })

    return file
}

/**
 * Match CVE ID in R2 files for VulnCheck KEV source
 */
async function findVulnCheckKevR2File(prisma: PrismaClient, cveId: string) {
    // Check if this CVE is referenced in VulnCheck KEV records
    const kevCve = await prisma.vulnCheckKEVCVE.findFirst({
        where: { cveId },
        include: {
            kev: true
        }
    })

    if (!kevCve) return null

    const file = await prisma.vulnCheckKevFile.findFirst({
        where: {
            status: { in: ['completed', 'processing', 'ready'] },
            r2Path: { not: null }
        },
        orderBy: { createdAt: 'desc' }
    })

    return file
}

/**
 * Match CVE ID in R2 files for CISA KEV source
 */
async function findCisaKevR2File(prisma: PrismaClient, cveId: string) {
    // Check if this CVE exists in CISA KEV
    const kev = await prisma.kev.findFirst({
        where: {
            cveID: cveId,
            source: 'CISA'
        }
    })

    if (!kev) return null

    const file = await prisma.cisaKevFile.findFirst({
        where: {
            status: { in: ['completed', 'processing', 'ready'] },
            r2Path: { not: null }
        },
        orderBy: { createdAt: 'desc' }
    })

    return file
}

/**
 * Match CVE ID in R2 files for GHSA source
 */
async function findGhsaR2File(prisma: PrismaClient, cveId: string) {
    // GHSA files may reference CVEs, need to check CVEMetadata for ghsa source
    const metadata = await prisma.cVEMetadata.findFirst({
        where: {
            cveId,
            source: 'ghsa'
        }
    })

    if (!metadata) return null

    const file = await prisma.ghsaFile.findFirst({
        where: {
            status: { in: ['completed', 'processing', 'ready'] },
            r2Path: { not: null }
        },
        orderBy: { createdAt: 'desc' }
    })

    return file
}

/**
 * Match CVE ID in R2 files for OSV source
 */
async function findOsvR2File(prisma: PrismaClient, cveId: string) {
    // OSV files may reference CVEs
    const metadata = await prisma.cVEMetadata.findFirst({
        where: {
            cveId,
            source: 'osv'
        }
    })

    if (!metadata) return null

    const file = await prisma.osvFile.findFirst({
        where: {
            status: { in: ['completed', 'processing', 'ready'] },
            r2Path: { not: null }
        },
        orderBy: { createdAt: 'desc' }
    })

    return file
}

/**
 * Match CVE ID in R2 files for EUVD source
 */
async function findEuvdR2File(prisma: PrismaClient, cveId: string) {
    const metadata = await prisma.cVEMetadata.findFirst({
        where: {
            cveId,
            source: 'euvd'
        }
    })

    if (!metadata) return null

    const file = await prisma.euvdFile.findFirst({
        where: {
            status: { in: ['completed', 'processing', 'ready'] },
            r2Path: { not: null }
        },
        orderBy: { createdAt: 'desc' }
    })

    return file
}

/**
 * GET /info/:identifier
 * Returns comprehensive CVE information including metadata and R2 file tracking
 */
app.get('/:identifier', async (c) => {
    const prisma: PrismaClient = c.get('prisma')
    const psql: PsqlClient = c.get('psql')
    const logger = c.get('logger')
    let cveId = c.req.param('identifier').toUpperCase()

    try {
        const startTime = Date.now()

        // Normalize identifier to GHSA format
        if (cveId.startsWith('GHSA-')) {
            cveId = cveId.toLowerCase()
        }

        // Query all CVEMetadata records for this CVE across all sources
        const cveRecords = await psql.findMany('CVEMetadata', {
            where: { cveId },
            include: {
                references: true,
                problemTypes: true,
                metrics: true,
                affected: true,
                impacts: true,
                descriptions: true,
                scorecard: true,
                gcveIssuances: true,
                primaryAliases: {
                    include: {
                        aliasCve: true
                    }
                },
                aliasedBy: {
                    include: {
                        primaryCve: true
                    }
                }
            }
        })

        // Check for R2 files across all sources
        const r2FileChecks = await Promise.allSettled([
            findMitreR2File(prisma, cveId),
            findNistNvdR2File(prisma, cveId),
            findVulnCheckNvdR2File(prisma, cveId),
            findVulnCheckKevR2File(prisma, cveId),
            findCisaKevR2File(prisma, cveId),
            findGhsaR2File(prisma, cveId),
            findOsvR2File(prisma, cveId),
            findEuvdR2File(prisma, cveId)
        ])

        // Map R2 file results
        const r2Files: { [key: string]: any } = {}
        DATA_SOURCES.forEach((source, index) => {
            const result = r2FileChecks[index]
            if (result.status === 'fulfilled' && result.value) {
                r2Files[source.name] = result.value
            }
        })

        // Build sources array
        const sources: any[] = []
        const sourcesWithData = new Set<string>()

        // Add sources that have CVEMetadata records
        cveRecords.forEach(record => {
            sourcesWithData.add(record.source)
            const hasR2File = r2Files[record.source] !== undefined
            sources.push({
                name: record.source,
                processing: false // CVEMetadata exists, so not processing
            })
        })

        // Add sources that only have R2 files (processing = true)
        Object.keys(r2Files).forEach(sourceName => {
            if (!sourcesWithData.has(sourceName)) {
                sources.push({
                    name: sourceName,
                    processing: true // Only R2 file exists, still processing
                })
            }
        })

        const matched = cveRecords.length > 0 || Object.keys(r2Files).length > 0

        // Check for GCVE issuance
        const gcveIssuances = cveRecords.flatMap(r => r.gcveIssuances || [])
        const hasGcve = gcveIssuances.length > 0

        // Aggregate counts
        const totalReferences = cveRecords.reduce((sum, r) => sum + (r.references?.length || 0), 0)
        const totalProblemTypes = cveRecords.reduce((sum, r) => sum + (r.problemTypes?.length || 0), 0)
        const totalMetrics = cveRecords.reduce((sum, r) => sum + (r.metrics?.length || 0), 0)
        const totalAffected = cveRecords.reduce((sum, r) => sum + (r.affected?.length || 0), 0)
        const totalImpacts = cveRecords.reduce((sum, r) => sum + (r.impacts?.length || 0), 0)
        const totalDescriptions = cveRecords.reduce((sum, r) => sum + (r.descriptions?.length || 0), 0)
        const totalScorecards = cveRecords.filter(r => r.scorecard).length

        // Collect unique aliases
        const aliasSet = new Set<string>()
        cveRecords.forEach(record => {
            record.primaryAliases.forEach(alias => {
                aliasSet.add(alias.aliasCveId)
            })
            record.aliasedBy.forEach(alias => {
                aliasSet.add(alias.primaryCveId)
            })
        })
        const aliases = Array.from(aliasSet).filter(a => a !== cveId)

        // Get latest fetched and enriched timestamps
        const lastFetchedAt = cveRecords.length > 0
            ? Math.max(...cveRecords.map(r => r.lastFetchedAt))
            : null
        const lastEnrichedAt = cveRecords.length > 0
            ? Math.max(...cveRecords.filter(r => r.lastEnriched).map(r => r.lastEnriched!))
            : null

        // Build links array
        const links: any[] = []

        // Add page link if matched
        if (matched) {
            links.push({
                type: 'page',
                format: 'http',
                url: `https://vdb.vulnetix.com/${cveId}`
            })
        }

        // Add R2 file links
        Object.entries(r2Files).forEach(([sourceName, file]: [string, any]) => {
            const sourceConfig = DATA_SOURCES.find(s => s.name === sourceName)
            if (file.r2Path && sourceConfig) {
                links.push({
                    type: sourceName,
                    format: sourceConfig.schema,
                    url: `${sourceConfig.r2BaseUrl}${file.r2Path}`
                })
            }
        })

        const response = {
            _identifier: cveId,
            _timestamp: Math.floor(Date.now() / 1000),
            matched,
            gcve: hasGcve,
            lastFetchedAt,
            lastEnrichedAt,
            sources,
            aliases,
            references: totalReferences,
            problemTypes: totalProblemTypes,
            metrics: totalMetrics,
            affected: totalAffected,
            impacts: totalImpacts,
            descriptions: totalDescriptions,
            scorecards: totalScorecards,
            links
        }

        logger.info('CVE info retrieved', {
            identifier: cveId,
            matched,
            sources: sources.length,
            duration: Date.now() - startTime
        })

        return c.json(response)
    } catch (error) {
        logger.error('Error fetching CVE info:', error)
        return c.json({
            success: false,
            error: 'Failed to fetch CVE information',
            details: error instanceof Error ? error.message : String(error)
        }, 500)
    }
})

export default app
