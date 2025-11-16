/**
 * CVE Information API - CVEListV5 Format Array
 * Returns an array of CVEListV5 format records, one for each distinct source
 */
import { createVulnIdResolver } from '@/services/vdb/vulnIdResolver'
import { createVulnProcessor } from '@/services/vdb/vulnProcessor'
import { Validator } from '@cfworker/json-schema'
import type { PrismaClient } from '@prisma/client'
import type { HonoEnv } from '@worker'
import { Hono } from 'hono'

const app = new Hono<HonoEnv>()

// Load CVE Record Format schema and create validator
const cveRecordSchema = require('@schemas/CVE_Record_Format.json')
const cveRecordValidator = new Validator(cveRecordSchema as any)

/**
 * Build a CVEListV5 format record for a specific source
 */
async function buildCVEListV5Record(
    prisma: PrismaClient,
    cveMetadata: any,
    logger: any,
    r2adapter: any
): Promise<any> {
    const normalizedVulnId = cveMetadata.cveId

    // Start with base structure
    const cvelistv5: any = {
        dataType: 'CVE_RECORD',
        dataVersion: '5.1',
        cveMetadata: {
            cveId: normalizedVulnId,
            assignerOrgId: cveMetadata.cna?.orgId || 'vulnetix',
            state: cveMetadata.state || 'PUBLISHED',
            datePublished: cveMetadata.datePublished
                ? new Date(cveMetadata.datePublished * 1000).toISOString()
                : new Date().toISOString(),
            dateUpdated: cveMetadata.dateUpdated
                ? new Date(cveMetadata.dateUpdated * 1000).toISOString()
                : undefined,
            dateReserved: cveMetadata.dateReserved
                ? new Date(cveMetadata.dateReserved * 1000).toISOString()
                : undefined
        },
        containers: {
            cna: {
                providerMetadata: {
                    orgId: cveMetadata.cna?.orgId || 'vulnetix',
                    shortName: cveMetadata.cna?.shortName === 'Vulnetix'
                        ? 'VVD'
                        : cveMetadata.cna?.shortName || 'VVD'
                },
                title: cveMetadata.title || normalizedVulnId,
                descriptions: [],
                affected: [],
                references: []
            }
        }
    }

    // Load raw data if available
    if (cveMetadata.rawDataJSON) {
        try {
            const rawData = JSON.parse(cveMetadata.rawDataJSON)
            // Merge raw data if it's CVEListV5 format
            if (rawData.dataType === 'CVE_RECORD' && rawData.containers?.cna) {
                Object.assign(cvelistv5, rawData)
            }
        } catch (e) {
            logger.warn(`Failed to parse rawDataJSON for ${normalizedVulnId} from ${cveMetadata.source}`)
        }
    }

    // Add enrichment metadata
    cvelistv5.containers.vulnetixEnrichment = {
        generatorVersion: '0.2.0',
        generatedAt: new Date().toISOString(),
        enrichmentSource: 'Vulnetix Vulnerability Database',
        dataSource: cveMetadata.source,
        dataCollected: []
    }

    // Fetch and add descriptions
    const descriptions = await prisma.cVEDescription.findMany({
        where: {
            cveId: normalizedVulnId,
            source: cveMetadata.source
        }
    })

    if (descriptions.length > 0) {
        const existingDescValues = new Set(
            cvelistv5.containers.cna.descriptions?.map((d: any) => d.value) || []
        )

        for (const desc of descriptions) {
            if (!existingDescValues.has(desc.value)) {
                cvelistv5.containers.cna.descriptions.push({
                    lang: desc.lang || 'en',
                    value: desc.value
                })
                existingDescValues.add(desc.value)
            }
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('descriptions')
    }

    // Fetch and add problem types (CWEs)
    const problemTypes = await prisma.cVEProblemType.findMany({
        where: {
            cveId: normalizedVulnId,
            source: cveMetadata.source
        }
    })

    if (problemTypes.length > 0) {
        if (!cvelistv5.containers.cna.problemTypes) {
            cvelistv5.containers.cna.problemTypes = []
        }

        const cwesByContainer = new Map<string, any[]>()
        for (const pt of problemTypes) {
            const key = pt.containerType || 'cna'
            if (!cwesByContainer.has(key)) {
                cwesByContainer.set(key, [])
            }
            cwesByContainer.get(key)!.push({
                type: pt.descriptionType || 'CWE',
                cweId: pt.cweId,
                lang: pt.lang || 'en',
                description: pt.description || pt.cweId
            })
        }

        for (const [containerType, cwes] of cwesByContainer) {
            if (containerType === 'cna') {
                cvelistv5.containers.cna.problemTypes.push({
                    descriptions: cwes
                })
            }
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('problem_types')
    }

    // Fetch and add metrics (CVSS scores)
    const metrics = await prisma.cVEMetric.findMany({
        where: {
            cveId: normalizedVulnId,
            source: cveMetadata.source
        }
    })

    if (metrics.length > 0) {
        if (!cvelistv5.containers.cna.metrics) {
            cvelistv5.containers.cna.metrics = []
        }

        for (const metric of metrics) {
            const metricObj: any = {}

            if (metric.metricType === 'cvssV3_1' || metric.metricType === 'cvssV3.1') {
                metricObj.cvssV3_1 = {
                    version: '3.1',
                    vectorString: metric.vectorString,
                    baseScore: metric.baseScore,
                    baseSeverity: metric.baseSeverity
                }
            } else if (metric.metricType === 'cvssV3_0' || metric.metricType === 'cvssV3.0') {
                metricObj.cvssV3_0 = {
                    version: '3.0',
                    vectorString: metric.vectorString,
                    baseScore: metric.baseScore,
                    baseSeverity: metric.baseSeverity
                }
            } else if (metric.metricType === 'cvssV2_0' || metric.metricType === 'cvssV2.0') {
                metricObj.cvssV2_0 = {
                    version: '2.0',
                    vectorString: metric.vectorString,
                    baseScore: metric.baseScore
                }
            } else if (metric.metricType === 'cvssV4_0' || metric.metricType === 'cvssV4.0') {
                metricObj.cvssV4_0 = {
                    version: '4.0',
                    vectorString: metric.vectorString,
                    baseScore: metric.baseScore,
                    baseSeverity: metric.baseSeverity
                }
            }

            if (metric.scenariosJSON) {
                try {
                    metricObj.scenarios = JSON.parse(metric.scenariosJSON)
                } catch (e) {
                    logger.warn(`Failed to parse scenariosJSON for metric`)
                }
            }

            if (Object.keys(metricObj).length > 0) {
                cvelistv5.containers.cna.metrics.push(metricObj)
            }
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('metrics')
    }

    // Fetch and add affected products
    const affected = await prisma.cVEAffected.findMany({
        where: {
            cveId: normalizedVulnId,
            source: cveMetadata.source
        },
        include: {
            versions: true
        }
    })

    if (affected.length > 0) {
        if (!cvelistv5.containers.cna.affected) {
            cvelistv5.containers.cna.affected = []
        }

        for (const aff of affected) {
            const affectedObj: any = {}

            if (aff.vendor) affectedObj.vendor = aff.vendor
            if (aff.product) affectedObj.product = aff.product
            if (aff.collectionURL) affectedObj.collectionURL = aff.collectionURL
            if (aff.packageName) affectedObj.packageName = aff.packageName
            if (aff.cpes) affectedObj.cpes = aff.cpes
            if (aff.modules) affectedObj.modules = aff.modules
            if (aff.programFiles) affectedObj.programFiles = aff.programFiles
            if (aff.programRoutines) affectedObj.programRoutines = aff.programRoutines
            if (aff.platforms) affectedObj.platforms = aff.platforms
            if (aff.repo) affectedObj.repo = aff.repo
            if (aff.defaultStatus) affectedObj.defaultStatus = aff.defaultStatus

            // Add versions
            if (aff.versions && aff.versions.length > 0) {
                affectedObj.versions = aff.versions.map((v: any) => {
                    const versionObj: any = {
                        version: v.version,
                        status: v.status
                    }
                    if (v.versionType) versionObj.versionType = v.versionType
                    if (v.lessThan) versionObj.lessThan = v.lessThan
                    if (v.lessThanOrEqual) versionObj.lessThanOrEqual = v.lessThanOrEqual
                    if (v.changesJSON) {
                        try {
                            versionObj.changes = JSON.parse(v.changesJSON)
                        } catch (e) {
                            // Ignore parse errors
                        }
                    }
                    return versionObj
                })
            }

            if (Object.keys(affectedObj).length > 0) {
                cvelistv5.containers.cna.affected.push(affectedObj)
            }
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('affected')
    }

    // Fetch and add references
    const references = await prisma.cVEMetadataReferences.findMany({
        where: {
            cveId: normalizedVulnId,
            source: cveMetadata.source
        }
    })

    if (references.length > 0) {
        if (!cvelistv5.containers.cna.references) {
            cvelistv5.containers.cna.references = []
        }

        const existingUrls = new Set(
            cvelistv5.containers.cna.references.map((r: any) => r.url) || []
        )

        for (const ref of references) {
            if (!existingUrls.has(ref.url)) {
                const refObj: any = {
                    url: ref.url
                }

                if (ref.title) refObj.name = ref.title
                if (ref.type) refObj.tags = [ref.type.toLowerCase()]

                cvelistv5.containers.cna.references.push(refObj)
                existingUrls.add(ref.url)
            }
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('references')
    }

    // Fetch and add impacts
    const impacts = await prisma.cVEImpact.findMany({
        where: {
            cveId: normalizedVulnId,
            source: cveMetadata.source
        },
        include: {
            descriptions: true
        }
    })

    if (impacts.length > 0) {
        if (!cvelistv5.containers.vulnetixEnrichment.impacts) {
            cvelistv5.containers.vulnetixEnrichment.impacts = []
        }

        for (const impact of impacts) {
            cvelistv5.containers.vulnetixEnrichment.impacts.push({
                capecId: impact.capecId,
                descriptions: impact.descriptions.map((d: any) => ({
                    lang: d.lang || 'en',
                    value: d.value
                }))
            })
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('impacts')
    }

    // Add ADP (Authorized Data Publisher) data if available
    if (cveMetadata.adp && cveMetadata.adp.length > 0) {
        if (!cvelistv5.containers.adp) {
            cvelistv5.containers.adp = []
        }

        for (const adpEntry of cveMetadata.adp) {
            if (adpEntry.adp) {
                const adpData: any = {
                    providerMetadata: {
                        orgId: adpEntry.adp.orgId,
                        shortName: adpEntry.adp?.shortName === 'Vulnetix'
                            ? 'VVD'
                            : adpEntry.adp?.shortName || 'CISA-ADP',
                        dateUpdated: adpEntry.dateUpdated
                            ? new Date(adpEntry.dateUpdated * 1000).toISOString()
                            : undefined
                    },
                    title: adpEntry.title
                }

                // Add ADP-specific data if stored
                if (adpEntry.adpJSON) {
                    try {
                        const parsed = JSON.parse(adpEntry.adpJSON)
                        Object.assign(adpData, parsed)
                    } catch (e) {
                        logger.warn(`Failed to parse adpJSON for ${normalizedVulnId}`)
                    }
                }

                cvelistv5.containers.adp.push(adpData)
            }
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('adp')
    }

    // Add global enrichment data (not source-specific)

    // EPSS data
    const latestEpss = await prisma.epssScore.findFirst({
        where: { cve: normalizedVulnId },
        orderBy: { dateString: 'desc' }
    })

    if (latestEpss) {
        cvelistv5.containers.vulnetixEnrichment.epss = {
            score: latestEpss.score,
            percentile: latestEpss.percentile,
            date: latestEpss.dateString,
            modelVersion: latestEpss.modelVersion
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('epss')
    }

    // CESS data
    const latestCess = await prisma.cessScore.findFirst({
        where: { cve: normalizedVulnId },
        orderBy: { dateString: 'desc' }
    })

    if (latestCess) {
        cvelistv5.containers.vulnetixEnrichment.cess = {
            score: latestCess.score,
            probabilityExploitUsage: latestCess.probabilityExploitUsage,
            date: latestCess.dateString,
            modelVersion: latestCess.modelVersion
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('cess')
    }

    // KEV data
    const kevEntry = await prisma.kev.findFirst({
        where: { cveID: normalizedVulnId }
    })

    if (kevEntry) {
        cvelistv5.containers.vulnetixEnrichment.kev = {
            source: kevEntry.source,
            vendorProject: kevEntry.vendorProject,
            product: kevEntry.product,
            vulnerabilityName: kevEntry.vulnerabilityName,
            dateAdded: new Date(kevEntry.dateAdded * 1000).toISOString(),
            shortDescription: kevEntry.shortDescription,
            requiredAction: kevEntry.requiredAction,
            dueDate: new Date(kevEntry.dueDate * 1000).toISOString(),
            knownRansomwareCampaignUse: kevEntry.knownRansomwareCampaignUse,
            notes: kevEntry.notes,
            cwes: kevEntry.cwesJSON ? JSON.parse(kevEntry.cwesJSON) : []
        }
        cvelistv5.containers.vulnetixEnrichment.dataCollected.push('kev')
    }

    // Aliases (query only once per CVE, not per source)
    const aliases = await prisma.cVEAlias.findMany({
        where: {
            OR: [
                { primaryCveId: normalizedVulnId },
                { aliasCveId: normalizedVulnId }
            ]
        }
    })

    if (aliases.length > 0) {
        const allAliases = new Set<string>()

        for (const alias of aliases) {
            if (alias.primaryCveId === normalizedVulnId) {
                allAliases.add(alias.aliasCveId)
            } else {
                allAliases.add(alias.primaryCveId)
            }
        }

        if (allAliases.size > 0) {
            cvelistv5.containers.vulnetixEnrichment.aliases = Array.from(allAliases)
            cvelistv5.containers.vulnetixEnrichment.dataCollected.push('aliases')
        }
    }

    // AI analyses
    const agentInferences = await prisma.pixLog.findMany({
        where: {
            vulnId: normalizedVulnId,
            vulnSource: 'vvb',
        },
        include: {
            pix: true,
        }
    })

    if (agentInferences?.length > 0) {
        const aiAnalyses: any[] = []
        let affectedFunctionsText: string | null = null
        let advisoryText: string | null = null

        for (const inference of agentInferences) {
            if (inference.pix && inference.responseText) {
                aiAnalyses.push({
                    activityKey: inference.pix.activityKey,
                    analysis: inference.responseText,
                    generatedAt: inference.createdAt
                })

                if (inference.pix.activityKey === 'affected_functions') {
                    affectedFunctionsText = inference.responseText
                }

                if (inference.pix.activityKey === 'analysis_in_triage') {
                    advisoryText = inference.responseText
                }
            }
        }

        if (affectedFunctionsText) {
            const functionNames = affectedFunctionsText
                .split('\n')
                .map(line => line.trim())
                .filter(line => line && !line.startsWith('#') && !line.startsWith('//'))

            if (functionNames.length > 0) {
                cvelistv5.containers.vulnetixEnrichment.affectedFunctions = functionNames
                cvelistv5.containers.vulnetixEnrichment.dataCollected.push('affected_functions')
            }
        }

        if (advisoryText) {
            cvelistv5.containers.vulnetixEnrichment.advisory = advisoryText
            cvelistv5.containers.vulnetixEnrichment.dataCollected.push('advisory')
        }

        if (aiAnalyses.length > 0) {
            cvelistv5.containers.vulnetixEnrichment.aiAnalyses = aiAnalyses
            cvelistv5.containers.vulnetixEnrichment.dataCollected.push('ai_analyses')
        }
    }

    return cvelistv5
}

/**
 * GET /info/:identifier
 * Returns an array of CVEListV5 format records, one for each distinct source
 */
app.get('/:identifier', async (c) => {
    const prisma: PrismaClient = c.get('prisma')
    const logger = c.get('logger')
    const vulnId = c.req.param('identifier')
    const r2adapter = c.env.r2artifacts

    if (!vulnId) {
        return c.json({ error: 'Missing vulnerability ID' }, 400)
    }

    // Normalize to uppercase for case-insensitive lookup
    const normalizedVulnId = vulnId.trim().toUpperCase()

    // Detect identifier type to configure appropriate data sources
    const isCVE = normalizedVulnId.startsWith('CVE-')
    const isEUVD = normalizedVulnId.startsWith('EUVD-')
    const isGHSA = normalizedVulnId.startsWith('GHSA-')
    // Also supports PYSEC-*, RUSTSEC-*, GO-*, OSV-*, and any other identifiers stored in CVEMetadata

    try {
        // Use VulnResolver to find the vulnerability
        const resolver = createVulnIdResolver(prisma)
        const resolved = await resolver.resolve(normalizedVulnId)

        // If not found, use VulnProcessor to fetch/create records
        if (!resolved.success) {
            logger.info(`Vulnerability ${normalizedVulnId} not found, processing with VulnProcessor`)

            // Configure data sources based on identifier type
            // For non-CVE identifiers, enable OSV which supports multiple ecosystems
            const processor = createVulnProcessor(prisma, {
                enableCVEOrg: isCVE,
                enableEPSS: isCVE,
                enableCESS: isCVE,
                enableKEV: isCVE,
                enableCisaVulnrichment: isCVE,
                enableNistNvd: isCVE,
                enableAnchoreADP: isCVE,
                enableEUVD: isEUVD || isCVE,
                enableGitHubAdvisory: isGHSA,
                enableOSV: true, // OSV supports CVE-*, GHSA-*, PYSEC-*, RUSTSEC-*, GO-*, etc.
                enableGoogleOsi: isGHSA,
                enableAIInference: true,
                enableUrlCategorization: true,
                autoSave: true,
                forceRefresh: false,
                orgId: 'public-vdb',
                memberId: 'public-vdb',
                llm: c.env.llm,
                r2adapter: r2adapter,
                jwtCredentials: {
                    clientId: c.env.GITHUB_APP_CLIENT_ID,
                    clientSecret: c.env.GITHUB_APP_CLIENT_SECRET,
                    privateKey: c.env.APP_PRIVATE_KEY,
                    appId: c.env.GITHUB_APP_ID,
                    personalAccessToken: c.env.GITHUB_PAT
                }
            })

            const result = await processor.process(normalizedVulnId, logger)

            if (!result.success || result.sources.length === 0) {
                const errorMsg = result.error || 'No data sources returned results'
                logger.error(`Failed to process ${normalizedVulnId}: ${errorMsg}`)
                return c.json({
                    error: 'Vulnerability not found',
                    identifier: normalizedVulnId,
                    details: errorMsg,
                    sourcesAttempted: result.sources
                }, 404)
            }

            logger.info(`Successfully processed ${normalizedVulnId}: sources=${result.sources.join(',')}`)
        }

        // Fetch all CVEMetadata records for this identifier (one per source)
        const cveRecords = await prisma.cVEMetadata.findMany({
            where: { cveId: normalizedVulnId },
            include: {
                cna: true,
                adp: {
                    include: {
                        adp: true
                    }
                }
            },
            orderBy: [
                { source: 'asc' }
            ]
        })

        if (cveRecords.length === 0) {
            return c.json({
                error: 'Vulnerability not found',
                identifier: normalizedVulnId
            }, 404)
        }

        // Build CVEListV5 records for each source
        const cvelistv5Array: any[] = []

        for (const cveMetadata of cveRecords) {
            try {
                const record = await buildCVEListV5Record(prisma, cveMetadata, logger, r2adapter)

                // Validate against CVE Record Format schema
                const validationResult = cveRecordValidator.validate(record)

                if (!validationResult.valid) {
                    logger.warn(`Schema validation failed for ${normalizedVulnId} (${cveMetadata.source}):`,
                        validationResult.errors)

                    // Add validation warning to the record
                    record.containers.vulnetixEnrichment.validationWarning =
                        'Schema validation failed - data may not be fully compliant'
                    record.containers.vulnetixEnrichment.validationErrors =
                        validationResult.errors?.map((err: any) => ({
                            field: err.instancePath || err.instanceLocation,
                            message: err.message || err.error,
                            keyword: err.keyword
                        }))
                }

                cvelistv5Array.push(record)
            } catch (error) {
                logger.error(`Failed to build CVEListV5 record for ${normalizedVulnId} (${cveMetadata.source}):`,
                    error)
                // Continue processing other sources
            }
        }

        if (cvelistv5Array.length === 0) {
            return c.json({
                error: 'Failed to generate CVEListV5 records',
                identifier: normalizedVulnId
            }, 500)
        }

        return c.json(cvelistv5Array, 200, {
            'Content-Type': 'application/json'
        })
    } catch (error) {
        logger.error(`Failed to generate CVElistv5 array for ${normalizedVulnId}:`, error)
        return c.json({
            error: 'Failed to generate CVEListV5 format',
            details: error instanceof Error ? error.message : String(error)
        }, 500)
    }
})

export default app
