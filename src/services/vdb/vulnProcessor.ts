/**
 * VulnProcessor - Core Vulnerability Enrichment Engine
 *
 * This service orchestrates parallel vulnerability data enrichment from multiple sources including
 * CVE.org, OSV.dev, NIST NVD, GitHub Advisory, Google OSI, EUVD, EPSS, CESS, and AI inference.
 *
 * Documentation: .repo/06-vulnerability-processing/vulnprocessor.md
 * Related Docs:
 * - CVE Enrichment: .repo/06-vulnerability-processing/cve-enrichment.md
 * - Parallel Processing: .repo/06-vulnerability-processing/parallel-processing.md
 * - AI Inference: .repo/06-vulnerability-processing/ai-inference.md
 * - Processor Boundaries: .repo/06-vulnerability-processing/processor-boundaries.md
 */

import type { PrismaClient } from '@prisma/client';
import { AnchoreADP } from '@shared/anchore-adp';
import { establishCVEAliasRelations } from '@shared/cve-alias-manager';
import { parseAnchoreAdpToCVE, parseCisaAdpToCVE, parseCVEOrgToCVE, parseNistNvdToCVE, parseOSVToCVE, storeCVEData, storeCVEImpacts, storeSSVCDecisions } from '@shared/cve-storage';
import * as cwesJson from '@shared/cwes.json';
import { EUVD, parseEUVDToCVE } from '@shared/euvd';
import { GitHubAdvisory, parseGitHubAdvisoryToCVE } from '@shared/github-advisory';
import type { GitHubJWTCredentials } from '@shared/github-enrichment-helpers';
import { GoogleOsi, parseGoogleOsiToCVE } from '@shared/google-osi';
import { NistNVD } from '@shared/nist-nvd';
import { batchStoreCVEReferences, batchStoreCVEReferencesOptimized, enrichReservedCVEWithReadme, processReference, storeCVEMetadataReference } from '@shared/reference-processor';
import { reevaluateSSVCWithReferences } from '@shared/ssvc-reevaluator';
import { CESS, EPSS, MitreCVE, OSV, VULNETIX_USER_AGENT } from '@shared/utils';
import { retrieveVulnJsonFromR2, storeVulnJsonToR2 } from '@shared/vdb-identifier';
import { categorizeURLs } from '../utilities/url-categorizer';

export interface VulnProcessorOptions {
    enableCVEOrg?: boolean
    enableOSV?: boolean
    enableGitHubAdvisory?: boolean // Enable GitHub Security Advisory API (for GHSA IDs)
    enableGoogleOsi?: boolean // Enable Google OSI (Open Source Insights) API for alias/CVSS enrichment
    enableNistNvd?: boolean // Enable NIST NVD (National Vulnerability Database) data
    enableAnchoreADP?: boolean // Enable Anchore ADP enrichment data (requires enableNistNvd)
    enableCisaVulnrichment?: boolean // Enable CISA Vulnrichment ADP data (requires enableCVEOrg with CISA ADP present)
    enableEPSS?: boolean
    enableCESS?: boolean
    enableEUVD?: boolean
    enableKEV?: boolean // Enable CISA KEV (Known Exploited Vulnerabilities) data
    enableCrowdSec?: boolean // Enable CrowdSec honeypot sighting data for CVEs
    enableAIInference?: boolean // Enable AI-powered analysis
    enableUrlCategorization?: boolean // Enable URL categorization for exploit/fix extraction
    enableNuclei?: boolean // Enable Nuclei template discovery from ProjectDiscovery repository
    autoSave?: boolean
    forceRefresh?: boolean // Force re-processing even if CVE exists
    orgId?: string
    memberId?: string
    llm?: any // LLM binding for AI inference
    r2adapter?: any // R2 storage adapter for raw JSON storage
    env?: any // Cloudflare Workers environment bindings (for NIST_APIKEY, CROWDSEC_APIKEY, etc.)
    jwtCredentials?: GitHubJWTCredentials // GitHub App JWT credentials for authenticated API requests (includes optional personalAccessToken)
}

export interface VulnProcessorResult {
    success: boolean
    vulnId: string
    sources: string[]
    epssAdded: boolean
    cessAdded: boolean
    osvAdded: boolean
    cveOrgAdded: boolean
    nistNvdAdded: boolean
    anchoreAdpAdded: boolean
    cisaVulnrichmentAdded: boolean
    euvdAdded: boolean
    kevAdded: boolean
    crowdSecAdded: boolean
    googleOsiAdded: boolean
    githubPocAdded: boolean
    vulnerabilityLabAdded: boolean
    nucleiAdded: boolean
    aiInferenceAdded: boolean
    affectedFunctionsAnalysisAdded: boolean
    securityAdvisoryAnalysisAdded: boolean
    urlCategorizationAdded: boolean
    githubEnrichmentAdded: boolean
    scorecardAdded: boolean
    scorecardUuid?: string
    exploitUrls?: any[]
    fixVersions?: string[]
    error?: string
}

interface Logger {
    warn: (message: string, data?: any) => void
    debug: (message: string, data?: any) => void
    error: (message: string, data?: any) => void
    info: (message: string, data?: any) => void
}

/**
 * Unified Vulnerability Processor
 * Fetches vulnerability data from multiple sources and optionally stores in database
 * Used by both public VDB endpoint and admin enrichment endpoint
 *
 * Sources: CVE.org, OSV, EPSS, CESS, (EUVD future)
 */
export class VulnProcessor {
    private options: Required<VulnProcessorOptions>

    // Cache TTL configuration (in seconds) for different sources
    // Determines how long data from each source is considered fresh before re-fetching
    private static readonly CACHE_TTL_SECONDS = {
        'cve-org': 24 * 60 * 60,      // 24 hours - CVE.org updates relatively frequently
        'nist-nvd': 7 * 24 * 60 * 60, // 7 days - NIST NVD data is more stable
    } as const

    constructor(
        private prisma: PrismaClient,
        options: VulnProcessorOptions = {}
    ) {
        // Default: enable all sources and auto-save
        this.options = {
            enableCVEOrg: options.enableCVEOrg ?? true,
            enableOSV: options.enableOSV ?? true,
            enableGitHubAdvisory: options.enableGitHubAdvisory ?? true,
            enableGoogleOsi: options.enableGoogleOsi ?? true, // Google OSI for alias/CVSS enrichment
            enableNistNvd: options.enableNistNvd ?? true, // NIST NVD data enrichment
            enableAnchoreADP: options.enableAnchoreADP ?? true, // Anchore ADP enrichment (requires NVD)
            enableCisaVulnrichment: options.enableCisaVulnrichment ?? true, // CISA Vulnrichment ADP (requires CVE.org with CISA ADP)
            enableEPSS: options.enableEPSS ?? true,
            enableCESS: options.enableCESS ?? true,
            enableEUVD: options.enableEUVD ?? true, // Now implemented
            enableKEV: options.enableKEV ?? true, // CISA Known Exploited Vulnerabilities
            enableCrowdSec: options.enableCrowdSec ?? false, // CrowdSec honeypot sightings (disabled by default)
            enableAIInference: options.enableAIInference ?? false,
            enableUrlCategorization: options.enableUrlCategorization ?? true,
            enableNuclei: options.enableNuclei ?? true, // Nuclei template discovery
            autoSave: options.autoSave ?? true,
            forceRefresh: options.forceRefresh ?? false,
            orgId: options.orgId || 'public-vdb',
            memberId: options.memberId || 'public-vdb',
            llm: options.llm || null,
            r2adapter: options.r2adapter || null,
            env: options.env || null,
            jwtCredentials: options.jwtCredentials || null
        }
    }

    /**
     * Batch store CVE references using optimized PostgreSQL batch operations
     * Uses efficient PostgreSQL batch operations via Prisma
     */
    private async storeCVEReferences(
        cveId: string,
        source: string,
        references: any[],
        referenceSource: string,
        logger: Logger,
        checkHttp: boolean = false,
        forceRefresh: boolean = false
    ): Promise<void> {
        // Use optimized PostgreSQL batch operations
        await batchStoreCVEReferencesOptimized(
            this.prisma,
            cveId,
            source,
            references,
            referenceSource,
            logger,
            checkHttp,
            forceRefresh
        )
    }

    /**
     * Enrich CWE IDs with metadata from cwes.json
     * @param cweIds - Array of CWE IDs (e.g., ["CWE-79", "CWE-89"])
     * @returns Array of enriched CWE objects with metadata
     */
    private enrichCweData(cweIds: string[]): Array<{
        cweId: string
        name?: string | null
        description?: string | null
        detail?: string | null
        mitigation?: string | null
        scopes?: string[]
        languages?: string[]
    }> {
        const cwesData = (cwesJson as any).default || cwesJson
        const enrichedCwes: Array<{
            cweId: string
            name?: string | null
            description?: string | null
            detail?: string | null
            mitigation?: string | null
            scopes?: string[]
            languages?: string[]
        }> = []

        for (const cweId of cweIds) {
            // Normalize CWE ID (remove "CWE-" prefix if present for lookup)
            const cweNumber = cweId.replace(/CWE-/i, '')
            const cweMetadata = cwesData.find((cwe: any) => cwe.cwe === cweNumber)

            if (cweMetadata) {
                enrichedCwes.push({
                    cweId,
                    name: cweMetadata.name || null,
                    description: cweMetadata.description || null,
                    detail: cweMetadata.detail || null,
                    mitigation: cweMetadata.mitigation || null,
                    scopes: cweMetadata.scopes || [],
                    languages: cweMetadata.languages || []
                })
            } else {
                // If no metadata found, still include the CWE ID
                enrichedCwes.push({
                    cweId,
                    name: null,
                    description: null,
                    detail: null,
                    mitigation: null,
                    scopes: [],
                    languages: []
                })
            }
        }

        return enrichedCwes
    }

    /**
     * Check R2 cache for vulnerability data before making API call
     * Respects forceRefresh option to bypass cache
     * @param identifier - Vulnerability identifier (CVE-*, GHSA-*, etc.)
     * @param logger - Logger instance
     * @returns Cached data or null if not found or forceRefresh is true
     */
    private async checkR2Cache(identifier: string, logger: Logger): Promise<{ data: any; source: string } | null> {
        // Skip R2 cache if forceRefresh is enabled or r2adapter is not available
        if (this.options.forceRefresh || !this.options.r2adapter) {
            if (this.options.forceRefresh) {
                logger.debug(`[R2 Cache] Skipping cache check for ${identifier} - forceRefresh enabled`)
            }
            return null
        }

        try {
            const cached = await retrieveVulnJsonFromR2(this.options.r2adapter, identifier, logger)
            if (cached) {
                logger.info(`[R2 Cache] ✅ Found cached data for ${identifier} from ${cached.source}`)
                return { data: cached.data, source: cached.source }
            }
            logger.debug(`[R2 Cache] No cached data found for ${identifier}`)
        } catch (error: any) {
            logger.warn(`[R2 Cache] Failed to check R2 for ${identifier}: ${error.message}`)
        }
        return null
    }

    /**
     * Check if data for a given CVE and source was recently fetched based on database lastFetchedAt
     * Uses source-specific TTLs to determine freshness
     * @param cveId - CVE identifier
     * @param source - Data source (cve-org, nist-nvd, etc.)
     * @param logger - Logger instance
     * @returns Object with isFresh boolean and optional metadata record
     */
    private async isDataFreshInDatabase(
        cveId: string,
        source: 'cve-org' | 'nist-nvd',
        logger: Logger
    ): Promise<{ isFresh: boolean; metadata: any | null; ageInHours: number | null }> {
        try {
            // Query CVEMetadata for this CVE and source
            const metadata = await this.prisma.cVEMetadata.findUnique({
                where: {
                    cveId_source: {
                        cveId,
                        source: source === 'cve-org' ? 'cve.org' : 'nvd'
                    }
                },
                select: {
                    lastFetchedAt: true,
                    cveId: true,
                    source: true
                }
            })

            if (!metadata || !metadata.lastFetchedAt) {
                logger.debug(`[DB Cache Check] No lastFetchedAt found for ${cveId} from ${source}`)
                return { isFresh: false, metadata: null, ageInHours: null }
            }

            // Calculate age of cached data
            const now = Math.floor(Date.now() / 1000) // Current Unix timestamp in seconds
            const ageInSeconds = now - metadata.lastFetchedAt
            const ageInHours = Math.floor(ageInSeconds / 3600)

            // Get TTL for this source
            const ttlSeconds = VulnProcessor.CACHE_TTL_SECONDS[source]

            // Check if data is fresh
            const isFresh = ageInSeconds < ttlSeconds

            if (isFresh) {
                logger.info(`[DB Cache Check] ✅ ${cveId} from ${source} is fresh (${ageInHours}h old, TTL: ${ttlSeconds / 3600}h)`)
            } else {
                logger.info(`[DB Cache Check] ⏰ ${cveId} from ${source} is stale (${ageInHours}h old, TTL: ${ttlSeconds / 3600}h)`)
            }

            return { isFresh, metadata, ageInHours }
        } catch (error: any) {
            logger.warn(`[DB Cache Check] Failed to check database for ${cveId} from ${source}: ${error.message}`)
            return { isFresh: false, metadata: null, ageInHours: null }
        }
    }

    /**
     * Check if bulk data (EPSS, CESS) is fresh enough to skip API call
     * @param dataType - Type of bulk data to check
     * @param logger - Logger instance
     * @returns true if data is fresh, false otherwise
     */
    private async isBulkDataFresh(dataType: 'epss' | 'cess', logger: Logger): Promise<boolean> {
        // Always fetch if forceRefresh is enabled
        if (this.options.forceRefresh) {
            logger.debug(`[Bulk Data Check] Skipping freshness check for ${dataType} - forceRefresh enabled`)
            return false
        }

        try {
            const oneDayAgo = Math.floor(Date.now() / 1000) - (24 * 60 * 60)

            switch (dataType) {
                case 'epss': {
                    // Check if we have any EPSS scores from the last 24 hours
                    const recentEpss = await this.prisma.epssScore.findFirst({
                        where: {
                            fetchedAt: {
                                gte: oneDayAgo
                            }
                        }
                    })
                    if (recentEpss) {
                        logger.info(`[Bulk Data Check] EPSS data is fresh (last update: ${new Date(recentEpss.fetchedAt * 1000).toISOString()})`)
                        return true
                    }
                    break
                }
                case 'cess': {
                    // Check if we have any CESS scores from the last 24 hours
                    const recentCess = await this.prisma.cessScore.findFirst({
                        where: {
                            fetchedAt: {
                                gte: oneDayAgo
                            }
                        }
                    })
                    if (recentCess) {
                        logger.info(`[Bulk Data Check] CESS data is fresh (last update: ${new Date(recentCess.fetchedAt * 1000).toISOString()})`)
                        return true
                    }
                    break
                }
            }
            logger.debug(`[Bulk Data Check] ${dataType} data is stale or missing`)
        } catch (error: any) {
            logger.warn(`[Bulk Data Check] Failed to check ${dataType} freshness: ${error.message}`)
        }
        return false
    }

    /**
     * Check if a specific CVE-source combination recently failed
     * Uses BulkDataDumpTracker to cache failures for 1 day
     * @param cveId - CVE identifier
     * @param source - Data source (cess, epss, nvd, euvd, github, googleosi, kev)
     * @param logger - Logger instance
     * @returns true if recently failed (skip retry), false if should attempt
     */
    private async hasRecentFailure(cveId: string, source: string, logger: Logger): Promise<boolean> {
        // Always attempt if forceRefresh is enabled
        if (this.options.forceRefresh) {
            logger.debug(`[Failure Cache] Skipping failure check for ${cveId}_${source} - forceRefresh enabled`)
            return false
        }

        try {
            const trackerKey = `${cveId}_${source}`
            const oneDayAgo = Math.floor(Date.now() / 1000) - (24 * 60 * 60)

            const tracker = await this.prisma.bulkDataDumpTracker.findUnique({
                where: { source: trackerKey }
            })

            if (tracker && tracker.lastProcessedAt > oneDayAgo) {
                logger.info(`[Failure Cache] Skipping ${source} for ${cveId} - recently failed (${Math.floor((Date.now()/1000 - tracker.lastProcessedAt) / 3600)}h ago)`)
                return true
            }

            return false
        } catch (error) {
            logger.warn(`Failed to check failure cache for ${cveId}_${source}:`, error)
            return false // Proceed with attempt on cache check failure
        }
    }

    /**
     * Mark a CVE-source combination as failed
     * @param cveId - CVE identifier
     * @param source - Data source
     * @param logger - Logger instance
     */
    private async markFailure(cveId: string, source: string, logger: Logger): Promise<void> {
        try {
            const trackerKey = `${cveId}_${source}`
            const now = Math.floor(Date.now() / 1000)

            await this.prisma.bulkDataDumpTracker.upsert({
                where: { source: trackerKey },
                create: {
                    source: trackerKey,
                    lastProcessedAt: now,
                    frequency: 86400, // 1 day in seconds
                    createdAt: now,
                    updatedAt: now
                },
                update: {
                    lastProcessedAt: now,
                    updatedAt: now
                }
            })

            logger.debug(`[Failure Cache] Marked ${trackerKey} as failed`)
        } catch (error) {
            logger.warn(`Failed to mark failure for ${cveId}_${source}:`, error)
        }
    }

    /**
     * Validate parsed CVE data before storage
     * Ensures minimum required fields are present to prevent invalid records
     * @param data - Parsed CVE data object (can be null)
     * @param source - Source name for logging purposes
     * @returns true if data is valid, false otherwise
     */
    private validateParsedData(data: any, source: string): boolean {
        if (!data) {
            return false
        }
        if (!data.cveId || typeof data.cveId !== 'string' || data.cveId.trim() === '') {
            return false
        }
        if (!data.source || typeof data.source !== 'string' || data.source.trim() === '') {
            return false
        }
        if (!data.state || typeof data.state !== 'string' || data.state.trim() === '') {
            return false
        }
        return true
    }

    /**
     * Helper function to fetch CVE sightings from CrowdSec API
     */
    private async fetchCrowdSecData(cveId: string, apiKey: string): Promise<{ url: string; httpStatus: number; data: any }> {
        const crowdsecApiUrl = this.options.env?.CROWDSEC_API_URL || 'https://cti.api.crowdsec.net/v2'
        const url = `${crowdsecApiUrl}/smoke/search?query=cves%3A%22${cveId}%22&since=30d`

        const response = await fetch(url, {
            headers: {
                'accept': 'application/json',
                'x-api-key': apiKey,
                'user-agent': VULNETIX_USER_AGENT
            }
        })

        return {
            url,
            httpStatus: response.status,
            data: response.status === 200 ? await response.json() : await response.text()
        }
    }

    /**
     * Helper function to create or update CVEMetadataReference for CrowdSec
     */
    private async ensureCrowdSecReference(cveId: string, logger: Logger): Promise<void> {
        const crowdsecExplorerUrl = this.options.env?.CROWDSEC_EXPLORER_URL || 'https://app.crowdsec.net/cti/cve-explorer'
        const url = `${crowdsecExplorerUrl}/${cveId}`
        const now = Math.floor(Date.now() / 1000)

        try {
            // Check if reference already exists
            const existing = await this.prisma.cVEMetadataReferences.findFirst({
                where: {
                    cveId,
                    source: 'vvd',
                    url
                }
            })

            if (!existing) {
                await this.prisma.cVEMetadataReferences.create({
                    data: {
                        cveId,
                        source: 'vvd',
                        url,
                        type: 'sighting',
                        referenceSource: 'CROWDSEC',
                        title: 'CrowdSec CTI CVE Explorer',
                        createdAt: now,
                        httpStatus: null,
                        deadLinkCheckedAt: null,
                        deadLink: 0
                    }
                })
                logger.debug(`Created CrowdSec CVEMetadataReference for ${cveId}`)
            }
        } catch (error) {
            logger.warn(`Failed to create CrowdSec reference for ${cveId}:`, error)
        }
    }

    /**
     * Helper function to parse and store CrowdSec sighting data
     */
    private async processCrowdSecResponse(
        logUuid: string,
        responseData: any,
        logger: Logger
    ): Promise<number> {
        if (!responseData.items || !Array.isArray(responseData.items)) {
            return 0
        }

        const now = Math.floor(Date.now() / 1000)
        let processedCount = 0

        // Collect all unique CVE IDs from the response
        const allCveIds = new Set<string>()
        for (const item of responseData.items) {
            const cves = item.cves || []
            cves.forEach((cveId: string) => allCveIds.add(cveId))
        }

        // Batch check which CVEs already exist in CVEMetadata
        const existingCveIds = new Set<string>()
        const cveIdArray = Array.from(allCveIds)
        const batchSize = 100

        for (let i = 0; i < cveIdArray.length; i += batchSize) {
            const batch = cveIdArray.slice(i, i + batchSize)
            const existingCves = await this.prisma.cVEMetadata.findMany({
                where: {
                    AND: [
                        { cveId: { in: batch } },
                        { source: 'vvd' }
                    ]
                },
                select: { cveId: true }
            })
            existingCves.forEach(cve => existingCveIds.add(cve.cveId))
        }

        // Process each item in the response
        for (const item of responseData.items) {
            const ip = item.ip
            if (!ip) continue

            const cves = item.cves || []
            if (cves.length === 0) continue

            // Process each CVE
            for (const cveId of cves) {
                try {
                    // Extract data from CrowdSec response
                    const behaviorsCsv = (item.behaviors || []).map((b: any) => b.name).join(',')

                    // Filter attack_details to exclude items referencing different CVEs
                    const cvePattern = /CVE-\d{4}-\d{4,}/
                    const filteredAttackDetails = (item.attack_details || []).filter((a: any) => {
                        const fieldsToCheck = [a.name, a.label, a.description]
                        for (const field of fieldsToCheck) {
                            if (field && typeof field === 'string') {
                                const match = field.match(cvePattern)
                                if (match && match[0] !== cveId) {
                                    return false
                                }
                            }
                        }
                        return true
                    })
                    const attackDetailsCsv = filteredAttackDetails.map((a: any) => a.name).join(',')

                    const classificationsCsv = (item.classifications?.classifications || []).map((c: any) => c.name).join(',')
                    const mitreTechniquesCsv = (item.mitre_techniques || []).map((m: any) => m.name).join(',')
                    const targetCountriesJSON = item.target_countries ? JSON.stringify(item.target_countries) : null

                    // Create sighting record
                    const { v4: uuidv4 } = await import('uuid')
                    await this.prisma.crowdSecSighting.create({
                        data: {
                            uuid: uuidv4(),
                            crowdSecLogUuid: logUuid,
                            cveId,
                            source: 'vvd',
                            ip: item.ip,
                            reputation: item.reputation,
                            confidence: item.confidence,
                            backgroundNoiseScore: item.background_noise_score,
                            asName: item.as_name,
                            asNum: item.as_num,
                            ipRange24: item.ip_range_24,
                            ipRange24Reputation: item.ip_range_24_reputation,
                            ipRange24Score: item.ip_range_24_score,
                            locationCountry: item.location?.country,
                            locationCity: item.location?.city,
                            locationLat: item.location?.latitude,
                            locationLon: item.location?.longitude,
                            reverseDns: item.reverse_dns,
                            behaviorsCsv,
                            attackDetailsCsv,
                            classificationsCsv,
                            mitreTechniquesCsv,
                            targetCountriesJSON,
                            firstSeen: item.history?.first_seen ? Math.floor(new Date(item.history.first_seen).getTime() / 1000) : null,
                            lastSeen: item.history?.last_seen ? Math.floor(new Date(item.history.last_seen).getTime() / 1000) : null,
                            falsePositivesCount: (item.classifications?.false_positives || []).length,
                            scoreLastDayAggressiveness: item.scores?.last_day?.aggressiveness,
                            scoreLastDayThreat: item.scores?.last_day?.threat,
                            scoreLastDayTrust: item.scores?.last_day?.trust,
                            scoreLastWeekAggressiveness: item.scores?.last_week?.aggressiveness,
                            scoreLastWeekThreat: item.scores?.last_week?.threat,
                            scoreLastWeekTrust: item.scores?.last_week?.trust,
                            scoreLastMonthAggressiveness: item.scores?.last_month?.aggressiveness,
                            scoreLastMonthThreat: item.scores?.last_month?.threat,
                            scoreLastMonthTrust: item.scores?.last_month?.trust,
                            createdAt: now,
                            updatedAt: now
                        }
                    })

                    // Ensure CVEMetadataReference exists for this CVE
                    await this.ensureCrowdSecReference(cveId, logger)

                    processedCount++
                } catch (error) {
                    logger.error(`Failed to create CrowdSec sighting for ${cveId}:`, error)
                }
            }
        }

        return processedCount
    }

    /**
     * Process a vulnerability from all enabled sources
     * @param vulnId - Vulnerability ID (CVE-*, GHSA-*, PYSEC-*, etc.)
     * @param logger - Logger instance
     * @param finding - Optional Finding object for context (used by storeCVE functions)
     */
    async process(vulnId: string, logger: Logger, finding?: any): Promise<VulnProcessorResult> {
        // Normalize vulnId to uppercase for case-insensitive storage
        const normalizedVulnId = vulnId.trim().toUpperCase()
        
        // IMPORTANT: Always use the normalized (uppercase) vulnId as the primary identifier
        // For GHSA-*, PYSEC-*, etc., we store them with their uppercase ID
        // The CVE-* alias will be stored separately if discovered
        const primaryId = normalizedVulnId

        const result: VulnProcessorResult = {
            success: false,
            vulnId: normalizedVulnId,
            sources: [],
            epssAdded: false,
            cessAdded: false,
            osvAdded: false,
            cveOrgAdded: false,
            nistNvdAdded: false,
            anchoreAdpAdded: false,
            cisaVulnrichmentAdded: false,
            euvdAdded: false,
            kevAdded: false,
            crowdSecAdded: false,
            googleOsiAdded: false,
            githubPocAdded: false,
            vulnerabilityLabAdded: false,
            nucleiAdded: false,
            aiInferenceAdded: false,
            affectedFunctionsAnalysisAdded: false,
            securityAdvisoryAnalysisAdded: false,
            urlCategorizationAdded: false,
            githubEnrichmentAdded: false,
            scorecardAdded: false,
            exploitUrls: [],
            fixVersions: []
        }

        try {

            // For backward compatibility and AI inference, we need to track the CVE ID
            // For CVE IDs, cveId = primaryId
            // For non-CVE IDs, we'll discover the CVE ID from OSV data later
            let cveId = primaryId.startsWith('CVE-') ? primaryId : null

            // For non-CVE IDs, try to extract CVE from Finding aliases (for backward compatibility)
            if (!cveId && finding?.aliases) {
                const aliases = typeof finding.aliases === 'string' ? JSON.parse(finding.aliases) : finding.aliases
                cveId = aliases.find((a: string) => a.startsWith('CVE-')) || null
            }

            // Check if this ID already exists in database from ALL sources
            // Note: We check all sources to populate result.sources, but we DON'T return early
            // because the same vulnerability may need to be enriched from multiple sources
            // (e.g., OSV, EUVD, GitHub Advisory, CVE.org all may have data for the same CVE)
            let existingRecords: any[] = []
            if (this.options.autoSave) {
                existingRecords = await this.prisma.cVEMetadata.findMany({
                    where: { cveId: primaryId }
                })

                if (existingRecords.length > 0) {
                    const existingSources = existingRecords.map(r => r.source)
                    logger.info(`${primaryId} already exists in database from ${existingRecords.length} source(s): ${existingSources.join(', ')}`)
                    result.sources = existingSources
                    result.success = true

                    // Only return early if:
                    // 1. No finding is provided (don't need to update Finding aliases)
                    // 2. AI inference is disabled (don't need to generate AI analyses)
                    // 3. forceRefresh is disabled (don't want to re-fetch)
                    // 4. ALL enabled sources already have records (no new sources to fetch from)
                    const allSourcesExist = (
                        (!this.options.enableOSV || existingSources.includes('osv')) &&
                        (!this.options.enableCVEOrg || !primaryId.startsWith('CVE-') || existingSources.includes('cve.org')) &&
                        (!this.options.enableGitHubAdvisory || !primaryId.startsWith('GHSA-') || existingSources.includes('github')) &&
                        (!this.options.enableEUVD || existingSources.includes('euvd'))
                    )

                    if (!finding && !this.options.enableAIInference && !this.options.forceRefresh && allSourcesExist) {
                        logger.info(`All enabled sources already processed for ${primaryId}, skipping`)
                        return result
                    }
                }
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // PHASE 1: PARALLEL DATA FETCHING
            // Execute all independent data fetching operations in parallel for performance
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            logger.info(`📥 Starting parallel data fetching phase for ${primaryId}`)

            const parallelTasks = []
            let cveOrgBaseData: any = null // Store CVE.org data for CISA Vulnrichment processing
            let osvParsedData: any = null // Store OSV parsed CVEMetadata for Google OSI enrichment
            let githubParsedData: any = null // Store GitHub parsed CVEMetadata for Google OSI enrichment

            // Task 1: Fetch from OSV (faster and more comprehensive)
            // Always fetch if finding is provided to update aliases/related fields
            // SKIP OSV for GHSA IDs when GitHub Advisory is enabled (use GitHub as authoritative source)
            const skipOsvForGhsa = primaryId.startsWith('GHSA-') && this.options.enableGitHubAdvisory
            // SKIP OSV for EUVD IDs - OSV does not support EUVD identifiers and will return 404
            const skipOsvForEuvd = primaryId.startsWith('EUVD-')
            logger.info(`[OSV Check] enableOSV=${this.options.enableOSV}, primaryId=${primaryId}, skipOsvForGhsa=${skipOsvForGhsa}, skipOsvForEuvd=${skipOsvForEuvd}`)
            if (this.options.enableOSV && !skipOsvForGhsa && !skipOsvForEuvd) {
                const osvTask = (async () => {
                    try {
                        const osv = new OSV()
                        let osvData = null

                        // Check R2 cache first before making API call
                        const cachedOsv = await this.checkR2Cache(primaryId, logger)
                        if (cachedOsv && cachedOsv.source === 'osv') {
                            logger.info(`✅ Using cached OSV data for ${primaryId} from R2`)
                            osvData = cachedOsv.data
                        } else {
                            // First try the normalized vulnId (GHSA, PYSEC, etc.)
                            logger.info(`Fetching ${primaryId} from OSV API`)
                            osvData = await osv.query(this.prisma, this.options.orgId, this.options.memberId, primaryId)
                        }

                        // For non-CVE IDs, extract CVE from aliases and query it separately
                        if (osvData && !primaryId.startsWith('CVE-')) {
                            // Extract CVE ID from OSV aliases if not already known
                            // Normalize all aliases to uppercase
                            if (!cveId && osvData.aliases && Array.isArray(osvData.aliases)) {
                                const normalizedAliases = osvData.aliases.map((a: string) => a.toUpperCase())
                                cveId = normalizedAliases.find((a: string) => a.startsWith('CVE-')) || null
                                // Update osvData.aliases with normalized values
                                osvData.aliases = normalizedAliases
                            }
                        }

                        if (osvData) {
                            // Validate OSV data before storing - check for error responses
                            // OSV returns { message: "Bug not found." } when vulnerability doesn't exist
                            const hasErrorMessage = osvData.message && (
                                osvData.message.toLowerCase().includes('not found') ||
                                osvData.message.toLowerCase().includes('bug not found')
                            )
                            const isValidOsvData = osvData.id && !hasErrorMessage

                            // Store raw OSV JSON to R2 if adapter available and data is valid
                            if (this.options.r2adapter && isValidOsvData) {
                                try {
                                    await storeVulnJsonToR2(this.options.r2adapter, primaryId, `osv`, osvData, logger)
                                } catch (r2Error: any) {
                                    logger.warn(`Failed to store OSV JSON to R2: ${r2Error.message}`)
                                }
                            } else if (!isValidOsvData) {
                                logger.info(`Skipping R2 storage for ${primaryId} - OSV returned error: ${osvData.message || 'Invalid data'}`)
                                osvData = null // Clear osvData so it's not processed further
                            }

                            // Check if OSV record already exists for this ID
                            const existingOSV = await this.prisma.cVEMetadata.findFirst({
                                where: { cveId: primaryId, source: 'osv' }
                            })

                            // Store CVEMetadata when autoSave is enabled and OSV record doesn't exist (or forceRefresh is true)
                            const shouldProcess = this.options.autoSave && (!existingOSV || this.options.forceRefresh)

                            if (shouldProcess) {
                                // Store with the PRIMARY ID (GHSA-*, PYSEC-*, etc.)
                                const parsedCVEData = parseOSVToCVE(osvData, primaryId)
                                if (parsedCVEData && this.validateParsedData(parsedCVEData, 'osv')) {
                                    await storeCVEData(this.prisma, parsedCVEData, logger)
                                    logger.info(`${existingOSV ? 'Updated' : 'Stored'} ${primaryId} CVE metadata from OSV`)

                                    // Store parsed data for Google OSI enrichment (if enabled)
                                    osvParsedData = parsedCVEData

                                    // Store references if available (always process when forceRefresh or new record)
                                    logger.info(`[VulnProcessor] OSV parsedCVEData has ${parsedCVEData.references?.length || 0} references`)
                                    if (parsedCVEData.references && parsedCVEData.references.length > 0) {
                                        await this.storeCVEReferences(
                                            primaryId,
                                            'osv',
                                            parsedCVEData.references,
                                            'OSV.dev',
                                            logger,
                                            false, // Don't check HTTP status on initial storage
                                            this.options.forceRefresh // Pass forceRefresh to delete existing refs
                                        )
                                        logger.info(`Stored ${parsedCVEData.references.length} reference(s) for ${primaryId} from OSV`)
                                    }
                                } else if (parsedCVEData) {
                                    logger.warn(`Parsed OSV data failed validation for ${primaryId}, skipping storage`)
                                }
                            }

                            // Only mark OSV as successful if we actually processed and stored data
                            result.sources.push('osv')
                            result.osvAdded = true
                        } else {
                            logger.warn(`OSV returned no data for ${primaryId} - not marking as source`)
                        }
                    } catch (osvError) {
                        logger.error(`Failed to fetch/store ${primaryId} from OSV:`, osvError)
                    }
                })()
                parallelTasks.push(osvTask)
            }

            // Task 2: Fetch from GitHub Security Advisory (for GHSA IDs)
            // IMPORTANT: Only executes if primaryId is a GHSA ID
            logger.info(`[GitHub Advisory Check] enableGitHubAdvisory=${this.options.enableGitHubAdvisory}, primaryId=${primaryId}, startsWith GHSA-=${primaryId.startsWith('GHSA-')}`)
            if (this.options.enableGitHubAdvisory && primaryId.startsWith('GHSA-')) {
                const githubTask = (async () => {
                    try {
                        // Check if this CVE-source combination recently failed
                        const hasGithubFailed = await this.hasRecentFailure(primaryId, 'github', logger)
                        if (hasGithubFailed) {
                            logger.info(`Skipping GitHub Advisory for ${primaryId} - recently failed`)
                            return
                        }

                        let ghData = null

                        // Check R2 cache first before making API call
                        const cachedGithub = await this.checkR2Cache(primaryId, logger)
                        if (cachedGithub && cachedGithub.source === 'github') {
                            logger.info(`✅ Using cached GitHub Advisory data for ${primaryId} from R2`)
                            ghData = cachedGithub.data
                        } else {
                            logger.info(`Fetching ${primaryId} from GitHub Security Advisory API`)
                            const githubAdvisory = new GitHubAdvisory()
                            ghData = await githubAdvisory.query(this.prisma, this.options.orgId, this.options.memberId, primaryId, undefined, this.options.r2adapter)
                        }

                        if (ghData) {
                            // Store raw GitHub Advisory JSON to R2 if adapter available and not from cache
                            if (this.options.r2adapter && !cachedGithub) {
                                try {
                                    await storeVulnJsonToR2(this.options.r2adapter, primaryId, `github`, ghData, logger)
                                } catch (r2Error: any) {
                                    logger.warn(`Failed to store GitHub Advisory JSON to R2: ${r2Error.message}`)
                                }
                            }

                            // Extract CVE ID from GitHub advisory if not already known
                            if (!cveId && ghData.cve_id) {
                                cveId = ghData.cve_id
                                logger.info(`Discovered CVE ID ${cveId} from GitHub Advisory ${primaryId}`)
                            }

                            // Check if GHSA record exists (using composite key: cveId + source)
                            const existingGHSA = await this.prisma.cVEMetadata.findFirst({
                                where: { cveId: primaryId, source: 'github' }
                            })

                            // Store CVEMetadata when autoSave is enabled (always process if forceRefresh is true)
                            const shouldProcess = this.options.autoSave && (!existingGHSA || this.options.forceRefresh)

                            if (shouldProcess) {
                                const parsedGHData = parseGitHubAdvisoryToCVE(ghData, primaryId)
                                if (parsedGHData && this.validateParsedData(parsedGHData, 'github')) {
                                    await storeCVEData(this.prisma, parsedGHData, logger)
                                    logger.info(`${existingGHSA ? 'Updated' : 'Stored'} ${primaryId} CVE metadata from GitHub Advisory`)

                                    // Store parsed data for Google OSI enrichment (if enabled)
                                    githubParsedData = parsedGHData

                                    // Store references if available
                                    logger.info(`[VulnProcessor] GitHub Advisory parsedData has ${parsedGHData.references?.length || 0} references`)
                                    if (parsedGHData.references && parsedGHData.references.length > 0) {
                                        await this.storeCVEReferences(
                                            primaryId,
                                            'github',
                                            parsedGHData.references,
                                            'GitHub Security Advisory',
                                            logger,
                                            false, // Don't check HTTP status on initial storage
                                            this.options.forceRefresh // Pass forceRefresh to delete existing refs
                                        )
                                        logger.info(`Stored ${parsedGHData.references.length} reference(s) for ${primaryId} from GitHub Advisory`)
                                    }

                                    // Establish CVEAlias relation if CVE ID was discovered
                                    // This creates bidirectional junction table entries linking GHSA <-> CVE
                                    if (cveId && cveId !== primaryId) {
                                        await establishCVEAliasRelations(
                                            this.prisma,
                                            primaryId,
                                            'github',
                                            [cveId],
                                            'github',
                                            logger
                                        )
                                        logger.info(`Established CVEAlias relation: ${primaryId}:github <-> ${cveId}`)
                                    }
                                } else if (parsedGHData) {
                                    logger.warn(`Parsed GitHub Advisory data failed validation for ${primaryId}, skipping storage`)
                                }
                            }

                            result.sources.push('github')
                        } else {
                            logger.warn(`GitHub Advisory API returned no data for ${primaryId}`)
                        }
                    } catch (githubError) {
                        logger.error(`Failed to fetch/store ${primaryId} from GitHub Advisory:`, githubError)
                        await this.markFailure(primaryId, 'github', logger)
                    }
                })()
                parallelTasks.push(githubTask)
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // Task 3: Fetch from CVE.org (SEQUENTIAL - RUNS FIRST)
            // IMPORTANT: Executes BEFORE parallel tasks to ensure cve.org data exists
            // GitHub PoC and Nuclei tasks depend on cve.org CVEMetadata being available
            // ONLY executes if the normalized vulnId starts with CVE-
            // For non-CVE IDs (GHSA, PYSEC, etc.), skip CVE.org even if CVE alias discovered
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            logger.info(`[CVE.org Check] enableCVEOrg=${this.options.enableCVEOrg}, vulnId=${primaryId}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)
            if (this.options.enableCVEOrg && primaryId.startsWith('CVE-')) {
                const cveOrgTask = async () => {
                    try {
                        let cveData = null
                        let fromCache = false

                        // Step 1: Check R2 cache first (respects forceRefresh internally)
                        const cachedCveOrg = await this.checkR2Cache(primaryId, logger)
                        if (cachedCveOrg && cachedCveOrg.source === 'cve-org') {
                            logger.info(`[CVE.org] ✅ Found data in R2 cache for ${primaryId}`)
                            cveData = cachedCveOrg.data
                            fromCache = true
                        }

                        // Step 2: If no R2 cache and forceRefresh is disabled, check database freshness
                        if (!cveData && !this.options.forceRefresh) {
                            const { isFresh, ageInHours } = await this.isDataFreshInDatabase(primaryId, 'cve-org', logger)
                            if (isFresh) {
                                logger.info(`[CVE.org] ⏭️  Skipping API call for ${primaryId} - data fetched ${ageInHours}h ago (within 24h TTL)`)
                                return // Skip API call entirely
                            }
                        }

                        // Step 3: Fetch from API if needed
                        if (!cveData) {
                            logger.info(`[CVE.org] 🔄 Fetching ${primaryId} from CVE.org API`)
                            const mitreCVE = new MitreCVE()
                            cveData = await mitreCVE.query(this.prisma, this.options.orgId, this.options.memberId, primaryId, null)
                        }

                        if (cveData) {
                            // Store CVE.org data for CISA Vulnrichment processing (avoids R2 race condition)
                            cveOrgBaseData = cveData

                            // Step 4: Store CVE.org full JSON to R2 (only if fetched from API, not from cache)
                            if (this.options.r2adapter && !fromCache) {
                                try {
                                    await storeVulnJsonToR2(this.options.r2adapter, primaryId, `cve.org`, cveData, logger)
                                    logger.info(`[CVE.org] 💾 Stored raw JSON to R2 for ${primaryId}`)
                                } catch (r2Error: any) {
                                    logger.warn(`[CVE.org] Failed to store JSON to R2: ${r2Error.message}`)
                                }
                            }

                            // Check if CVE record exists for this CVE ID
                            const existingCVE = await this.prisma.cVEMetadata.findFirst({
                                where: { cveId: primaryId }
                            })

                            // Store CVEMetadata when autoSave is enabled (always process if forceRefresh is true)
                            const shouldProcess = this.options.autoSave && (!existingCVE || this.options.forceRefresh)

                            if (shouldProcess) {
                                const parsedCVEData = parseCVEOrgToCVE(cveData, logger)
                                if (parsedCVEData && this.validateParsedData(parsedCVEData, 'cve.org')) {
                                    await storeCVEData(this.prisma, parsedCVEData, logger)
                                    logger.info(`${existingCVE ? 'Updated' : 'Stored'} ${primaryId} CVE metadata from CVE.org`)

                                    // Store SSVC decisions if finding is provided (requires findingUuid)
                                    if (finding && parsedCVEData.ssvcDecisions && parsedCVEData.ssvcDecisions.length > 0) {
                                        await storeSSVCDecisions(
                                            this.prisma,
                                            finding.uuid,
                                            parsedCVEData.ssvcDecisions,
                                            null, // No triage UUID at this stage
                                            logger
                                        )
                                        logger.info(`Stored ${parsedCVEData.ssvcDecisions.length} SSVC decision(s) for finding ${finding.uuid}`)
                                    }

                                    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                                    // STORE CVE IMPACTS FROM CNA AND ADP CONTAINERS
                                    // Extract and store CAPEC-based impact scenarios from CVEListV5 format
                                    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                                    try {
                                        // Extract CNA impacts from containers.cna.impacts
                                        if (cveData.containers?.cna?.impacts && Array.isArray(cveData.containers.cna.impacts)) {
                                            logger.info(`Storing ${cveData.containers.cna.impacts.length} CNA impact(s) for ${primaryId}`)
                                            await storeCVEImpacts(
                                                this.prisma,
                                                primaryId,
                                                'cve.org',
                                                'cna',
                                                cveData.containers.cna.impacts,
                                                null,
                                                logger
                                            )
                                        }

                                        // Extract ADP impacts from containers.adp[].impacts
                                        if (cveData.containers?.adp && Array.isArray(cveData.containers.adp)) {
                                            for (const adpContainer of cveData.containers.adp) {
                                                if (adpContainer.impacts && Array.isArray(adpContainer.impacts)) {
                                                    const adpOrgId = adpContainer.providerMetadata?.orgId || null
                                                    const adpShortName = adpContainer.providerMetadata?.shortName || 'Unknown ADP'
                                                    logger.info(`Storing ${adpContainer.impacts.length} ADP impact(s) from ${adpShortName} for ${primaryId}`)
                                                    await storeCVEImpacts(
                                                        this.prisma,
                                                        primaryId,
                                                        'cve.org',
                                                        'adp',
                                                        adpContainer.impacts,
                                                        adpOrgId,
                                                        logger
                                                    )
                                                }
                                            }
                                        }
                                    } catch (impactError) {
                                        logger.error(`Failed to store impacts for ${primaryId} from CVE.org:`, impactError)
                                        // Don't fail the entire operation if impact storage fails
                                    }

                                    // Store references if available (always process when forceRefresh or new CVE)
                                    logger.info(`[VulnProcessor] CVE.org parsedCVEData has ${parsedCVEData.references?.length || 0} references`)
                                    if (parsedCVEData.references && parsedCVEData.references.length > 0) {
                                    await this.storeCVEReferences(
                                        primaryId,
                                        'cve.org',
                                        parsedCVEData.references,
                                        'CVE.org',
                                        logger,
                                        false, // Don't check HTTP status on initial storage
                                        this.options.forceRefresh // Pass forceRefresh to delete existing refs
                                    )
                                    logger.info(`Stored ${parsedCVEData.references.length} reference(s) for ${primaryId} from CVE.org`)
                                    }
                                } else if (parsedCVEData) {
                                    logger.warn(`Parsed CVE.org data failed validation for ${primaryId}, skipping storage`)
                                }
                            }

                            result.sources.push('cve.org')
                            result.cveOrgAdded = true
                        } else {
                            logger.warn(`CVE.org returned no data for ${primaryId}`)
                        }
                    } catch (cveOrgError) {
                        logger.error(`Failed to fetch/store ${primaryId} from CVE.org:`, cveOrgError)
                    }
                }
                // Execute cve.org task immediately (before parallel tasks)
                await cveOrgTask()
                logger.info(`✅ CVE.org sequential fetch completed for ${primaryId}`)
            }

            // Task 3.5: Fetch from NIST NVD (National Vulnerability Database)
            // IMPORTANT: ONLY executes if the normalized vulnId starts with CVE-
            // Provides comprehensive enrichment with CVSS scores, CWE classifications, and CPE configurations
            // Store NVD data in variable for Anchore ADP to use (avoid R2 race condition)
            let nvdBaseData: any = null

            logger.info(`[NIST NVD Check] enableNistNvd=${this.options.enableNistNvd}, vulnId=${primaryId}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)
            if (this.options.enableNistNvd && primaryId.startsWith('CVE-')) {
                const nistNvdTask = (async () => {
                    try {
                        // Check if this CVE-source combination recently failed
                        const hasNvdFailed = await this.hasRecentFailure(primaryId, 'nvd', logger)
                        if (hasNvdFailed) {
                            logger.info(`[NIST NVD] ⏭️  Skipping ${primaryId} - recently failed`)
                            return
                        }

                        let nvdVulnerability = null
                        let fromCache = false

                        // Step 1: Check R2 cache first (respects forceRefresh internally)
                        const cachedNvd = await this.checkR2Cache(primaryId, logger)
                        if (cachedNvd && cachedNvd.source === 'nist-nvd') {
                            logger.info(`[NIST NVD] ✅ Found data in R2 cache for ${primaryId}`)
                            nvdVulnerability = cachedNvd.data
                            fromCache = true
                        }

                        // Step 2: If no R2 cache and forceRefresh is disabled, check database freshness
                        if (!nvdVulnerability && !this.options.forceRefresh) {
                            const { isFresh, ageInHours } = await this.isDataFreshInDatabase(primaryId, 'nist-nvd', logger)
                            if (isFresh) {
                                logger.info(`[NIST NVD] ⏭️  Skipping API call for ${primaryId} - data fetched ${ageInHours}h ago (within 7d TTL)`)
                                return // Skip API call entirely
                            }
                        }

                        // Step 3: Fetch from API if needed
                        if (!nvdVulnerability) {
                            logger.info(`[NIST NVD] 🔄 Fetching ${primaryId} from NIST NVD API`)
                            const nistNvd = new NistNVD()
                            nvdVulnerability = await nistNvd.query(this.prisma, this.options.orgId, this.options.memberId, primaryId, logger, this.options.r2adapter, this.options.env)
                        }

                        if (nvdVulnerability) {
                            // Store NVD data for Anchore ADP to use
                            nvdBaseData = nvdVulnerability

                            // Step 4: Store raw NIST NVD JSON to R2 (only if fetched from API, not from cache)
                            if (this.options.r2adapter && !fromCache) {
                                try {
                                    await storeVulnJsonToR2(this.options.r2adapter, primaryId, `nist-nvd`, nvdVulnerability, logger)
                                    logger.info(`[NIST NVD] 💾 Stored raw JSON to R2 for ${primaryId}`)
                                } catch (r2Error: any) {
                                    logger.warn(`[NIST NVD] Failed to store JSON to R2: ${r2Error.message}`)
                                }
                            }

                            // Check if NIST NVD record exists for this CVE ID
                            const existingNVD = await this.prisma.cVEMetadata.findFirst({
                                where: { cveId: primaryId, source: 'nvd' }
                            })

                            // Store CVEMetadata when autoSave is enabled (always process if forceRefresh is true)
                            const shouldProcess = this.options.autoSave && (!existingNVD || this.options.forceRefresh)

                            if (shouldProcess) {
                                const parsedNVDData = parseNistNvdToCVE(nvdVulnerability, logger)
                                if (parsedNVDData && this.validateParsedData(parsedNVDData, 'nvd')) {
                                    await storeCVEData(this.prisma, parsedNVDData, logger)
                                    logger.info(`${existingNVD ? 'Updated' : 'Stored'} ${primaryId} CVE metadata from NIST NVD`)

                                    // Store references if available (always process when forceRefresh or new record)
                                    logger.info(`[VulnProcessor] NIST NVD parsedData has ${parsedNVDData.references?.length || 0} references`)
                                    if (parsedNVDData.references && parsedNVDData.references.length > 0) {
                                        await this.storeCVEReferences(
                                            primaryId,
                                            'nvd',
                                            parsedNVDData.references,
                                            'NIST NVD',
                                            logger,
                                            false, // Don't check HTTP status on initial storage
                                            this.options.forceRefresh // Pass forceRefresh to delete existing refs
                                        )
                                        logger.info(`Stored ${parsedNVDData.references.length} reference(s) for ${primaryId} from NIST NVD`)
                                    }
                                } else if (parsedNVDData) {
                                    logger.warn(`Parsed NIST NVD data failed validation for ${primaryId}, skipping storage`)
                                }
                            }

                            result.sources.push('nvd')
                            result.nistNvdAdded = true
                        } else {
                            logger.warn(`NIST NVD returned no data for ${primaryId}`)
                        }
                    } catch (nistNvdError) {
                        logger.error(`Failed to fetch/store ${primaryId} from NIST NVD:`, nistNvdError)
                        await this.markFailure(primaryId, 'nvd', logger)
                    }
                })()
                parallelTasks.push(nistNvdTask)
            }

            // Task 4: Fetch EPSS time series (30 days)
            // IMPORTANT: ONLY executes if the normalized vulnId starts with CVE-
            // For non-CVE IDs (GHSA, PYSEC, etc.), skip EPSS even if CVE alias discovered
            logger.info(`[EPSS Check] enableEPSS=${this.options.enableEPSS}, vulnId=${primaryId}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)
            if (this.options.enableEPSS && primaryId.startsWith('CVE-')) {
                // Check if bulk EPSS data is fresh (last 24 hours)
                const epssBulkDataFresh = await this.isBulkDataFresh('epss', logger)

                const epssTask = (async () => {
                    try {
                        // Check if this CVE-source combination recently failed
                        const hasEpssFailed = await this.hasRecentFailure(primaryId, 'epss', logger)
                        if (hasEpssFailed) {
                            logger.info(`Skipping EPSS for ${primaryId} - recently failed`)
                            return
                        }

                        // Check if EPSS data already exists for this specific CVE
                        const existingEpss = await this.prisma.epssScore.findFirst({
                            where: { cve: primaryId }
                        })

                        // Only fetch if forceRefresh OR (no bulk data AND no existing data for this CVE)
                        // If bulk data is fresh but this CVE doesn't have data, skip (it's not in EPSS dataset)
                        if (this.options.forceRefresh || (!epssBulkDataFresh && !existingEpss)) {
                            logger.info(`Fetching EPSS time series for ${primaryId}`)
                            const epss = new EPSS()
                            const epssData = await epss.query(this.prisma, this.options.orgId, this.options.memberId, primaryId, this.options.r2adapter)
                            
                            // Store raw EPSS JSON to R2 if adapter available
                            if (this.options.r2adapter && epssData) {
                                try {
                                    // EPSS doesn't have a standard R2 config, use custom path
                                    const epssPath = `epss/${primaryId}.json`
                                    await this.options.r2adapter.put(epssPath, JSON.stringify(epssData, null, 2), {
                                        httpMetadata: { contentType: `application/json` }
                                    })
                                    logger.info(`Stored EPSS raw JSON to R2: ${epssPath}`)
                                } catch (r2Error: any) {
                                    logger.warn(`Failed to store EPSS JSON to R2: ${r2Error.message}`)
                                }
                            }

                            // Note: epss.query() already fetches time series internally, no need to call fetchTimeSeries() again

                            const epssScores = await this.prisma.epssScore.findMany({
                                where: { cve: primaryId },
                                take: 1
                            })

                            if (epssScores.length > 0) {
                                result.epssAdded = true
                                logger.info(`Added EPSS time series for ${primaryId}`)
                            }
                        } else {
                            if (epssBulkDataFresh) {
                                logger.info(`EPSS bulk data is fresh (< 24h), skipping API call for ${primaryId}`)
                            } else {
                                logger.info(`EPSS data already exists for ${primaryId}, skipping (use forceRefresh to update)`)
                            }
                            result.epssAdded = false
                        }
                    } catch (epssError) {
                        logger.warn(`Failed to fetch EPSS for ${primaryId}:`, epssError)
                        await this.markFailure(primaryId, 'epss', logger)
                    }
                })()
                parallelTasks.push(epssTask)
            }

            // Task 5: Fetch CESS history and exploits
            // IMPORTANT: ONLY executes if the normalized vulnId starts with CVE-
            // For non-CVE IDs (GHSA, PYSEC, etc.), skip ESS even if CVE alias discovered
            logger.info(`[ESS Check] enableCESS=${this.options.enableCESS}, vulnId=${primaryId}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)
            if (this.options.enableCESS && primaryId.startsWith('CVE-')) {
                // Check if bulk CESS data is fresh (last 24 hours)
                const cessBulkDataFresh = await this.isBulkDataFresh('cess', logger)

                const cessTask = (async () => {
                    try {
                        // Check if this CVE-source combination recently failed
                        const hasCessFailed = await this.hasRecentFailure(primaryId, 'cess', logger)
                        if (hasCessFailed) {
                            logger.info(`Skipping CESS for ${primaryId} - recently failed`)
                            return
                        }

                        // Check if CESS data already exists for this specific CVE
                        const existingCess = await this.prisma.cessScore.findFirst({
                            where: { cve: primaryId }
                        })

                        // Only fetch if forceRefresh OR (no bulk data AND no existing data for this CVE)
                        // If bulk data is fresh but this CVE doesn't have data, skip (it's not in CESS dataset)
                        if (this.options.forceRefresh || (!cessBulkDataFresh && !existingCess)) {
                            logger.info(`Fetching ESS history for ${primaryId}`)
                            const cess = new CESS(this.options.env?.CESS_API_URL)
                            const cessData = await cess.query(this.prisma, this.options.orgId, this.options.memberId, primaryId, this.options.r2adapter)
                            
                            // Store raw CESS JSON to R2 if adapter available
                            if (this.options.r2adapter && cessData) {
                                try {
                                    // CESS (ESS) doesn't have a standard R2 config, use custom path
                                    const cessPath = `cess/${primaryId}.json`
                                    await this.options.r2adapter.put(cessPath, JSON.stringify(cessData, null, 2), {
                                        httpMetadata: { contentType: `application/json` }
                                    })
                                    logger.info(`Stored ESS raw JSON to R2: ${cessPath}`)
                                } catch (r2Error: any) {
                                    logger.warn(`Failed to store ESS JSON to R2: ${r2Error.message}`)
                                }
                            }
                            
                            // Also fetch history for historical data
                            await cess.fetchHistory(this.prisma, this.options.orgId, this.options.memberId, primaryId)

                            const cessScores = await this.prisma.cessScore.findMany({
                                where: { cve: primaryId },
                                take: 1
                            })

                            if (cessScores.length > 0) {
                                result.cessAdded = true
                                logger.info(`Added ESS history for ${primaryId}`)
                            }

                            // Fetch exploits from ExploitDB and Metasploit (with R2 caching)
                            logger.info(`Fetching exploits for ${primaryId}`)
                            await cess.fetchExploits(this.prisma, this.options.orgId, this.options.memberId, primaryId, this.options.r2adapter)
                        } else {
                            if (cessBulkDataFresh) {
                                logger.info(`CESS bulk data is fresh (< 24h), skipping API call for ${primaryId}`)
                            } else {
                                logger.info(`ESS data already exists for ${primaryId}, skipping (use forceRefresh to update)`)
                            }
                            result.cessAdded = false
                        }
                    } catch (cessError) {
                        logger.warn(`Failed to fetch ESS for ${primaryId}:`, cessError)
                        await this.markFailure(primaryId, 'cess', logger)
                    }
                })()
                parallelTasks.push(cessTask)
            }

            // Task 6: Check CISA KEV (Known Exploited Vulnerabilities) data from database
            // IMPORTANT: ONLY executes if the normalized vulnId starts with CVE-
            // For non-CVE IDs (GHSA, PYSEC, etc.), skip KEV even if CVE alias discovered
            // NOTE: Database/R2-only - no API calls. KEV data is populated by scheduled workers.
            logger.info(`[CISA KEV Check] enableKEV=${this.options.enableKEV}, vulnId=${primaryId}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)
            if (this.options.enableKEV && primaryId.startsWith('CVE-')) {
                const kevTask = (async () => {
                    try {
                        // Check database for existing CISA KEV entry (database-only, no API calls)
                        const existingKev = await this.prisma.kev.findUnique({
                            where: {
                                cveID_source: {
                                    cveID: primaryId,
                                    source: 'CISA'
                                }
                            }
                        })

                        if (existingKev) {
                            logger.info(`[CISA KEV] ✅ Found KEV data for ${primaryId} in database`)
                            logger.info(`[CISA KEV]    - Date Added: ${new Date(existingKev.dateAdded * 1000).toISOString().split('T')[0]}`)
                            logger.info(`[CISA KEV]    - Due Date: ${new Date(existingKev.dueDate * 1000).toISOString().split('T')[0]}`)
                            logger.info(`[CISA KEV]    - Vendor/Product: ${existingKev.vendorProject} / ${existingKev.product}`)
                            if (existingKev.knownRansomwareCampaignUse) {
                                logger.info(`[CISA KEV]    - Ransomware Campaign Use: ${existingKev.knownRansomwareCampaignUse}`)
                            }

                            result.kevAdded = true

                            // Update Finding with KEV data if finding is provided
                            if (finding && this.options.autoSave) {
                                try {
                                    await this.prisma.finding.update({
                                        where: { uuid: finding.uuid },
                                        data: {
                                            cisaKevDate: existingKev.dateAdded,
                                            knownRansomwareCampaignUse: existingKev.knownRansomwareCampaignUse || null,
                                            cisaDateAdded: existingKev.dateAdded
                                        }
                                    })
                                    logger.info(`[CISA KEV] Updated Finding ${finding.uuid} with KEV data`)
                                } catch (updateError) {
                                    logger.error(`[CISA KEV] Failed to update Finding with KEV data:`, updateError)
                                }
                            }
                        } else {
                            logger.debug(`[CISA KEV] No KEV data found for ${primaryId} in database`)
                            result.kevAdded = false
                        }
                    } catch (kevError) {
                        logger.warn(`[CISA KEV] Failed to check database for ${primaryId}:`, kevError)
                        result.kevAdded = false
                    }
                })()
                parallelTasks.push(kevTask)
            }

            // Task 7: Fetch from EUVD (European Union Vulnerability Database)
            // Supports both CVE IDs and EUVD IDs (EUVD-YYYY-NNNNN format)
            if (this.options.enableEUVD) {
                const euvdTask = (async () => {
                    try {
                        // Check if this CVE-source combination recently failed
                        const hasEuvdFailed = await this.hasRecentFailure(primaryId, 'euvd', logger)
                        if (hasEuvdFailed) {
                            logger.info(`Skipping EUVD for ${primaryId} - recently failed`)
                            return
                        }

                        let euvdData = null

                        // Check R2 cache first before making API call
                        const cachedEuvd = await this.checkR2Cache(primaryId, logger)
                        if (cachedEuvd && cachedEuvd.source === 'euvd') {
                            logger.info(`✅ Using cached EUVD data for ${primaryId} from R2`)
                            euvdData = cachedEuvd.data
                        } else {
                            logger.info(`Fetching ${primaryId} from EUVD API`)
                            const euvd = new EUVD()
                            euvdData = await euvd.query(this.prisma, this.options.orgId, this.options.memberId, primaryId, logger, this.options.r2adapter)
                        }

                        if (euvdData) {
                            // Store raw EUVD JSON to R2 if adapter available and not from cache
                            // Use EUVD vendorId if available, otherwise fall back to primaryId
                            const euvdFileIdentifier = euvdData.vendorId || primaryId
                            if (this.options.r2adapter && !cachedEuvd) {
                                try {
                                    await storeVulnJsonToR2(this.options.r2adapter, euvdFileIdentifier, `euvd`, euvdData, logger)
                                } catch (r2Error: any) {
                                    logger.warn(`Failed to store EUVD JSON to R2: ${r2Error.message}`)
                                }
                            }

                            // Determine the correct identifier for EUVD data
                            // Convert EUVD ID to CVE ID by replacing prefix
                            let euvdIdentifier = primaryId
                            let useCveIdentifier = false

                            if (primaryId.startsWith('EUVD-')) {
                                const potentialCveId = primaryId.replace(/^EUVD-/i, 'CVE-')
                                logger.info(`Checking if CVE ${potentialCveId} exists for EUVD ${primaryId}`)

                                // Check if CVE exists in database
                                const existingCVE = await this.prisma.cVEMetadata.findFirst({
                                    where: { cveId: potentialCveId }
                                })

                                if (existingCVE) {
                                    logger.info(`Found existing CVE ${potentialCveId} in database, using it as EUVD identifier`)
                                    euvdIdentifier = potentialCveId
                                    useCveIdentifier = true
                                } else {
                                    logger.info(`CVE ${potentialCveId} not found in database, storing as EUVD ${primaryId}`)
                                    euvdIdentifier = primaryId
                                    useCveIdentifier = false
                                }
                            }

                            // Check if EUVD record exists
                            const existingEUVD = await this.prisma.cVEMetadata.findFirst({
                                where: { cveId: euvdIdentifier, source: 'euvd' }
                            })

                            // Store CVEMetadata when autoSave is enabled (always process if forceRefresh is true)
                            const shouldProcess = this.options.autoSave && (!existingEUVD || this.options.forceRefresh)

                            if (shouldProcess) {
                                const parsedEUVDData = parseEUVDToCVE(euvdData, euvdIdentifier, useCveIdentifier)
                                if (parsedEUVDData && this.validateParsedData(parsedEUVDData, 'euvd')) {
                                    await storeCVEData(this.prisma, parsedEUVDData, logger)
                                    logger.info(`${existingEUVD ? 'Updated' : 'Stored'} ${euvdIdentifier} CVE metadata from EUVD`)

                                    // Verify the parent CVEMetadata record exists before storing references
                                    const verifyParent = await this.prisma.cVEMetadata.findUnique({
                                        where: {
                                            cveId_source: {
                                                cveId: euvdIdentifier,
                                                source: 'euvd'
                                            }
                                        }
                                    })

                                    if (!verifyParent) {
                                        logger.error(`Failed to verify EUVD CVEMetadata parent record for ${euvdIdentifier}`)
                                    } else {
                                        // Store references if available
                                        logger.info(`[VulnProcessor] EUVD parsedData has ${parsedEUVDData.references?.length || 0} references`)
                                        if (parsedEUVDData.references && parsedEUVDData.references.length > 0) {
                                            await this.storeCVEReferences(
                                                euvdIdentifier,
                                                'euvd',
                                                parsedEUVDData.references,
                                                'EUVD (ENISA)',
                                                logger,
                                                false, // Don't check HTTP status on initial storage
                                                this.options.forceRefresh // Pass forceRefresh to delete existing refs
                                            )
                                            logger.info(`Stored ${parsedEUVDData.references.length} reference(s) for ${euvdIdentifier} from EUVD`)
                                        }
                                    }
                                } else if (parsedEUVDData) {
                                    logger.warn(`Parsed EUVD data failed validation for ${euvdIdentifier}, skipping storage`)
                                }
                            }

                            result.sources.push('euvd')
                            result.euvdAdded = true
                            logger.info(`Successfully processed EUVD data for ${primaryId}`)
                        } else {
                            logger.warn(`EUVD returned no data for ${primaryId}`)
                        }
                    } catch (euvdError) {
                        logger.error(`Failed to fetch/store ${primaryId} from EUVD:`, euvdError)
                        await this.markFailure(primaryId, 'euvd', logger)
                    }
                })()
                parallelTasks.push(euvdTask)
            }

            // Task 8: Fetch GitHub PoC data from nomi-sec/PoC-in-GitHub
            // IMPORTANT: ONLY executes if we have a CVE ID (from primaryId or aliases)
            // Fetches exploit proof-of-concept repositories from GitHub
            logger.info(`[GitHub PoC Check] primaryId=${primaryId}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)

            // Determine if we have a CVE ID to work with
            let pocCveId = primaryId.startsWith('CVE-') ? primaryId : cveId

            if (pocCveId && pocCveId.startsWith('CVE-')) {
                const githubPocTask = (async () => {
                    try {
                        // Extract year from CVE-YYYY-NNNNN format
                        const cveMatch = pocCveId.match(/^CVE-(\d{4})-\d+$/)
                        if (!cveMatch) {
                            logger.warn(`Invalid CVE format for GitHub PoC: ${pocCveId}`)
                            return
                        }

                        const year = cveMatch[1]
                        const pocUrl = `https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/refs/heads/master/${year}/${pocCveId}.json`

                        logger.info(`Fetching GitHub PoC data from: ${pocUrl}`)

                        // Fetch the JSON from nomi-sec repository
                        const response = await fetch(pocUrl, {
                            headers: {
                                'User-Agent': VULNETIX_USER_AGENT
                            }
                        })

                        if (response.status === 404) {
                            logger.info(`No GitHub PoC found for ${pocCveId} (404)`)
                            result.githubPocAdded = false
                            return
                        }

                        if (!response.ok) {
                            logger.warn(`Failed to fetch GitHub PoC for ${pocCveId}: HTTP ${response.status}`)
                            result.githubPocAdded = false
                            return
                        }

                        const pocData = await response.json()

                        if (!Array.isArray(pocData) || pocData.length === 0) {
                            logger.info(`GitHub PoC data for ${pocCveId} is empty or invalid format`)
                            result.githubPocAdded = false
                            return
                        }

                        logger.info(`Found ${pocData.length} GitHub PoC repository/repositories for ${pocCveId}`)

                        // Get the cve.org CVEMetadata record specifically for enrichment
                        // GitHub PoC references should be associated with cve.org source for README/CVSS enrichment
                        let cveMetadata = await this.prisma.cVEMetadata.findUnique({
                            where: {
                                cveId_source: {
                                    cveId: pocCveId,
                                    source: 'cve.org'
                                }
                            }
                        })

                        if (!cveMetadata) {
                            logger.warn(`No cve.org CVEMetadata found for ${pocCveId}, using or creating vulnetix stub record`)

                            // Use upsert to atomically get or create the vulnetix stub
                            // This prevents race conditions when multiple processes run concurrently
                            const now = Math.floor(Date.now() / 1000)
                            try {
                                cveMetadata = await this.prisma.cVEMetadata.upsert({
                                    where: {
                                        cveId_source: {
                                            cveId: pocCveId,
                                            source: 'vulnetix'
                                        }
                                    },
                                    update: {
                                        lastFetchedAt: now,
                                    },
                                    create: {
                                        cveId: pocCveId,
                                        source: 'vulnetix',
                                        dataVersion: '1.0',
                                        state: 'RESERVED',
                                        datePublished: now,
                                        lastFetchedAt: now,
                                        fetchCount: 1,
                                        title: pocCveId
                                    }
                                })
                                logger.info(`Using vulnetix stub record for ${pocCveId} (created or retrieved)`)
                            } catch (error) {
                                logger.error(`Failed to upsert stub CVEMetadata for ${pocCveId}:`, error)
                                result.githubPocAdded = false
                                return
                            }
                        }

                        // Store all references directly to have full control over enrichment fields
                        if (this.options.autoSave) {
                            let storedCount = 0

                            for (const repo of pocData) {
                                if (!repo.html_url) {
                                    logger.warn(`Skipping PoC repository without html_url: ${JSON.stringify(repo)}`)
                                    continue
                                }

                                try {
                                    // Convert created_at to Unix timestamp in seconds (PostgreSQL INT type)
                                    const createdAtMs = repo.created_at ?
                                        new Date(repo.created_at).getTime() :
                                        Date.now()
                                    const createdAtTimestamp = Math.floor(createdAtMs / 1000)

                                    // Check if reference already exists
                                    const existingRef = await this.prisma.cVEMetadataReferences.findFirst({
                                        where: {
                                            cveId: pocCveId,
                                            source: cveMetadata.source,
                                            url: repo.html_url
                                        }
                                    })

                                    if (existingRef && !this.options.forceRefresh) {
                                        logger.debug(`GitHub PoC reference already exists: ${repo.html_url}`)
                                        continue
                                    }

                                    const referenceData = {
                                        cveId: pocCveId,
                                        source: cveMetadata.source,
                                        url: repo.html_url,
                                        type: 'exploit',
                                        referenceSource: 'GitHub PoC (nomi-sec)',
                                        title: repo.name || repo.full_name || null,
                                        createdAt: createdAtTimestamp,
                                        // Store repository owner in commitAuthorLogin field
                                        commitAuthorLogin: repo.owner?.login || null,
                                        // Store additional repository metadata in gistFiles as JSON
                                        gistFiles: JSON.stringify({
                                            full_name: repo.full_name,
                                            description: repo.description,
                                            stargazers_count: repo.stargazers_count,
                                            forks_count: repo.forks_count,
                                            topics: repo.topics || [],
                                            updated_at: repo.updated_at,
                                            pushed_at: repo.pushed_at
                                        })
                                    }

                                    if (existingRef && this.options.forceRefresh) {
                                        // Update existing reference
                                        await this.prisma.cVEMetadataReferences.update({
                                            where: { uuid: existingRef.uuid },
                                            data: referenceData
                                        })
                                        logger.debug(`Updated GitHub PoC reference: ${repo.html_url}`)
                                    } else {
                                        // Create new reference
                                        await this.prisma.cVEMetadataReferences.create({
                                            data: referenceData
                                        })
                                        logger.debug(`Created GitHub PoC reference: ${repo.html_url}`)
                                    }

                                    // Run enrichment pipeline for README and CVSS scoring
                                    // This applies to both new and updated references
                                    try {
                                        logger.info(`[GitHub PoC Enrichment] Processing reference for enrichment: ${repo.html_url}`)
                                        const processed = await processReference(repo.html_url, 'exploit', false)
                                        await enrichReservedCVEWithReadme(
                                            this.prisma,
                                            pocCveId,
                                            cveMetadata.source,
                                            repo.html_url,
                                            processed,
                                            logger
                                        )
                                    } catch (enrichError: any) {
                                        logger.warn(`[GitHub PoC Enrichment] Enrichment failed for ${repo.html_url}:`, enrichError.message)
                                        // Don't fail the entire operation if enrichment fails
                                    }

                                    storedCount++
                                } catch (refError: any) {
                                    logger.error(`Failed to store GitHub PoC reference ${repo.html_url}:`, refError)
                                }
                            }

                            if (storedCount > 0) {
                                logger.info(`✅ Stored ${storedCount} GitHub PoC reference(s) for ${pocCveId}`)
                                result.githubPocAdded = true
                            } else {
                                logger.warn(`No GitHub PoC references were stored for ${pocCveId}`)
                                result.githubPocAdded = false
                            }
                        } else {
                            logger.info(`AutoSave disabled, skipping storage of ${pocData.length} GitHub PoC references`)
                            result.githubPocAdded = false
                        }

                    } catch (pocError: any) {
                        logger.error(`Failed to fetch/store GitHub PoC for ${pocCveId}:`, pocError)
                        result.githubPocAdded = false
                    }
                })()
                parallelTasks.push(githubPocTask)
            } else {
                logger.info(`Skipping GitHub PoC - no CVE ID available (primaryId: ${primaryId}, cveId: ${cveId})`)
            }

            // Task 9: Fetch VulnerabilityLab exploits
            // IMPORTANT: ONLY executes if we have a CVE ID (from primaryId or aliases)
            // Searches vulnerability-lab.com for exploit information
            logger.info(`[VulnerabilityLab Check] primaryId=${primaryId}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)

            // Determine if we have a CVE ID to work with
            let vlCveId = primaryId.startsWith('CVE-') ? primaryId : cveId

            if (vlCveId && vlCveId.startsWith('CVE-')) {
                const vulnerabilityLabTask = (async () => {
                    try {
                        logger.info(`Searching VulnerabilityLab for exploits: ${vlCveId}`)

                        // Search vulnerability-lab.com for the CVE
                        const searchUrl = `https://www.vulnerability-lab.com/search.php?cve=${vlCveId}&submit=Search`
                        const searchResponse = await fetch(searchUrl, {
                            headers: {
                                'User-Agent': VULNETIX_USER_AGENT,
                                'Host': 'www.vulnerability-lab.com',
                                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                            }
                        })

                        if (searchResponse.status !== 200) {
                            logger.warn(`VulnerabilityLab search failed with status ${searchResponse.status}`)
                            result.vulnerabilityLabAdded = false
                            return
                        }

                        const searchHtml = await searchResponse.text()

                        // Extract exploit IDs from the search results
                        // Pattern: get_content.php?id=1234
                        const idMatches = searchHtml.matchAll(/get_content\.php\?id=(\d+)/g)
                        const exploitIds = new Set<string>()

                        for (const match of idMatches) {
                            exploitIds.add(match[1])
                        }

                        if (exploitIds.size === 0) {
                            logger.info(`No VulnerabilityLab exploits found for ${vlCveId}`)
                            result.vulnerabilityLabAdded = false
                            return
                        }

                        logger.info(`Found ${exploitIds.size} VulnerabilityLab exploit(s) for ${vlCveId}`)

                        // Store each exploit URL as a CVE reference
                        if (this.options.autoSave) {
                            let storedCount = 0

                            for (const exploitId of exploitIds) {
                                const exploitUrl = `https://www.vulnerability-lab.com/get_content.php?id=${exploitId}`

                                try {
                                    await storeCVEMetadataReference(
                                        this.prisma,
                                        vlCveId,
                                        'vl_exploit',
                                        {
                                            url: exploitUrl,
                                            type: 'exploit'
                                        },
                                        'vulnerability-lab',
                                        logger,
                                        false, // Don't check HTTP status (can be slow)
                                        this.options.forceRefresh || false
                                    )
                                    storedCount++
                                } catch (error: any) {
                                    logger.warn(`Failed to store VulnerabilityLab exploit ${exploitId}: ${error.message}`)
                                }
                            }

                            if (storedCount > 0) {
                                logger.info(`✅ Stored ${storedCount} VulnerabilityLab exploit reference(s) for ${vlCveId}`)
                                result.vulnerabilityLabAdded = true
                            } else {
                                logger.warn(`No VulnerabilityLab exploits were successfully stored for ${vlCveId}`)
                                result.vulnerabilityLabAdded = false
                            }
                        } else {
                            logger.info(`AutoSave disabled, skipping storage of ${exploitIds.size} VulnerabilityLab exploits`)
                            result.vulnerabilityLabAdded = false
                        }

                    } catch (vlError: any) {
                        logger.error(`Failed to fetch/store VulnerabilityLab exploits for ${vlCveId}:`, vlError)
                        result.vulnerabilityLabAdded = false
                    }
                })()
                parallelTasks.push(vulnerabilityLabTask)
            } else {
                logger.info(`Skipping VulnerabilityLab - no CVE ID available (primaryId: ${primaryId}, cveId: ${cveId})`)
            }

            // Task 10: Fetch Nuclei Templates from ProjectDiscovery
            // IMPORTANT: ONLY executes if we have a CVE ID and enableNuclei is true
            // Searches projectdiscovery/nuclei-templates repository for weaponized exploit templates
            logger.info(`[Nuclei Check] primaryId=${primaryId}, startsWith CVE-=${primaryId.startsWith('CVE-')}, enableNuclei=${this.options.enableNuclei}`)

            // Determine if we have a CVE ID to work with
            let nucleiCveId = primaryId.startsWith('CVE-') ? primaryId : cveId

            if (this.options.enableNuclei && nucleiCveId && nucleiCveId.startsWith('CVE-')) {
                const nucleiTask = (async () => {
                    try {
                        logger.info(`Searching Nuclei templates for: ${nucleiCveId}`)

                        // Build the GitHub Commits Search query for exact CVE ID match in YAML files
                        const searchQuery = `${nucleiCveId} repo:projectdiscovery/nuclei-templates`
                        const encodedQuery = encodeURIComponent(searchQuery)
                        const searchUrl = `https://api.github.com/search/commits?q=${encodedQuery}`

                        logger.info(`Fetching Nuclei templates from GitHub Commits Search API: ${searchUrl}`)

                        // Prepare headers for GitHub API
                        const headers: Record<string, string> = {
                            'Accept': 'application/vnd.github+json',
                            'User-Agent': VULNETIX_USER_AGENT,
                            'X-GitHub-Api-Version': '2022-11-28'
                        }

                        // Add authorization if GitHub PAT is available via jwtCredentials
                        if (this.options.jwtCredentials?.personalAccessToken) {
                            headers['Authorization'] = `Bearer ${this.options.jwtCredentials.personalAccessToken}`
                            logger.debug(`Using GitHub PAT for authentication (rate limit: 5,000/hour)`)
                        } else {
                            logger.warn(`No GitHub PAT found in jwtCredentials, using unauthenticated API (rate limit: 60/hour)`)
                        }

                        // Fetch from GitHub Commits Search API
                        const response = await fetch(searchUrl, { headers })

                        if (response.status === 404) {
                            logger.info(`No Nuclei templates found for ${nucleiCveId} (404)`)
                            result.nucleiAdded = false
                            return
                        }

                        if (!response.ok) {
                            const errorText = await response.text()
                            logger.warn(`Failed to fetch Nuclei templates for ${nucleiCveId}: HTTP ${response.status} - ${errorText}`)
                            result.nucleiAdded = false
                            return
                        }

                        const searchData = await response.json()

                        if (!searchData.items || !Array.isArray(searchData.items) || searchData.items.length === 0) {
                            logger.info(`No Nuclei templates found for ${nucleiCveId} (empty results)`)
                            result.nucleiAdded = false
                            return
                        }

                        logger.info(`Found ${searchData.items.length} Nuclei template commit(s) for ${nucleiCveId}`)

                        // Sort items by commit date (oldest first) to get the original Nuclei template commit
                        const sortedItems = searchData.items.sort((a: any, b: any) => {
                            const aDate = a.commit?.committer?.date || a.commit?.author?.date || ''
                            const bDate = b.commit?.committer?.date || b.commit?.author?.date || ''
                            return new Date(aDate).getTime() - new Date(bDate).getTime()
                        })

                        logger.info(`Sorted ${sortedItems.length} commits by date (oldest first)`)

                        // Get the cve.org CVEMetadata record
                        let cveMetadata = await this.prisma.cVEMetadata.findUnique({
                            where: {
                                cveId_source: {
                                    cveId: nucleiCveId,
                                    source: 'cve.org'
                                }
                            }
                        })

                        if (!cveMetadata) {
                            logger.warn(`No cve.org CVEMetadata found for ${nucleiCveId}, using or creating vulnetix stub record`)

                            // Use upsert to atomically get or create the vulnetix stub
                            // This prevents race conditions when multiple processes run concurrently
                            const now = Math.floor(Date.now() / 1000)
                            try {
                                cveMetadata = await this.prisma.cVEMetadata.upsert({
                                    where: {
                                        cveId_source: {
                                            cveId: nucleiCveId,
                                            source: 'vulnetix'
                                        }
                                    },
                                    update: {
                                        lastFetchedAt: now,
                                    },
                                    create: {
                                        cveId: nucleiCveId,
                                        source: 'vulnetix',
                                        dataVersion: '1.0',
                                        state: 'PUBLISHED',
                                        datePublished: now,
                                        lastFetchedAt: now,
                                        fetchCount: 1,
                                        title: nucleiCveId
                                    }
                                })
                                logger.info(`Using vulnetix stub record for ${nucleiCveId} (created or retrieved)`)
                            } catch (error) {
                                logger.error(`Failed to upsert stub CVEMetadata for ${nucleiCveId}:`, error)
                                result.nucleiAdded = false
                                return
                            }
                        }

                        // Try each commit (oldest first) until we find one with a valid YAML file path
                        if (this.options.autoSave) {
                            let stored = false

                            for (let i = 0; i < sortedItems.length; i++) {
                                const item = sortedItems[i]

                                if (!item.html_url) {
                                    logger.debug(`Commit ${i + 1}/${sortedItems.length} (${item.sha}) missing html_url, trying next`)
                                    continue
                                }

                                try {
                                    // Extract commit data from commits search response
                                    const commitData = item.commit || {}
                                    const authorData = commitData.author || {}
                                    const committerData = commitData.committer || {}

                                    // Use committer date as primary, fallback to author date (convert to seconds)
                                    const createdAtMs = committerData.date
                                        ? new Date(committerData.date).getTime()
                                        : authorData.date
                                            ? new Date(authorData.date).getTime()
                                            : Date.now()
                                    const createdAtTimestamp = Math.floor(createdAtMs / 1000)

                                    logger.info(`Using commit ${i + 1}/${sortedItems.length} from ${committerData.date || authorData.date}`)

                                    // Check if reference already exists
                                    const existingRef = await this.prisma.cVEMetadataReferences.findFirst({
                                        where: {
                                            cveId: nucleiCveId,
                                            source: cveMetadata.source,
                                            url: item.html_url
                                        }
                                    })

                                    if (existingRef && !this.options.forceRefresh) {
                                        logger.info(`Nuclei template reference already exists: ${item.html_url}`)
                                        result.nucleiAdded = true
                                        stored = true
                                        break
                                    }

                                    const referenceData = {
                                        cveId: nucleiCveId,
                                        source: cveMetadata.source,
                                        url: item.html_url,
                                        type: 'exploit',
                                        referenceSource: 'nuclei-templates',
                                        title: `Weaponized ${nucleiCveId} in Nuclei`,
                                        createdAt: createdAtTimestamp,
                                        commitSha: item.sha || null,
                                        commitAuthorName: authorData.name || null,
                                        commitAuthorEmail: authorData.email || null,
                                        commitCommitterName: committerData.name || null,
                                        commitCommitterEmail: committerData.email || null,
                                        commitMessage: commitData.message || null,
                                        commentCount: commitData.comment_count || 0,
                                        nucleiPath: item.commit.tree.url
                                    }

                                    if (existingRef) {
                                        // Update existing reference
                                        await this.prisma.cVEMetadataReferences.update({
                                            where: { uuid: existingRef.uuid },
                                            data: referenceData
                                        })
                                        logger.info(`✅ Updated Nuclei template reference (commit ${i + 1}/${sortedItems.length}): ${item.html_url}`)
                                    } else {
                                        // Create new reference
                                        await this.prisma.cVEMetadataReferences.create({
                                            data: referenceData
                                        })
                                        logger.info(`✅ Created Nuclei template reference (commit ${i + 1}/${sortedItems.length}): ${item.html_url}`)
                                    }

                                    result.nucleiAdded = true
                                    stored = true
                                    break // Successfully stored, exit loop
                                } catch (refError: any) {
                                    logger.warn(`Failed to process commit ${i + 1}/${sortedItems.length} (${item.sha}):`, refError)
                                    // Continue to next commit
                                    continue
                                }
                            }

                            if (!stored) {
                                logger.warn(`No valid Nuclei template commit found with YAML file path for ${nucleiCveId}`)
                                result.nucleiAdded = false
                            }
                        } else {
                            logger.info(`AutoSave disabled, skipping storage of Nuclei template reference`)
                            result.nucleiAdded = false
                        }

                    } catch (nucleiError: any) {
                        logger.error(`Failed to fetch/store Nuclei templates for ${nucleiCveId}:`, nucleiError)
                        result.nucleiAdded = false
                    }
                })()
                parallelTasks.push(nucleiTask)
            } else {
                if (!this.options.enableNuclei) {
                    logger.info(`Skipping Nuclei - disabled in options`)
                } else {
                    logger.info(`Skipping Nuclei - no CVE ID available (primaryId: ${primaryId}, cveId: ${cveId})`)
                }
            }

            // Task 11: Google OSI (Open Source Insights) - MOVED TO SEQUENTIAL SECTION
            // Google OSI provides minimal data and requires a base CVEMetadata record from OSV or GitHub
            // Therefore, it must run AFTER OSV/GitHub tasks complete to use their data as a base
            // See sequential Google OSI section below after Promise.all(parallelTasks)

            // Execute all parallel tasks and wait for completion
            if (parallelTasks.length > 0) {
                await Promise.all(parallelTasks)
                logger.info(`✅ Parallel data fetching phase completed (${parallelTasks.length} tasks)`)
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // GOOGLE OSI ENRICHMENT (SEQUENTIAL AFTER OSV/GITHUB)
            // Fetch Google OSI data and merge with OSV or GitHub base record
            // IMPORTANT: Only runs if OSV or GitHub was successful and created a base CVEMetadata
            // Google OSI provides minimal data (title, aliases, CVSS) so it needs a rich base
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            logger.info(`[Google OSI Check] enableGoogleOsi=${this.options.enableGoogleOsi}, primaryId=${primaryId}, osvParsedData=${!!osvParsedData}, githubParsedData=${!!githubParsedData}`)
            if (this.options.enableGoogleOsi) {
                try {
                    // Check if this CVE-source combination recently failed
                    const hasGoogleOsiFailed = await this.hasRecentFailure(primaryId, 'googleosi', logger)
                    if (hasGoogleOsiFailed) {
                        logger.info(`Skipping Google OSI for ${primaryId} - recently failed`)
                    }
                    // SHIELD: Explicitly exclude CVE and EUVD identifiers
                    // Google OSI API does not accept CVE or EUVD prefixes
                    else if (primaryId.startsWith('CVE-') || primaryId.startsWith('EUVD-')) {
                        logger.info(`Skipping Google OSI for ${primaryId} - CVE/EUVD identifiers not supported by API`)
                    }
                    // Only proceed if we have a base record from OSV or GitHub
                    else if (!osvParsedData && !githubParsedData) {
                        logger.info(`Skipping Google OSI for ${primaryId} - no base CVEMetadata from OSV or GitHub available`)
                    }
                    // Proceed with Google OSI enrichment
                    else {
                        // Prefer OSV base over GitHub base (OSV is typically more comprehensive)
                        const baseCVEMetadata = osvParsedData || githubParsedData
                        const baseSource = osvParsedData ? 'OSV' : 'GitHub'
                        logger.info(`✅ Fetching ${primaryId} from Google OSI for enrichment (using ${baseSource} as base)`)

                        const googleOsi = new GoogleOsi()
                        const osiData = await googleOsi.query(this.prisma, this.options.orgId, this.options.memberId, primaryId, this.options.r2adapter)

                        if (osiData) {
                            // Store raw Google OSI JSON to R2 if adapter available
                            if (this.options.r2adapter) {
                                try {
                                    await storeVulnJsonToR2(this.options.r2adapter, primaryId, `google-osi`, osiData, logger)
                                } catch (r2Error: any) {
                                    logger.warn(`Failed to store Google OSI JSON to R2: ${r2Error.message}`)
                                }
                            }

                            // Parse Google OSI data with base CVEMetadata for enrichment
                            // Returns enriched data only if Google OSI provides value (new CVSS, aliases, or references)
                            // Returns null if Google OSI provides no enrichments
                            const enrichedData = parseGoogleOsiToCVE(osiData, primaryId, baseCVEMetadata)

                            if (enrichedData && this.validateParsedData(enrichedData, 'google_osi') && this.options.autoSave) {
                                // Update the existing base record (OSV or GitHub) with Google OSI enrichments
                                // This preserves the original source while adding Google OSI enhancements
                                await storeCVEData(this.prisma, enrichedData, logger)
                                logger.info(`Enriched ${primaryId} ${baseSource} record with Google OSI data`)

                                // Store references if Google OSI added new ones
                                logger.info(`[VulnProcessor] Enriched data has ${enrichedData.references?.length || 0} references`)
                                if (enrichedData.references && enrichedData.references.length > 0) {
                                    await this.storeCVEReferences(
                                        primaryId,
                                        enrichedData.source, // Use the base source (osv or github)
                                        enrichedData.references,
                                        `${baseSource} enriched with Google OSI`,
                                        logger,
                                        false, // Don't check HTTP status on initial storage
                                        this.options.forceRefresh // Pass forceRefresh to delete existing refs
                                    )
                                    logger.info(`Updated references for ${primaryId} with Google OSI enrichments`)
                                }

                                // Log specific enrichments made
                                if (osiData.cvss3Vector && osiData.cvss3Vector.trim() && !baseCVEMetadata.vectorString) {
                                    logger.info(`✅ Google OSI enriched ${primaryId} with CVSS vector: ${osiData.cvss3Vector}`)
                                }
                                if (osiData.aliases && osiData.aliases.length > 0) {
                                    logger.info(`✅ Google OSI added ${osiData.aliases.length} alias(es) to ${primaryId}`)
                                }

                                result.sources.push('google_osi')
                                result.googleOsiAdded = true
                                logger.info(`Successfully enriched ${primaryId} with Google OSI data (base: ${baseSource})`)
                            } else if (enrichedData && !this.validateParsedData(enrichedData, 'google_osi')) {
                                logger.warn(`Google OSI enriched data failed validation for ${primaryId}, skipping storage`)
                            } else if (!enrichedData) {
                                logger.info(`Google OSI provided no enrichments for ${primaryId} - base ${baseSource} record unchanged`)
                            }
                        } else {
                            logger.warn(`Google OSI returned no data for ${primaryId}`)
                        }
                    }
                } catch (googleOsiError) {
                    logger.error(`Failed to fetch/store ${primaryId} from Google OSI:`, googleOsiError)
                    await this.markFailure(primaryId, 'googleosi', logger)
                }
            }

            // Log CVE-specific feature status
            if (!primaryId.startsWith('CVE-')) {
                logger.info(`ℹ️  Non-CVE ID (${primaryId}) - CVE-specific features (EPSS, ESS, CVE.org, KEV, AI) skipped`)
                if (cveId && cveId !== primaryId) {
                    logger.info(`ℹ️  Discovered CVE alias ${cveId} from ${primaryId} - stored separately`)
                }
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // TASK 3.6: ANCHORE ADP ENRICHMENT (SEQUENTIAL AFTER NVD)
            // Fetch Anchore ADP enrichment data and merge with NVD base
            // IMPORTANT: Only runs if NVD was successful and enableAnchoreADP is true
            // Uses nvdBaseData variable passed from NVD task to avoid R2 race condition
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            logger.info(`[Anchore ADP Check] enableAnchoreADP=${this.options.enableAnchoreADP}, nistNvdAdded=${result.nistNvdAdded}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)
            if (this.options.enableAnchoreADP && result.nistNvdAdded && primaryId.startsWith('CVE-')) {
                try {
                    logger.info(`📦 Fetching Anchore ADP enrichment for ${primaryId}`)
                    const anchoreAdp = new AnchoreADP()
                    const adpData = await anchoreAdp.query(this.prisma, this.options.orgId, this.options.memberId, primaryId, logger, this.options.r2adapter)

                    if (adpData) {
                        logger.info(`✅ Successfully fetched Anchore ADP data for ${primaryId}`)

                        // Use NVD base data from variable (passed from NVD task above)
                        if (nvdBaseData) {
                            logger.info(`Using NVD base data from memory for merging with Anchore ADP`)

                            // Check if Anchore ADP record already exists
                            const existingADP = await this.prisma.cVEMetadata.findFirst({
                                where: { cveId: primaryId, source: 'anchore_adp' }
                            })

                            // Process if forceRefresh or no existing ADP record
                            const shouldProcess = this.options.autoSave && (!existingADP || this.options.forceRefresh)

                            if (shouldProcess) {
                                // Parse and merge Anchore ADP with NVD base
                                const parsedADPData = parseAnchoreAdpToCVE(nvdBaseData, adpData, logger)
                                if (parsedADPData && this.validateParsedData(parsedADPData, 'anchore_adp')) {
                                    // Store merged data to CVEMetadata
                                    await storeCVEData(this.prisma, parsedADPData, logger)
                                    logger.info(`${existingADP ? 'Updated' : 'Stored'} ${primaryId} CVE metadata from Anchore ADP`)

                                    // Store merged JSON to R2
                                    if (this.options.r2adapter) {
                                        try {
                                            const mergedData = {
                                                nvd: nvdBaseData,
                                                adp: adpData
                                            }
                                            await storeVulnJsonToR2(this.options.r2adapter, primaryId, `anchore-adp`, mergedData, logger)
                                        } catch (r2Error: any) {
                                            logger.warn(`Failed to store Anchore ADP merged JSON to R2: ${r2Error.message}`)
                                        }
                                    }

                                    // Store references if available
                                    logger.info(`[VulnProcessor] Anchore ADP parsedData has ${parsedADPData.references?.length || 0} references`)
                                    if (parsedADPData.references && parsedADPData.references.length > 0) {
                                        await this.storeCVEReferences(
                                            primaryId,
                                            'anchore_adp',
                                            parsedADPData.references,
                                            'Anchore ADP',
                                            logger,
                                            false, // Don't check HTTP status on initial storage
                                            this.options.forceRefresh // Pass forceRefresh to delete existing refs
                                        )
                                        logger.info(`Stored ${parsedADPData.references.length} reference(s) for ${primaryId} from Anchore ADP`)
                                    }

                                    result.sources.push('anchore_adp')
                                    result.anchoreAdpAdded = true
                                    logger.info(`✅ Successfully enriched ${primaryId} with Anchore ADP data`)
                                } else if (parsedADPData) {
                                    logger.warn(`Parsed Anchore ADP data failed validation for ${primaryId}, skipping storage`)
                                }
                            } else {
                                logger.info(`⏭️  Anchore ADP data already exists for ${primaryId}, skipping (use forceRefresh to update)`)
                                result.anchoreAdpAdded = false
                            }
                        } else {
                            logger.warn(`⚠️  No NVD base data available in memory for ${primaryId}, cannot merge Anchore ADP`)
                        }
                    } else {
                        logger.info(`ℹ️  No Anchore ADP data available for ${primaryId}`)
                        result.anchoreAdpAdded = false
                    }
                } catch (adpError) {
                    logger.error(`Failed to process Anchore ADP for ${primaryId}:`, adpError)
                    result.anchoreAdpAdded = false
                }
            } else if (this.options.enableAnchoreADP && !result.nistNvdAdded) {
                logger.info(`⏭️  Skipping Anchore ADP for ${primaryId} - NVD data required as base`)
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // TASK 3.7: CISA VULNRICHMENT ADP (SEQUENTIAL AFTER CVE.ORG)
            // Extract CISA ADP container from CVE.org data if present
            // IMPORTANT: Only runs if CVE.org was successful and enableCisaVulnrichment is true
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            logger.info(`[CISA Vulnrichment Check] enableCisaVulnrichment=${this.options.enableCisaVulnrichment}, cveOrgAdded=${result.cveOrgAdded}, startsWith CVE-=${primaryId.startsWith('CVE-')}`)
            if (this.options.enableCisaVulnrichment && result.cveOrgAdded && primaryId.startsWith('CVE-')) {
                try {
                    logger.info(`🛡️  Checking for CISA Vulnrichment ADP in CVE.org data for ${primaryId}`)

                    // Use CVE.org data from variable (already fetched in parallel phase)
                    // This avoids R2 race condition where data may not be saved yet
                    const cveOrgData = cveOrgBaseData

                    if (cveOrgData) {
                        logger.info(`Using CVE.org data from parallel fetch for CISA ADP extraction`)
                        // Check if CISA ADP record already exists
                        const existingCisaADP = await this.prisma.cVEMetadata.findFirst({
                            where: { cveId: primaryId, source: 'cisa_adp' }
                        })

                        // Process if forceRefresh or no existing CISA ADP record
                        const shouldProcess = this.options.autoSave && (!existingCisaADP || this.options.forceRefresh)

                        if (shouldProcess) {
                            // Parse CISA ADP container from CVE.org data
                            const parsedCisaADP = parseCisaAdpToCVE(cveOrgData, logger)

                            if (parsedCisaADP && this.validateParsedData(parsedCisaADP, 'cisa_adp')) {
                                // Store CISA ADP data to CVEMetadata
                                await storeCVEData(this.prisma, parsedCisaADP, logger)
                                logger.info(`${existingCisaADP ? 'Updated' : 'Stored'} ${primaryId} CVE metadata from CISA Vulnrichment`)

                                // Store SSVC decisions if available and finding is provided
                                if (finding && parsedCisaADP.ssvcDecisions && parsedCisaADP.ssvcDecisions.length > 0) {
                                    await storeSSVCDecisions(
                                        this.prisma,
                                        finding.uuid,
                                        parsedCisaADP.ssvcDecisions,
                                        null, // No triage UUID at this stage
                                        logger
                                    )
                                    logger.info(`Stored ${parsedCisaADP.ssvcDecisions.length} SSVC decision(s) from CISA Vulnrichment for finding ${finding.uuid}`)
                                }

                                // Store references if available
                                logger.info(`[VulnProcessor] CISA Vulnrichment parsedData has ${parsedCisaADP.references?.length || 0} references`)
                                if (parsedCisaADP.references && parsedCisaADP.references.length > 0) {
                                    await this.storeCVEReferences(
                                        primaryId,
                                        'cisa_adp',
                                        parsedCisaADP.references,
                                        'CISA Vulnrichment',
                                        logger,
                                        false, // Don't check HTTP status on initial storage
                                        this.options.forceRefresh // Pass forceRefresh to delete existing refs
                                    )
                                    logger.info(`Stored ${parsedCisaADP.references.length} reference(s) for ${primaryId} from CISA Vulnrichment`)
                                }

                                result.sources.push('cisa_adp')
                                result.cisaVulnrichmentAdded = true
                                logger.info(`✅ Successfully extracted CISA Vulnrichment ADP data for ${primaryId}`)
                            } else if (parsedCisaADP && !this.validateParsedData(parsedCisaADP, 'cisa_adp')) {
                                logger.warn(`Parsed CISA Vulnrichment data failed validation for ${primaryId}, skipping storage`)
                                result.cisaVulnrichmentAdded = false
                            } else {
                                logger.info(`ℹ️  No CISA ADP container found in CVE.org data for ${primaryId}`)
                                result.cisaVulnrichmentAdded = false
                            }
                        } else {
                            logger.info(`⏭️  CISA Vulnrichment data already exists for ${primaryId}, skipping (use forceRefresh to update)`)
                            result.cisaVulnrichmentAdded = false
                        }
                    } else {
                        logger.warn(`⚠️  No CVE.org data available for ${primaryId}, cannot extract CISA ADP`)
                        result.cisaVulnrichmentAdded = false
                    }
                } catch (cisaAdpError) {
                    logger.error(`Failed to process CISA Vulnrichment for ${primaryId}:`, cisaAdpError)
                    result.cisaVulnrichmentAdded = false
                }
            } else if (this.options.enableCisaVulnrichment && !result.cveOrgAdded) {
                logger.info(`⏭️  Skipping CISA Vulnrichment for ${primaryId} - CVE.org data required as base`)
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // URL CATEGORIZATION PHASE
            // Process references to extract exploits and fixes
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            if (this.options.enableUrlCategorization) {
                try {
                    logger.info(`🔍 Starting URL categorization for ${primaryId}`)

                    // Get all references from CVEMetadata
                    const metadata = await this.prisma.cVEMetadata.findFirst({
                        where: { cveId: primaryId },
                        include: { references: true }
                    })

                    if (metadata && metadata.references && metadata.references.length > 0) {
                        logger.info(`Categorizing ${metadata.references.length} reference URLs`)

                        const referenceUrls = metadata.references.map(r => r.url)
                        const categorizedURLs = categorizeURLs(referenceUrls)

                        const exploitUrls: any[] = []
                        const fixCommitHashes: string[] = []
                        const allFixVersions: string[] = []

                        for (const categorizedURL of categorizedURLs) {
                            const { url, category } = categorizedURL

                            // Extract PoC/Exploit/Sighting URLs
                            if (category.type === 'exploit' || category.type === 'poc' || category.type === 'sighting') {
                                const exploitEntry: any = {
                                    url: url,
                                    type: category.type,
                                    subcategory: category.subcategory,
                                    confidence: category.confidence,
                                    description: category.description,
                                    ...category.extractedData
                                }

                                // Add source-specific metadata
                                if (category.subcategory === 'exploit-db' && category.extractedData?.exploitId) {
                                    exploitEntry.exploitDbId = category.extractedData.exploitId
                                } else if (category.subcategory === 'github' && category.type === 'poc') {
                                    exploitEntry.sourceType = 'github_poc'
                                    if (category.extractedData?.repoOwner && category.extractedData?.repoName) {
                                        exploitEntry.repository = `${category.extractedData.repoOwner}/${category.extractedData.repoName}`
                                    }
                                }

                                exploitUrls.push(exploitEntry)
                            }

                            // Extract commit hashes from fix URLs
                            if (category.type === 'fix' && category.extractedData?.commitHash) {
                                const commitHash = category.extractedData.commitHash
                                fixCommitHashes.push(commitHash)

                                // Add commit hash as a fix version identifier
                                const fixVersionString = `commit:${commitHash}`
                                if (commitHash.length >= 7) { // Valid commit hash
                                    allFixVersions.push(fixVersionString)
                                }
                            }

                            // Extract release tags as fix versions
                            if (category.type === 'fix' && category.extractedData?.releaseTag) {
                                allFixVersions.push(category.extractedData.releaseTag)
                            }
                        }

                        // Store categorized exploit URLs and fix versions
                        if (exploitUrls.length > 0) {
                            result.exploitUrls = exploitUrls
                            logger.info(`Found ${exploitUrls.length} exploit/PoC URLs`)
                            // Note: Exploit data is available via CVEMetadataReferences.type='Exploit' and KEV table
                        }

                        if (allFixVersions.length > 0) {
                            result.fixVersions = allFixVersions
                            logger.info(`Found ${allFixVersions.length} fix versions: ${allFixVersions.join(', ')}`)
                        }

                        // Generate categorization summary
                        const categoryStats = categorizedURLs.reduce((stats, cat) => {
                            stats[cat.category.type] = (stats[cat.category.type] || 0) + 1
                            return stats
                        }, {} as Record<string, number>)

                        const highConfidence = categorizedURLs.filter(cat => cat.category.confidence >= 80).length

                        logger.info(`✅ URL categorization completed: ${JSON.stringify(categoryStats)}, high confidence: ${highConfidence}`)
                        result.urlCategorizationAdded = true
                    } else {
                        logger.info(`No references to categorize for ${primaryId}`)
                    }
                } catch (categorizationError) {
                    logger.error(`Failed to categorize URLs for ${primaryId}:`, categorizationError)
                }
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // PHASE 1.5: RECURSIVE ALIAS ENRICHMENT
            // Discover and enrich all related vulnerability IDs (aliases) before AI inference
            // This ensures complete context for AI analysis across all related identifiers
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // Also runs when forceRefresh is true to ensure alias files are stored
            if (this.options.enableAIInference || finding || this.options.forceRefresh) {
                logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                logger.info(`🔗 PHASE 1.5: ALIAS ENRICHMENT for ${primaryId}`)
                logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)

                // Track all discovered aliases (use Set to avoid duplicates)
                // Normalize all aliases to uppercase for case-insensitive storage
                const allAliases = new Set<string>()
                const processedAliases = new Set<string>()
                const aliasesToProcess = new Set<string>()

                // Add the normalized vulnId as already processed
                processedAliases.add(primaryId)
                if (cveId && cveId !== primaryId) {
                    processedAliases.add(cveId)
                }

                // Collect initial aliases from ALL CVEMetadata records (all sources)
                // This ensures we capture aliases from OSV, GitHub, Google OSI, EUVD, etc.
                const metadataRecords = await this.prisma.cVEMetadata.findMany({
                    where: { cveId: primaryId }
                })

                let totalAliasesFound = 0
                for (const metadata of metadataRecords) {
                    if (metadata.aliases) {
                        const aliases = typeof metadata.aliases === 'string'
                            ? JSON.parse(metadata.aliases)
                            : metadata.aliases

                        if (Array.isArray(aliases)) {
                            aliases.forEach((alias: string) => {
                                // Normalize alias to uppercase
                                const normalizedAlias = alias.toUpperCase()
                                if (!processedAliases.has(normalizedAlias)) {
                                    allAliases.add(normalizedAlias)
                                    aliasesToProcess.add(normalizedAlias)
                                    totalAliasesFound++
                                }
                            })
                        }
                    }
                }

                if (totalAliasesFound > 0) {
                    logger.info(`Found ${totalAliasesFound} initial aliases from ${metadataRecords.length} CVEMetadata source(s)`)
                }

                // Also add the discovered CVE ID if it's different from primaryId
                if (cveId && cveId !== primaryId && !processedAliases.has(cveId)) {
                    allAliases.add(cveId)
                    aliasesToProcess.add(cveId)
                    logger.info(`Added discovered CVE ID ${cveId} to alias processing queue`)
                }

                // Collect aliases from Finding if provided
                if (finding && finding.aliases) {
                    const findingAliases = typeof finding.aliases === 'string'
                        ? JSON.parse(finding.aliases)
                        : finding.aliases

                    if (Array.isArray(findingAliases)) {
                        findingAliases.forEach((alias: string) => {
                            // Normalize alias to uppercase
                            const normalizedAlias = alias.toUpperCase()
                            if (!processedAliases.has(normalizedAlias)) {
                                allAliases.add(normalizedAlias)
                                aliasesToProcess.add(normalizedAlias)
                            }
                        })
                        logger.info(`Found ${findingAliases.length} aliases from Finding`)
                    }
                }

                // Collect related IDs from Finding if provided
                // Related IDs (from OSV) should also be processed and have alias relations established
                if (finding && finding.related) {
                    const findingRelated = typeof finding.related === 'string'
                        ? JSON.parse(finding.related)
                        : finding.related

                    if (Array.isArray(findingRelated)) {
                        findingRelated.forEach((relatedId: string) => {
                            // Normalize related ID to uppercase
                            const normalizedRelated = relatedId.toUpperCase()
                            if (!processedAliases.has(normalizedRelated)) {
                                allAliases.add(normalizedRelated)
                                aliasesToProcess.add(normalizedRelated)
                            }
                        })
                        logger.info(`Found ${findingRelated.length} related IDs from Finding`)
                    }
                }

                // Recursively process all aliases until no new ones are discovered
                let iterationCount = 0
                const maxIterations = 10 // Safety limit to prevent infinite loops

                while (aliasesToProcess.size > 0 && iterationCount < maxIterations) {
                    iterationCount++
                    logger.info(`Alias enrichment iteration ${iterationCount}: processing ${aliasesToProcess.size} aliases`)

                    // Process current batch of aliases in parallel
                    const currentBatch = Array.from(aliasesToProcess)
                    aliasesToProcess.clear()

                    const aliasEnrichmentTasks = currentBatch.map(async (aliasId) => {
                        try {
                            logger.info(`Enriching alias: ${aliasId}`)

                            // Create a new VulnProcessor instance with same options but disable AI inference
                            // Enable APIs based on alias type to ensure comprehensive data collection
                            const aliasProcessor = new VulnProcessor(this.prisma, {
                                ...this.options,
                                enableAIInference: false, // Critical: prevent recursive AI calls
                                // Enable CVE-specific APIs for CVE aliases
                                enableCVEOrg: aliasId.startsWith('CVE-') && this.options.enableCVEOrg,
                                enableEPSS: aliasId.startsWith('CVE-') && this.options.enableEPSS,
                                enableCESS: aliasId.startsWith('CVE-') && this.options.enableCESS,
                                enableEUVD: aliasId.startsWith('CVE-') && this.options.enableEUVD,
                                enableKEV: aliasId.startsWith('CVE-') && this.options.enableKEV,
                                enableNistNvd: aliasId.startsWith('CVE-') && this.options.enableNistNvd,
                                enableAnchoreADP: aliasId.startsWith('CVE-') && this.options.enableAnchoreADP,
                                enableCisaVulnrichment: aliasId.startsWith('CVE-') && this.options.enableCisaVulnrichment,
                                // Enable GHSA-specific APIs for GHSA aliases
                                enableGitHubAdvisory: aliasId.startsWith('GHSA-') && this.options.enableGitHubAdvisory,
                                // Enable Google OSI for GHSA and OSV aliases (supports both)
                                enableGoogleOsi: (aliasId.startsWith('GHSA-') || aliasId.startsWith('OSV-')) && this.options.enableGoogleOsi,
                                // Always enable OSV for all aliases
                                enableOSV: this.options.enableOSV,
                                jwtCredentials: this.options.jwtCredentials
                            })

                            // Process the alias (fetch from all sources)
                            const aliasResult = await aliasProcessor.process(aliasId, logger, null)

                            // Mark as processed
                            processedAliases.add(aliasId)

                            // Check if this alias enrichment discovered new aliases
                            const aliasMetadata = await this.prisma.cVEMetadata.findFirst({
                                where: {
                                    OR: [
                                        { cveId: aliasId },
                                        { cveId: aliasId.startsWith('CVE-') ? aliasId : undefined }
                                    ]
                                }
                            })

                            if (aliasMetadata && aliasMetadata.aliases) {
                                const newAliases = typeof aliasMetadata.aliases === 'string'
                                    ? JSON.parse(aliasMetadata.aliases)
                                    : aliasMetadata.aliases

                                if (Array.isArray(newAliases)) {
                                    newAliases.forEach((newAlias: string) => {
                                        // Normalize new alias to uppercase
                                        const normalizedNewAlias = newAlias.toUpperCase()
                                        if (!processedAliases.has(normalizedNewAlias) && !aliasesToProcess.has(normalizedNewAlias)) {
                                            allAliases.add(normalizedNewAlias)
                                            aliasesToProcess.add(normalizedNewAlias)
                                        }
                                    })
                                }
                            }

                            if (aliasResult.success) {
                                logger.info(`✅ Successfully enriched alias: ${aliasId} (sources: ${aliasResult.sources.join(', ')})`)
                            } else {
                                logger.warn(`⚠️  Failed to enrich alias: ${aliasId} - ${aliasResult.error}`)
                            }
                        } catch (error) {
                            logger.error(`Failed to enrich alias ${aliasId}:`, error)
                            processedAliases.add(aliasId) // Mark as processed to avoid retry loops
                        }
                    })

                    // Wait for all alias enrichment tasks in this batch
                    await Promise.all(aliasEnrichmentTasks)

                    if (aliasesToProcess.size > 0) {
                        logger.info(`Discovered ${aliasesToProcess.size} new aliases in iteration ${iterationCount}`)
                    }
                }

                if (iterationCount >= maxIterations) {
                    logger.warn(`⚠️  Alias enrichment stopped at maximum iteration limit (${maxIterations})`)
                }

                logger.info(`✅ Alias enrichment completed: processed ${processedAliases.size} total IDs (${allAliases.size} aliases discovered)`)
                logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)

                // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                // PHASE 1.6: ESTABLISH CVEALIAS RELATIONS
                // Now that all aliases have been processed and stored, create junction table entries
                // This ensures all CVEMetadata records exist before creating foreign key relations
                // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                if (allAliases.size > 0) {
                    logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                    logger.info(`🔗 PHASE 1.6: ESTABLISHING CVEALIAS RELATIONS`)
                    logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)

                    // Get the primary CVE source (prefer cve.org for CVE IDs, osv/github for others)
                    const primarySource = primaryId.startsWith('CVE-') ? 'cve.org' : (primaryId.startsWith('GHSA-') ? 'github' : 'osv')

                    // Establish alias relations from primary to all discovered aliases
                    await establishCVEAliasRelations(
                        this.prisma,
                        primaryId,
                        primarySource,
                        Array.from(allAliases),
                        primarySource,
                        logger
                    )

                    logger.info(`✅ Established CVEAlias relations for ${allAliases.size} aliases`)
                    logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                }
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // CROWDSEC HONEYPOT SIGHTINGS
            // Fetch CrowdSec sighting data for CVEs
            // This runs after all data fetching and alias enrichment to ensure we have a CVE ID
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

            logger.info(`[CrowdSec Check] enableCrowdSec=${this.options.enableCrowdSec}, primaryId=${primaryId}`)
            if (this.options.enableCrowdSec) {
                // Extract CVE ID - use primary ID if it's a CVE, otherwise look in aliases
                let cveIdForCrowdSec: string | null = null

                if (primaryId.startsWith('CVE-')) {
                    cveIdForCrowdSec = primaryId
                } else {
                    // Look for CVE in aliases
                    try {
                        const aliases = await this.prisma.cVEAlias.findMany({
                            where: {
                                OR: [
                                    { primaryCveId: primaryId },
                                    { aliasCveId: primaryId }
                                ]
                            }
                        })

                        for (const alias of aliases) {
                            if (alias.primaryCveId.startsWith('CVE-')) {
                                cveIdForCrowdSec = alias.primaryCveId
                                break
                            }
                            if (alias.aliasCveId.startsWith('CVE-')) {
                                cveIdForCrowdSec = alias.aliasCveId
                                break
                            }
                        }
                    } catch (aliasError) {
                        logger.warn(`Failed to fetch aliases for CrowdSec check:`, aliasError)
                    }
                }

                if (cveIdForCrowdSec && this.options.env?.CROWDSEC_APIKEY) {
                    logger.info(`Processing CrowdSec sightings for ${cveIdForCrowdSec}`)

                    try {
                        // Check if we should skip this CVE (unless forceRefresh is enabled)
                        if (!this.options.forceRefresh) {
                            const existingLog = await this.prisma.crowdSecLog.findFirst({
                                where: { cveId: cveIdForCrowdSec },
                                orderBy: { createdAt: 'desc' }
                            })

                            if (existingLog) {
                                const hoursSinceLastCheck = (Date.now() / 1000 - existingLog.createdAt) / 3600
                                if (hoursSinceLastCheck < 24) {
                                    logger.info(`Skipping CrowdSec for ${cveIdForCrowdSec} - checked ${hoursSinceLastCheck.toFixed(1)} hours ago`)

                                    // Check if we have sightings
                                    const existingSightings = await this.prisma.crowdSecSighting.findFirst({
                                        where: { cveId: cveIdForCrowdSec }
                                    })

                                    if (existingSightings) {
                                        result.crowdSecAdded = true
                                    }

                                    // Skip API call
                                    logger.info(`✅ Using cached CrowdSec data for ${cveIdForCrowdSec}`)
                                } else {
                                    logger.info(`Refreshing CrowdSec data for ${cveIdForCrowdSec} (last checked ${hoursSinceLastCheck.toFixed(1)} hours ago)`)
                                }
                            }
                        }

                        // Only fetch if we don't have recent data or forceRefresh is enabled
                        if (this.options.forceRefresh || !result.crowdSecAdded) {
                            const { v4: uuidv4 } = await import('uuid')
                            const logUuid = uuidv4()
                            const now = Math.floor(Date.now() / 1000)

                            // Fetch from CrowdSec API
                            const { url, httpStatus, data } = await this.fetchCrowdSecData(
                                cveIdForCrowdSec,
                                this.options.env.CROWDSEC_APIKEY
                            )

                            let totalItems = 0
                            let errorMessage: string | null = null
                            let r2Path: string | null = null

                            if (httpStatus === 200 && typeof data === 'object') {
                                // Success - store JSON to R2 if adapter is available
                                const responseData = data as { items?: any[] }
                                totalItems = responseData.items?.length || 0

                                if (this.options.r2adapter) {
                                    const date = new Date()
                                    const dateString = date.toISOString().split('T')[0].replace(/-/g, '')
                                    r2Path = `/crowdsec/${dateString}/${logUuid}.jsonc`

                                    const curlComment = `// curl -v -H 'accept: application/json' -H "x-api-key: \${CROWDSEC_APIKEY}" '${url}' | jq .\n`
                                    const jsonContent = curlComment + JSON.stringify(data, null, 2)

                                    await this.options.r2adapter.put(r2Path, jsonContent, {
                                        httpMetadata: {
                                            contentType: 'application/json'
                                        }
                                    })
                                }
                            } else {
                                // Error
                                errorMessage = typeof data === 'string' ? data : JSON.stringify(data)
                                totalItems = 0
                            }

                            // Create log record
                            await this.prisma.crowdSecLog.create({
                                data: {
                                    uuid: logUuid,
                                    r2Path: r2Path || '',
                                    url,
                                    cveId: cveIdForCrowdSec,
                                    httpStatus,
                                    errorMessage,
                                    totalItems,
                                    createdAt: now
                                }
                            })

                            // Process sightings if successful
                            if (httpStatus === 200 && typeof data === 'object') {
                                const sightingsCreated = await this.processCrowdSecResponse(logUuid, data, logger)

                                logger.info(`✅ CrowdSec fetch completed for ${cveIdForCrowdSec}`)
                                logger.info(`   - Total Items: ${totalItems}`)
                                logger.info(`   - Sightings Created: ${sightingsCreated}`)
                                result.crowdSecAdded = true
                            } else {
                                logger.warn(`CrowdSec fetch returned non-200 status for ${cveIdForCrowdSec}: ${httpStatus}`)
                            }
                        }
                    } catch (crowdSecError: any) {
                        logger.warn(`Failed to fetch CrowdSec data for ${cveIdForCrowdSec}:`, crowdSecError.message)
                    }
                } else {
                    if (!cveIdForCrowdSec) {
                        logger.info(`No CVE ID found for CrowdSec check (primaryId: ${primaryId})`)
                    } else if (!this.options.env?.CROWDSEC_APIKEY) {
                        logger.warn(`CROWDSEC_APIKEY not configured, skipping CrowdSec enrichment`)
                    }
                }
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // PHASE 2: GITHUB ENRICHMENT & SCORECARD
            // Extract GitHub repository information and fetch OpenSSF Scorecard data
            // Links scorecard to CVEMetadata for security posture tracking
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            if (this.options.jwtCredentials && this.options.autoSave) {
                try {
                    logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                    logger.info(`🔍 PHASE 3: GitHub Enrichment & Scorecard`)
                    logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)

                    // Fetch ALL CVE metadata records (multiple sources) with references and affected data
                    // Batch all related data in single query to reduce database round trips
                    const allCveMetadata = await this.prisma.cVEMetadata.findMany({
                        where: { cveId: primaryId },
                        include: {
                            references: true,
                            affected: true,
                            metrics: true,
                            problemTypes: true,
                            descriptions: true,
                            adp: true,
                            impacts: true
                        }
                    })

                    if (allCveMetadata && allCveMetadata.length > 0) {
                        const { extractAndEnrichGitHubRepos } = await import('@shared/github-enrichment-helpers')
                        const { OpenSSFScorecardService } = await import('@shared/openssf-scorecard-service')

                        // Debug: Log credentials being passed
                        logger.info(`🔑 GitHub JWT Credentials:`)
                        logger.info(`   - appId: ${this.options.jwtCredentials?.appId || 'MISSING'}`)
                        logger.info(`   - clientId: ${this.options.jwtCredentials?.clientId ? 'SET' : 'MISSING'}`)
                        logger.info(`   - clientSecret: ${this.options.jwtCredentials?.clientSecret ? 'SET' : 'MISSING'}`)
                        logger.info(`   - privateKey: ${this.options.jwtCredentials?.privateKey ? 'SET (length: ' + this.options.jwtCredentials.privateKey.length + ')' : 'MISSING'}`)

                        // Combine references and affected data from all sources
                        const allReferences: any[] = []
                        const allAffected: any[] = []

                        for (const metadata of allCveMetadata) {
                            if (metadata.references) {
                                allReferences.push(...metadata.references)
                            }
                            if (metadata.affected) {
                                allAffected.push(...metadata.affected)
                            }
                        }

                        // Debug: Log what data we have
                        logger.info(`📋 Found ${allCveMetadata.length} CVE metadata source(s):`)
                        logger.info(`   - Total References: ${allReferences.length}`)
                        logger.info(`   - Total Affected: ${allAffected.length}`)
                        if (allAffected.length > 0) {
                            const repos = allAffected.map(a => a.repo).filter(Boolean)
                            logger.info(`   - Affected repos: ${repos.length > 0 ? repos.join(', ') : 'none'}`)
                        }

                        // Extract and enrich GitHub repositories (pass metadata for affectedVersionsJSON parsing)
                        const repoIds = await extractAndEnrichGitHubRepos(
                            this.prisma,
                            this.options.jwtCredentials,
                            allReferences,
                            allAffected,
                            allCveMetadata,
                            primaryId,
                            logger
                        )

                        if (repoIds.size > 0) {
                            logger.info(`✅ Enriched ${repoIds.size} GitHub repository/ies from CVE data`)
                            result.githubEnrichmentAdded = true

                            // Fetch scorecard for each repository
                            const scorecardService = new OpenSSFScorecardService({ prisma: this.prisma, logger })

                            for (const [fullName, repoId] of repoIds) {
                                try {
                                    logger.info(`📊 Fetching scorecard for ${fullName}...`)

                                    const scorecardUuid = await scorecardService.fetchAndStoreScorecard(
                                        repoId,
                                        fullName
                                    )

                                    if (scorecardUuid) {
                                        // Link scorecard to all CVEMetadata records for this CVE
                                        const linked = await scorecardService.linkScorecardToAllCVESources(
                                            primaryId,
                                            scorecardUuid
                                        )

                                        logger.info(`✅ Linked scorecard to ${linked} CVEMetadata record(s) for ${primaryId}`)
                                        result.scorecardAdded = true
                                        result.scorecardUuid = scorecardUuid
                                    } else {
                                        logger.info(`ℹ️  No scorecard data available for ${fullName}`)
                                    }
                                } catch (scorecardError) {
                                    logger.warn(`Failed to fetch/link scorecard for ${fullName}:`, scorecardError)
                                    // Continue processing other repos
                                }
                            }

                            logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                        } else {
                            logger.info(`ℹ️  No GitHub repositories found in CVE data`)
                            logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                        }
                    } else {
                        logger.info(`❌ No CVE metadata found for GitHub enrichment: ${primaryId}`)
                        logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                    }
                } catch (enrichmentError) {
                    logger.error(`Failed to perform GitHub enrichment for ${primaryId}:`, enrichmentError)
                    // Don't fail the entire process - this is optional enrichment
                }
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // Phase 3: SSVC RE-EVALUATION WITH ALL COLLECTED REFERENCES
            // After all references are collected from all sources (CVE.org, OSV, CESS, KEV, etc.),
            // re-evaluate SSVC decisions to apply Vulnetix overrides based on complete exploit data
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            if (finding && primaryId.startsWith('CVE-')) {
                try {
                    logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                    logger.info(`🔄 RE-EVALUATING SSVC WITH ALL REFERENCES for ${primaryId}`)
                    logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)

                    const reevalResult = await reevaluateSSVCWithReferences(
                        this.prisma,
                        primaryId,
                        finding.uuid,
                        logger
                    )

                    if (reevalResult.overrideApplied) {
                        logger.info(`✅ Vulnetix SSVC override applied: ${reevalResult.originalExploitation} → ${reevalResult.newExploitation}`)
                        logger.info(`   Sources: ${reevalResult.sources?.join(', ')}`)
                    } else {
                        logger.debug(`No SSVC override needed for ${primaryId}`)
                    }

                    logger.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`)
                } catch (ssvcError) {
                    logger.error(`Failed to re-evaluate SSVC for ${primaryId}:`, ssvcError)
                    // Don't fail the entire process - SSVC re-evaluation is optional
                }
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // PHASE 4: RESERVED CVE CVSS 4.0 ENHANCEMENT
            // For RESERVED CVEs with exploits, add a default CVSS 4.0 vector string
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            if (this.options.autoSave && primaryId.startsWith('CVE-')) {
                try {
                    // Check if this is a RESERVED CVE from CVE.org
                    const cveOrgMetadata = await this.prisma.cVEMetadata.findFirst({
                        where: {
                            cveId: primaryId,
                            source: 'cve.org',
                            state: 'RESERVED'
                        }
                    })

                    if (cveOrgMetadata) {
                        logger.debug(`Checking RESERVED CVE ${primaryId} for exploit-based CVSS enhancement`)

                        // Check if CVSS 4.0 metric already exists
                        const existingCvss4 = await this.prisma.cVEMetric.findFirst({
                            where: {
                                cveId: primaryId,
                                source: 'cve.org',
                                metricType: 'cvssV4_0'
                            }
                        })

                        if (!existingCvss4) {
                            // Check for exploits
                            const exploits = await this.prisma.cVEMetadataReferences.findMany({
                                where: {
                                    cveId: primaryId,
                                    type: {
                                        in: ['exploit', 'poc']
                                    }
                                }
                            })

                            if (exploits.length > 0) {
                                // Determine exploit maturity
                                const hasPoc = exploits.some(e => e.type === 'poc')
                                const exploitMaturity = hasPoc ? 'P' : 'A' // P = Proof-of-Concept, A = Attacked
                                const vectorString = `CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:${exploitMaturity}`

                                // Create CVSS 4.0 metric
                                await this.prisma.cVEMetric.create({
                                    data: {
                                        cveId: primaryId,
                                        source: 'cve.org',
                                        containerType: 'cna',
                                        metricType: 'cvssV4_0',
                                        vectorString: vectorString,
                                        createdAt: Math.floor(Date.now() / 1000)
                                    }
                                })

                                logger.info(`✅ Added CVSS 4.0 vector (E:${exploitMaturity}) to RESERVED CVE ${primaryId} based on ${exploits.length} exploit(s)`)
                            } else {
                                logger.debug(`No exploits found for RESERVED CVE ${primaryId}, skipping CVSS enhancement`)
                            }
                        } else {
                            logger.debug(`CVSS 4.0 metric already exists for ${primaryId}, skipping enhancement`)
                        }
                    }
                } catch (reservedCvssError) {
                    logger.error(`Failed to enhance RESERVED CVE ${primaryId} with CVSS 4.0:`, reservedCvssError)
                    // Don't fail the entire process - this is an optional enhancement
                }
            }

            // Determine overall success
            result.success = result.sources.length > 0 || result.epssAdded || result.cessAdded || result.aiInferenceAdded

            if (!result.success) {
                result.error = `No data found for ${primaryId} from any enabled source`
                logger.warn(result.error)
            } else {
                logger.info(`Successfully processed ${primaryId}: ${result.sources.join(', ')}`)
            }

            return result
        } catch (error) {
            logger.error(`Vulnerability processing failed for ${primaryId}:`, error)
            result.error = error instanceof Error ? error.message : 'Unknown error'
            return result
        }
    }

    /**
     * Check if a vulnerability exists in the database
     * Normalizes vulnId to uppercase for case-insensitive lookup
     */
    async exists(vulnId: string): Promise<boolean> {
        const normalizedVulnId = vulnId.trim().toUpperCase()
        const cve = await this.prisma.cVEMetadata.findFirst({
            where: { cveId: normalizedVulnId }
        })
        return !!cve
    }

    /**
     * Get configuration
     */
    getOptions(): Required<VulnProcessorOptions> {
        return { ...this.options }
    }

    /**
     * Update configuration
     */
    setOptions(options: Partial<VulnProcessorOptions>): void {
        this.options = {
            ...this.options,
            ...options
        }
    }
}

/**
 * Helper function to create a VulnProcessor instance
 */
export function createVulnProcessor(
    prisma: PrismaClient,
    options?: VulnProcessorOptions
): VulnProcessor {
    return new VulnProcessor(prisma, options)
}
