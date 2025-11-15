import { categorizeURL } from '@/services/utilities/url-categorizer';
import { mergeCVEMetadata, normalizeSourceName } from '@/services/vdb/cveMetadataMerger';
import { deduplicateCVESources } from '@/services/vdb/cveSourceMerger';
import { generateGcveId, lookupGcveId, storeGcveCveListV5 } from '@/services/vdb/gcveIdGenerator';
import { Logger } from '@/shared/storage-utils';
import { CVSS30, CVSS31, CVSS40 } from '@pandatix/js-cvss';
import type { PrismaClient } from '@prisma/client';
import { DepsDevClient } from '@shared/deps-dev-client';
import { latestTriage } from '@shared/finding';
import { fetchExploitDBData, fetchGitHubGistData, fetchVulnerabilityLabData, storeCVEMetadataReference } from '@shared/reference-processor';
import { CESS, EPSS } from '@shared/utils';

export interface BuildCVEDependencies {
    prisma?: PrismaClient
    jwtCredentials?: { clientId: string; clientSecret: string; privateKey: string; appId: string };
    octokit?: any; // Octokit instance for GitHub API calls
    logger?: Logger;
    r2artifacts?: R2Bucket;
    env?: any; // Cloudflare Workers environment bindings (for API URLs, keys, etc.)
}

export interface BuildCVEDataContext {
    orgId?: string
    memberId?: string
}

export interface BuildCVEDataOptions {
    collectAliases?: boolean
    includeAI?: boolean
    includeFileLinks?: boolean
}

export interface PatchIntelligence {
    hasPatch: boolean
    commits?: Array<{
        hash: string
        source: string
        url?: string
    }>
    versionFixes?: Array<{
        ecosystem: string
        packageName: string
        version: string
        versionType: 'commit' | 'semver' | 'range' | 'unknown'
        statement: string
        source: string
        repo?: string
    }>
    remediationAdvice?: string
    cweRemediations?: string[]
    pixAnalysis?: string
    affectedFunctions?: string[]
    sources: string[]
}

const identifierPatterns = [
    'rhsaId', 'ghsaId', 'cveId', 'osvId', 'pysecId', 'rustsecId',
    'goId', 'npmId', 'mavenId', 'nugetId', 'rubygemsId', 'composerId',
    'debianId', 'ubuntuId', 'redhatId', 'susaId', 'alasId', 'snykId',
    'awsId', 'pypiId', 'golangId'
]

// Helper to extract CVSS version from vector string
const getCvssVersion = (vectorString: string | null): string | null => {
    if (!vectorString) return null
    const match = vectorString.match(/CVSS:(\d+\.\d+)/)
    return match ? match[1] : null
}

// Helper to calculate CVSS score from vector string
const calculateCvssScore = (vectorString: string | null): number | null => {
    if (!vectorString) return null

    try {
        const version = getCvssVersion(vectorString)

        if (version === '4.0') {
            const cvss = new CVSS40(vectorString)
            const score = cvss.Score()
            return Number(score.toFixed(1))
        } else if (version === '3.1') {
            const cvss = new CVSS31(vectorString)
            const score = cvss.BaseScore()
            return Number(score.toFixed(1))
        } else if (version === '3.0') {
            const cvss = new CVSS30(vectorString)
            const score = cvss.BaseScore()
            return Number(score.toFixed(1))
        }
    } catch (e) {
        // Failed to calculate score, return null
    }

    return null
}

// Helper to check if EPSS data is stale
const isEpssStale = (epssHistory: any[]): boolean => {
    if (!epssHistory || epssHistory.length === 0) return true
    const now = new Date()
    const latestDate = new Date(epssHistory[0].dateString)
    const daysSinceLatest = Math.floor((now.getTime() - latestDate.getTime()) / (24 * 60 * 60 * 1000))
    return daysSinceLatest > 2 || epssHistory.length < 20
}

// Helper to check if CESS data is stale
const isCessStale = (cessHistory: any[]): boolean => {
    if (!cessHistory || cessHistory.length === 0) return true
    const now = new Date()
    const latestDate = new Date(cessHistory[0].dateString)
    const daysSinceLatest = Math.floor((now.getTime() - latestDate.getTime()) / (24 * 60 * 60 * 1000))
    return daysSinceLatest > 7 // CESS updates less frequently than EPSS
}

/**
 * Recursively collect all aliases for a given identifier
 * Searches CVEMetadata, CVEAlias relations, and Finding records
 */
const collectAllAliases = async (
    prisma: PrismaClient,
    identifier: string,
    logger: any,
    visitedIdentifiers: Set<string> = new Set()
): Promise<Set<string>> => {
    const normalizedId = identifier.trim().toUpperCase()

    // Prevent infinite loops
    if (visitedIdentifiers.has(normalizedId)) {
        return new Set()
    }
    visitedIdentifiers.add(normalizedId)

    const allAliases = new Set<string>()

    // 1. Check CVEAlias table for direct relationships
    try {
        const aliasRelations = await prisma.cVEAlias.findMany({
            where: {
                OR: [
                    { primaryCveId: normalizedId },
                    { aliasCveId: normalizedId }
                ]
            }
        })

        for (const relation of aliasRelations) {
            if (relation.primaryCveId !== normalizedId) {
                allAliases.add(relation.primaryCveId.toUpperCase())
            }
            if (relation.aliasCveId !== normalizedId) {
                allAliases.add(relation.aliasCveId.toUpperCase())
            }
        }
    } catch (e) {
        logger?.warn(`Failed to query CVEAlias for ${normalizedId}:`, e)
    }

    // 2. Check Finding records where identifier is detectionTitle
    try {
        const findingsByTitle = await prisma.finding.findMany({
            where: { detectionTitle: normalizedId },
            select: { aliases: true, detectionTitle: true }
        })

        for (const finding of findingsByTitle) {
            if (finding.aliases) {
                try {
                    const parsed = JSON.parse(finding.aliases)
                    if (Array.isArray(parsed)) {
                        parsed.forEach((alias: string) => {
                            const normalized = alias.toUpperCase()
                            if (normalized !== normalizedId) {
                                allAliases.add(normalized)
                            }
                        })
                    }
                } catch (e) {
                    // Ignore parse errors
                }
            }
        }
    } catch (e) {
        logger?.warn(`Failed to query Finding by detectionTitle for ${normalizedId}:`, e)
    }

    // 3. Check Finding records where identifier is in aliases
    try {
        const findingsByAlias = await prisma.finding.findMany({
            where: {
                aliases: {
                    contains: normalizedId
                }
            },
            select: { aliases: true, detectionTitle: true }
        })

        for (const finding of findingsByAlias) {
            // Add detectionTitle as an alias
            if (finding.detectionTitle !== normalizedId) {
                allAliases.add(finding.detectionTitle.toUpperCase())
            }

            // Add other aliases
            if (finding.aliases) {
                try {
                    const parsed = JSON.parse(finding.aliases)
                    if (Array.isArray(parsed)) {
                        parsed.forEach((alias: string) => {
                            const normalized = alias.toUpperCase()
                            if (normalized !== normalizedId) {
                                allAliases.add(normalized)
                            }
                        })
                    }
                } catch (e) {
                    // Ignore parse errors
                }
            }
        }
    } catch (e) {
        logger?.warn(`Failed to query Finding by aliases for ${normalizedId}:`, e)
    }

    // 4. Check CVEMetadata rawDataJSON for aliases
    try {
        const metadata = await prisma.cVEMetadata.findMany({
            where: { cveId: normalizedId },
            select: { rawDataJSON: true }
        })

        for (const meta of metadata) {
            if (meta.rawDataJSON) {
                try {
                    const rawData = JSON.parse(meta.rawDataJSON)
                    const aliases = Array.isArray(rawData?.aliases) ? rawData.aliases : []
                    const computedAliases = Array.isArray(rawData?.computedAliases) ? rawData.computedAliases : []

                    aliases.concat(computedAliases).forEach((alias: string) => {
                        const normalized = alias.toUpperCase()
                        if (normalized !== normalizedId) {
                            allAliases.add(normalized)
                        }
                    })
                } catch (e) {
                    // Ignore parse errors
                }
            }
        }
    } catch (e) {
        logger?.warn(`Failed to query CVEMetadata for aliases of ${normalizedId}:`, e)
    }

    // 5. Recursively collect aliases for newly discovered identifiers
    const newAliases = new Set<string>()
    for (const alias of allAliases) {
        if (!visitedIdentifiers.has(alias)) {
            const recursiveAliases = await collectAllAliases(prisma, alias, logger, visitedIdentifiers)
            recursiveAliases.forEach(a => newAliases.add(a))
        }
    }

    // Merge recursive results
    newAliases.forEach(a => allAliases.add(a))

    return allAliases
}

/**
 * Source preference order (from cveMetadataMerger.ts)
 */
const SOURCE_PREFERENCE = ['Anchore', 'Anchore ADP', 'Anchore-ADP', 'anchore_adp', 'CISA', 'CISA ADP', 'CISA-ADP', 'cisa_adp', 'CISA Vulnrichment', 'Vulnrichment', 'NVD', 'NIST-NVD', 'nist_nvd', 'OSV', 'OSV.dev', 'osv-org', 'GHSA', 'GitHub', 'github.com', 'Mitre', 'Mitre.org', 'mitre-org', 'CVE.org', 'cve-org', 'EUVD']

/**
 * Get preference score for a source (higher is better)
 */
const getSourcePreference = (source: string): number => {
    const index = SOURCE_PREFERENCE.findIndex(s => source.toLowerCase().includes(s.toLowerCase()))
    return index >= 0 ? SOURCE_PREFERENCE.length - index : 0
}

/**
 * Helper to convert a value to Unix timestamp (seconds)
 * Handles both date strings and existing timestamps (in seconds or milliseconds)
 */
const toUnixTimestamp = (value: string | number | null | undefined): number | null => {
    if (!value) return null

    // If it's already a number, check if it's in milliseconds or seconds
    if (typeof value === 'number') {
        // Timestamps in milliseconds are > 10^12 (1,000,000,000,000)
        // This corresponds to September 9, 2001 in seconds, or September 9, 33658 in milliseconds
        // Any real-world timestamp > 10^12 must be in milliseconds
        if (value > 1000000000000) {
            // It's in milliseconds, convert to seconds
            return Math.floor(value / 1000)
        }
        // Already in seconds
        return value
    }

    // If it's a string, parse it as a date
    if (typeof value === 'string') {
        const timestamp = new Date(value).getTime()
        // Check if it's a valid date
        if (isNaN(timestamp)) return null
        // Convert milliseconds to seconds
        return Math.floor(timestamp / 1000)
    }

    return null
}

/**
 * On-demand enrichment for references that are missing enrichment data
 * This function checks references and enriches them with data from external sources
 * Saves enrichment to database so it's available for future requests
 */
const enrichReferencesOnDemand = async (
    references: any[],
    dependencies: BuildCVEDependencies,
    logger: any
): Promise<void> => {
    if (!dependencies.prisma) return

    for (const ref of references) {
        const refUrl = ref.url?.toLowerCase() || ''
        let enriched = false

        try {
            // ExploitDB enrichment
            if ((refUrl.includes('exploit-db.com') || ref.subcategory === 'exploit-db') && !ref.exploitDbDate) {
                const exploitIdMatch = ref.url?.match(/\/exploits\/(\d+)/i) || ref.url?.match(/\/raw\/(\d+)/i)
                const exploitId = exploitIdMatch?.[1] || ref.exploitDbId

                if (exploitId && ref.uuid) {
                    logger?.info(`[OnDemand] Enriching ExploitDB reference #${exploitId}`)

                    const enrichment = await fetchExploitDBData(exploitId)
                    if (enrichment) {
                        await dependencies.prisma.cVEMetadataReferences.update({
                            where: { uuid: ref.uuid },
                            data: {
                                exploitDbId: enrichment.exploitId || null,
                                exploitDbAuthor: enrichment.author || null,
                                exploitDbDate: enrichment.date || null,
                                exploitDbPlatform: enrichment.platform || null,
                                exploitDbType: enrichment.type || null,
                                exploitDbPort: enrichment.port || null,
                                exploitDbVerified: enrichment.verified ? 1 : 0
                            }
                        })

                        // Update local object for immediate use
                        ref.exploitDbId = enrichment.exploitId
                        ref.exploitDbAuthor = enrichment.author
                        ref.exploitDbDate = enrichment.date
                        ref.exploitDbPlatform = enrichment.platform
                        ref.exploitDbType = enrichment.type
                        ref.exploitDbPort = enrichment.port
                        ref.exploitDbVerified = enrichment.verified

                        enriched = true
                        logger?.info(`[OnDemand] Successfully enriched ExploitDB #${exploitId}`)
                    }
                }
            }

            // GitHub Gist enrichment
            if ((refUrl.includes('gist.github.com') || ref.subcategory === 'gist') && !ref.gistUpdatedAt && dependencies.octokit) {
                const gistIdMatch = ref.url?.match(/gist\.github\.com\/[^/]+\/([a-f0-9]+)/i)
                const gistId = gistIdMatch?.[1] || ref.gistId

                if (gistId && ref.uuid) {
                    logger?.info(`[OnDemand] Enriching GitHub Gist ${gistId}`)

                    const enrichment = await fetchGitHubGistData(dependencies.octokit, gistId)
                    if (enrichment) {
                        await dependencies.prisma.cVEMetadataReferences.update({
                            where: { uuid: ref.uuid },
                            data: {
                                gistId: enrichment.gist_id || null,
                                commitAuthorLogin: enrichment.owner_login || null, // Reusing commitAuthorLogin for Gist owner
                                gistPublic: enrichment.public ? 1 : 0,
                                gistFilesCount: enrichment.files_count || null,
                                gistFiles: enrichment.files ? JSON.stringify(enrichment.files) : null,
                                gistComments: enrichment.comments_count || null,
                                gistUpdatedAt: enrichment.updatedAt || null
                            }
                        })

                        // Update local object for immediate use
                        ref.gistId = enrichment.gist_id
                        ref.commitAuthorLogin = enrichment.owner_login // Reusing commitAuthorLogin for Gist owner
                        ref.gistPublic = enrichment.public ? 1 : 0
                        ref.gistFilesCount = enrichment.files_count
                        ref.gistFiles = enrichment.files ? JSON.stringify(enrichment.files) : null
                        ref.gistComments = enrichment.comments_count
                        ref.gistUpdatedAt = enrichment.updatedAt

                        enriched = true
                        logger?.info(`[OnDemand] Successfully enriched Gist ${gistId}`)
                    }
                }
            }

            // VulnerabilityLab enrichment
            if ((refUrl.includes('vulnerability-lab.com') || ref.subcategory === 'vulnerability-lab') && !ref.vlCreatedAt) {
                const vlIdMatch = ref.url?.match(/[?&]id=(\d+)/i)
                const vlId = vlIdMatch?.[1] || ref.vlId

                if (vlId && ref.uuid) {
                    logger?.info(`[OnDemand] Enriching VulnerabilityLab reference #${vlId}`)

                    const enrichment = await fetchVulnerabilityLabData(vlId)
                    if (enrichment) {
                        await dependencies.prisma.cVEMetadataReferences.update({
                            where: { uuid: ref.uuid },
                            data: {
                                vlId: enrichment.vlId || null,
                                vlTitle: enrichment.title || null,
                                vlCreatedAt: enrichment.createdAt || null,
                                vlUpdatedAt: enrichment.updatedAt || null,
                                vlExploitationTechnique: enrichment.exploitationTechnique || null,
                                vlAuthenticationType: enrichment.authenticationType || null,
                                vlUserInteraction: enrichment.userInteraction || null,
                                vlAuthor: enrichment.author || null
                            }
                        })

                        // Update local object for immediate use
                        ref.vlId = enrichment.vlId
                        ref.vlTitle = enrichment.title
                        ref.vlCreatedAt = enrichment.createdAt
                        ref.vlUpdatedAt = enrichment.updatedAt
                        ref.vlExploitationTechnique = enrichment.exploitationTechnique
                        ref.vlAuthenticationType = enrichment.authenticationType
                        ref.vlUserInteraction = enrichment.userInteraction
                        ref.vlAuthor = enrichment.author

                        enriched = true
                        logger?.info(`[OnDemand] Successfully enriched VulnerabilityLab #${vlId}`)
                    }
                }
            }
        } catch (error) {
            logger?.warn(`[OnDemand] Failed to enrich reference ${ref.url}: ${error}`)
            // Continue with other references
        }
    }
}

/**
 * Build timeline events from all sources, aliases, EPSS/CESS history, KEV data, scorecard history, references, and exploit data
 */
const buildVulnerabilityTimeline = async (
    cveId: string,
    sources: any[],
    aliasData: any[],
    epssHistory: any[] | null,
    cessHistory: any[] | null,
    kevData: any | null,
    scorecardHistory: any[] | null,
    references: any[],
    vulnCheckKevData: any[],
    crowdSecSightings: any[],
    dependencies: BuildCVEDependencies,
    logger: any
): Promise<any[]> => {
    const events: any[] = []
    const seenTimestamps = new Set<number>()
    const seenIdentifiers = new Set<string>([cveId.toUpperCase()])
    const seenCommitHashes = new Set<string>()

    // Add events from primary sources
    sources.forEach((source, index) => {
        // Reserved date
        if (source.dateReserved && !seenTimestamps.has(source.dateReserved)) {
            events.push({
                time: source.dateReserved,
                value: `Reserved`,
                description: `${cveId} reserved by ${normalizeSourceName(source.source)}`,
                icon: 'mdi-bookmark-outline',
                color: 'secondary',
                type: 'source',
                source: source.source
            })
            seenTimestamps.add(source.dateReserved)
        }

        // Published date
        if (source.datePublished) {
            const publishKey = source.datePublished + index
            if (!seenTimestamps.has(publishKey)) {
                events.push({
                    time: source.datePublished,
                    value: `Published`,
                    description: `${cveId} published by ${normalizeSourceName(source.source)}`,
                    icon: 'mdi-publish',
                    color: 'primary',
                    cvssScore: source.score || null,
                    cvssVector: source.vectorString || null,
                    type: 'source',
                    source: source.source
                })
                seenTimestamps.add(publishKey)
            }
        }

        // Updated date
        if (source.dateUpdated) {
            const updateKey = source.dateUpdated + index + 1000
            if (!seenTimestamps.has(updateKey)) {
                events.push({
                    time: source.dateUpdated,
                    value: `Updated`,
                    description: `${cveId} updated by ${normalizeSourceName(source.source)}`,
                    icon: 'mdi-update',
                    color: 'secondary',
                    cvssScore: source.score || null,
                    cvssVector: source.vectorString || null,
                    type: 'source',
                    source: source.source
                })
                seenTimestamps.add(updateKey)
            }
        }
    })

    // Add events from aliases
    aliasData.forEach((alias, index) => {
        const aliasId = alias.id || alias.cveId
        if (!aliasId || seenIdentifiers.has(aliasId.toUpperCase())) {
            return
        }
        seenIdentifiers.add(aliasId.toUpperCase())

        // Reserved date for alias
        if (alias.dateReserved && !seenTimestamps.has(alias.dateReserved)) {
            events.push({
                time: alias.dateReserved,
                value: `Reserved`,
                description: `${aliasId} reserved by ${normalizeSourceName(alias.source)}`,
                icon: 'mdi-bookmark-outline',
                color: 'secondary',
                type: 'source',
                source: alias.source
            })
            seenTimestamps.add(alias.dateReserved)
        }

        // Published date for alias
        if (alias.datePublished) {
            const publishKey = alias.datePublished + index + 10000
            if (!seenTimestamps.has(publishKey)) {
                events.push({
                    time: alias.datePublished,
                    value: 'Published',
                    description: `${aliasId} published by ${normalizeSourceName(alias.source)}`,
                    icon: 'mdi-publish',
                    color: 'primary',
                    cvssScore: alias.score || null,
                    cvssVector: alias.vectorString || null,
                    type: 'source',
                    source: alias.source
                })
                seenTimestamps.add(publishKey)
            }
        }

        // Updated date for alias
        if (alias.dateUpdated) {
            const updateKey = alias.dateUpdated + index + 20000
            if (!seenTimestamps.has(updateKey)) {
                events.push({
                    time: alias.dateUpdated,
                    value: 'Updated',
                    description: `${aliasId} updated by ${normalizeSourceName(alias.source)}`,
                    icon: 'mdi-update',
                    color: 'info',
                    cvssScore: alias.score || null,
                    cvssVector: alias.vectorString || null,
                    type: 'source',
                    source: alias.source
                })
                seenTimestamps.add(updateKey)
            }
        }
    })

    // Add EPSS score change events
    if (epssHistory && epssHistory.length > 1) {
        let previousScore = epssHistory[0].score

        epssHistory.slice(1).forEach(entry => {
            const scoreDiff = Math.abs(entry.score - previousScore)
            if (scoreDiff > 0.01) { // 1% threshold
                const dateStr = entry.dateString || entry.date
                const timestamp = toUnixTimestamp(dateStr)
                if (timestamp) {
                    events.push({
                        time: timestamp,
                        value: 'EPSS Updated',
                        description: `from ${(previousScore * 100).toFixed(2)}% to ${(entry.score * 100).toFixed(2)}%`,
                        icon: 'mdi-trending-up',
                        color: 'warning',
                        type: 'score-change',
                        source: 'EPSS'
                    })
                }
            }
            previousScore = entry.score
        })
    }

    // Add CESS score change events
    if (cessHistory && cessHistory.length > 1) {
        let previousScore = cessHistory[0].score

        cessHistory.slice(1).forEach(entry => {
            const scoreDiff = Math.abs(entry.score - previousScore)
            if (scoreDiff > 0.1) { // 0.1 point threshold
                // Prefer timelineDate (already Unix timestamp) over dateString (needs conversion)
                const dateValue = entry.timelineDate || entry.dateString || entry.date
                const timestamp = toUnixTimestamp(dateValue)
                if (timestamp) {
                    events.push({
                        time: timestamp,
                        value: 'Coalition ESS Updated',
                        description: `from ${previousScore.toFixed(1)} to ${entry.score.toFixed(1)}`,
                        icon: 'mdi-chart-line',
                        color: 'warning',
                        type: 'score-change',
                        source: 'ESS'
                    })
                }
            }
            previousScore = entry.score
        })
    }

    // Add OpenSSF Scorecard score change events
    if (scorecardHistory && scorecardHistory.length > 1) {
        let previousScore = scorecardHistory[0].score
        let previousFailingCount = scorecardHistory[0].failingCount

        scorecardHistory.slice(1).forEach(entry => {
            const scoreDiff = Math.abs(entry.score - previousScore)
            const failingCountDiff = entry.failingCount - previousFailingCount

            // Track significant score changes (0.1 point threshold on 0-10 scale)
            if (scoreDiff >= 0.1) {
                const timestamp = toUnixTimestamp(entry.date)
                if (timestamp) {
                    const scorePercentPrev = ((previousScore / 10) * 100).toFixed(0)
                    const scorePercentCurrent = ((entry.score / 10) * 100).toFixed(0)
                    const direction = entry.score > previousScore ? 'improved' : 'decreased'
                    const icon = entry.score > previousScore ? 'mdi-trending-up' : 'mdi-trending-down'
                    const color = entry.score > previousScore ? 'success' : 'warning'

                    events.push({
                        time: timestamp,
                        value: 'OpenSSF Scorecard Updated',
                        description: `${direction} changed from ${scorePercentPrev}% to ${scorePercentCurrent}%`,
                        icon,
                        color,
                        type: 'score-change',
                        source: 'OpenSSF Scorecard'
                    })
                }
            }

            // Track significant changes in failing checks (1+ check difference)
            if (Math.abs(failingCountDiff) >= 1) {
                const timestamp = toUnixTimestamp(entry.date)
                if (timestamp) {
                    const direction = failingCountDiff < 0 ? 'improved' : 'worsened'
                    const change = Math.abs(failingCountDiff)
                    const icon = failingCountDiff < 0 ? 'mdi-check-circle' : 'mdi-alert-circle'
                    const color = failingCountDiff < 0 ? 'success' : 'warning'

                    events.push({
                        time: timestamp,
                        value: 'OpenSSF Security Scorecard Updated',
                        description: `Repository ${direction}: ${change} ${failingCountDiff < 0 ? 'fewer' : 'more'} failing security checks (${previousFailingCount} → ${entry.failingCount})`,
                        icon,
                        color,
                        type: 'score-change',
                        source: 'OpenSSF Scorecard'
                    })
                }
            }

            previousScore = entry.score
            previousFailingCount = entry.failingCount
        })
    }

    // Process references for patch-related events (commits, PRs, advisories, fixes)
    if (references && references.length > 0) {
        logger?.info(`Processing ${references.length} references for timeline events`)

        for (let index = 0; index < references.length; index++) {
            const ref = references[index]
            const refUrl = ref.url || ''
            const refCategory = ref.category || ''
            const refSource = ref.source || 'VVD'

            // IMPORTANT: Explicitly EXCLUDE exploit/poc references from PATCH processing
            // Exploit repositories (e.g., nuclei-templates) are NOT patches!
            // They will be processed later in the exploit section
            const isExploitOrPoc = refCategory && (refCategory.toLowerCase() === 'exploit' || refCategory.toLowerCase() === 'poc')

            // Extract commit hash from URL (supports GitHub, GitLab, SQLite, etc.)
            const commitMatch = refUrl.match(/\/commit\/([a-f0-9]{7,40})/i) ||
                refUrl.match(/\/info\/([a-f0-9]{7,40})/i) || // SQLite format
                refUrl.match(/\/changeset\/([a-f0-9]{7,40})/i) // Other VCS
            const prMatch = refUrl.match(/\/pull\/(\d+)/i)

            // Track fix commits (excluding exploit/poc references)
            if (!isExploitOrPoc && commitMatch && (refCategory === 'fix' || ref.tags?.includes('Patch') || ref.tags?.includes('FIX'))) {
                const commitHash = commitMatch[1]

                logger?.debug(`Found fix commit: ${commitHash} from ${refUrl}, has enrichment: prMergedAt=${!!ref.prMergedAt}, createdAt=${!!ref.createdAt}, commitHealth=${!!ref.commitHealth}`)

                // Skip if we've already seen this commit
                if (seenCommitHashes.has(commitHash)) {
                    return
                }
                seenCommitHashes.add(commitHash)

                // Try to determine commit date from enriched data
                // Enhanced timestamp priority: prMergedAt → commitHealth → createdAt
                let commitTimestamp: number | null = null

                // Check for prMergedAt (PR merged timestamp) - most accurate for PRs
                if (ref.prMergedAt) {
                    commitTimestamp = toUnixTimestamp(ref.prMergedAt)
                }

                // Check for commitHealth.createdAt (direct commit timestamp)
                if (!commitTimestamp && ref.commitHealth) {
                    try {
                        const healthData = typeof ref.commitHealth === 'string'
                            ? JSON.parse(ref.commitHealth)
                            : ref.commitHealth
                        if (healthData.createdAt) {
                            commitTimestamp = toUnixTimestamp(healthData.createdAt)
                        }
                    } catch (e) {
                        // Ignore JSON parse errors
                    }
                }

                // Check for createdAt (when reference was discovered) - fallback
                if (!commitTimestamp && ref.createdAt) {
                    commitTimestamp = toUnixTimestamp(ref.createdAt)
                }

                if (commitTimestamp) {
                    const eventKey = commitTimestamp + index + 30000
                    if (!seenTimestamps.has(eventKey)) {
                        events.push({
                            time: commitTimestamp,
                            value: 'Patch Released',
                            description: `Fix commit ${commitHash.substring(0, 7)} from ${refSource}`,
                            icon: 'mdi-source-commit',
                            color: 'success',
                            type: 'patch',
                            source: refSource,
                            // Rich commit data
                            commitHash: commitHash,
                            commitShort: commitHash.substring(0, 7),
                            commitUrl: refUrl,
                            commitAuthor: ref.commitAuthorLogin || ref.commitAuthorEmail,
                            commitVerified: ref.commitVerified,
                            commitStats: ref.commitHealth ? {
                                additions: ref.commitHealth.additions,
                                deletions: ref.commitHealth.deletions,
                                filesChanged: ref.commitHealth.files_changed
                            } : null
                        })
                        seenTimestamps.add(eventKey)
                    }
                }
            }

            // Track merged PRs that are fixes (excluding exploit/poc references)
            if (!isExploitOrPoc && prMatch && ref.prMergedAt && (refCategory === 'fix' || ref.tags?.includes('Patch') || ref.tags?.includes('FIX'))) {
                const prNumber = prMatch[1]
                const prTimestamp = toUnixTimestamp(ref.prMergedAt)
                if (!prTimestamp) return

                const eventKey = prTimestamp + index + 40000

                if (!seenTimestamps.has(eventKey)) {
                    events.push({
                        time: prTimestamp,
                        value: 'PR Merged',
                        description: `Pull request #${prNumber} merged by ${ref.prAuthor || 'unknown'}`,
                        icon: 'mdi-source-merge',
                        color: 'success',
                        type: 'patch',
                        source: refSource,
                        // Rich PR data
                        prNumber: prNumber,
                        prUrl: refUrl,
                        prAuthor: ref.prAuthor,
                        prState: ref.prState,
                        prMergeCommitSha: ref.prMergeCommitSha,
                        prStats: ref.prRepoHealth ? {
                            commits: ref.prRepoHealth.commits,
                            additions: ref.prRepoHealth.additions,
                            deletions: ref.prRepoHealth.deletions,
                            filesChanged: ref.prRepoHealth.changed_files
                        } : null
                    })
                    seenTimestamps.add(eventKey)
                }
            }

            // Track advisory publications (if distinct from source publication date)
            if (refCategory === 'advisory') {
                // Enhanced timestamp priority: vlUpdatedAt → vlCreatedAt → createdAt
                const dateToUse = ref.vlUpdatedAt || ref.vlCreatedAt || ref.createdAt
                if (!dateToUse) return

                const advisoryTimestamp = toUnixTimestamp(dateToUse)
                if (!advisoryTimestamp) return

                const eventKey = advisoryTimestamp + index + 50000

                // Check if this is different from existing source publication dates
                const isDuplicate = events.some(e =>
                    e.type === 'source' &&
                    e.value.includes('Published') &&
                    Math.abs(e.time - advisoryTimestamp) < 86400 // Within 24 hours
                )

                if (!isDuplicate && !seenTimestamps.has(eventKey)) {
                    events.push({
                        time: advisoryTimestamp,
                        value: 'Advisory Published',
                        description: ref.title || `Security advisory from ${refSource}`,
                        icon: 'mdi-file-document-alert',
                        color: 'warning',
                        type: 'advisory',
                        source: refSource,
                        advisoryUrl: refUrl,
                        advisoryTitle: ref.title,
                        // VulnerabilityLab enrichment (if VL date was used)
                        vlId: ref.vlId || undefined,
                        vlTitle: ref.vlTitle || undefined,
                        vlAuthor: ref.vlAuthor || undefined
                    })
                    seenTimestamps.add(eventKey)
                }
            }

            // Track exploit publications and weaponization evidence
            // This includes: exploit databases, PoCs, weaponization (Metasploit/Nuclei),
            // honeypot sightings, and arbitrary Exploit tags
            if ((refCategory === 'exploit' || refCategory === 'poc' || ref.tags?.includes('Exploit') || ref.type?.toLowerCase() === 'exploit' || ref.type?.toLowerCase() === 'sighting') && ref.createdAt) {
                // Enhanced timestamp priority: exploitDbDate → vlCreatedAt → gistUpdatedAt → createdAt
                const dateToUse = ref.exploitDbDate || ref.vlCreatedAt || ref.gistUpdatedAt || ref.createdAt
                const exploitTimestamp = toUnixTimestamp(dateToUse)
                if (!exploitTimestamp) return

                const eventKey = exploitTimestamp + index + 70000

                if (!seenTimestamps.has(eventKey)) {
                    // Helper function to check if string is a UUID (ADP organization ID)
                    const isUUID = (str: string): boolean => {
                        if (!str) return false
                        const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
                        return uuidPattern.test(str.trim())
                    }

                    // Determine exploit type, severity, and source details with comprehensive detection
                    let exploitType = 'Exploit'
                    // Filter out UUID titles (ADP organization IDs)
                    let exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Exploit evidence detected`
                    let exploitIcon = 'mdi-bug-outline'
                    let exploitColor = 'error'

                    // URL-based detection patterns for various sources
                    const urlLower = refUrl.toLowerCase()

                    // 1. Exploit Databases
                    if (urlLower.includes('exploit-db.com') || ref.subcategory === 'exploit-db') {
                        exploitType = 'Exploit-DB'
                        // Build rich description from ExploitDB enrichment data
                        const exploitParts: string[] = []

                        if (ref.exploitDbId || ref.extractedData?.exploitId) {
                            const edbId = ref.exploitDbId || ref.extractedData?.exploitId
                            exploitParts.push(`Exploit #${edbId}`)
                        }

                        // Only add title if it's not a UUID (ADP organization ID)
                        if (ref.title && !isUUID(ref.title)) {
                            exploitParts.push(`- ${ref.title}`)
                        }

                        if (ref.exploitDbAuthor) {
                            exploitParts.push(`by ${ref.exploitDbAuthor}`)
                        }

                        if (ref.exploitDbPlatform) {
                            exploitParts.push(`[${ref.exploitDbPlatform}]`)
                        }

                        if (ref.exploitDbType) {
                            exploitParts.push(`(${ref.exploitDbType})`)
                        }

                        if (ref.exploitDbVerified) {
                            exploitParts.push('✓')
                        }

                        exploitDescription = exploitParts.length > 0
                            ? exploitParts.join(' ')
                            : 'Exploit published on Exploit-DB'
                    }
                    // 2. PacketStorm Security
                    else if (urlLower.includes('packetstormsecurity.com') || ref.subcategory === 'packetstorm') {
                        exploitType = 'PacketStorm'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Exploit published on PacketStorm Security`
                    }
                    // 3. Metasploit Framework (weaponization)
                    else if (urlLower.includes('metasploit-framework') || urlLower.includes('rapid7/metasploit')) {
                        exploitType = 'Metasploit Module'
                        exploitIcon = 'mdi-shield-bug'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Metasploit module weaponized`
                        // Extract module path if available
                        const moduleMatch = refUrl.match(/modules\/([^?#]+)/)
                        if (moduleMatch) {
                            exploitDescription = `Metasploit module: ${moduleMatch[1]}`
                        }
                    }
                    // 4. Nuclei Templates (weaponization for scanning)
                    else if (urlLower.includes('nuclei-templates') || urlLower.includes('projectdiscovery/nuclei')) {
                        exploitType = 'Nuclei Template'
                        exploitIcon = 'mdi-shield-bug'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Nuclei scanning template published`
                    }
                    // 5. GitHub PoC repositories
                    else if ((urlLower.includes('github.com') || ref.subcategory === 'github') &&
                        (refCategory === 'poc' || ref.tags?.includes('PoC') || urlLower.includes('poc'))) {
                        exploitType = 'GitHub PoC'
                        if (ref.extractedData?.repoOwner && ref.extractedData?.repoName) {
                            exploitDescription = `PoC repository ${ref.extractedData.repoOwner}/${ref.extractedData.repoName} published`
                        } else {
                            exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Proof of Concept published on GitHub`
                        }
                    }
                    // 6. Honeypot Detections - CrowdSec
                    else if (urlLower.includes('crowdsec') || urlLower.includes('crowdsecurity')) {
                        exploitType = 'Honeypot Detection'
                        exploitIcon = 'mdi-target'
                        exploitColor = 'warning'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Active exploitation detected by CrowdSec honeypot`
                    }
                    // 7. Honeypot Detections - Shadowserver Foundation
                    else if (urlLower.includes('shadowserver')) {
                        exploitType = 'Honeypot Detection'
                        exploitIcon = 'mdi-target'
                        exploitColor = 'warning'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Active exploitation detected by Shadowserver Foundation`
                    }
                    // 8. SANS Internet Storm Center
                    else if (urlLower.includes('isc.sans.edu') || urlLower.includes('sans.org')) {
                        exploitType = 'SANS Storm Center'
                        exploitIcon = 'mdi-weather-lightning'
                        exploitColor = 'warning'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Active exploitation reported by SANS Storm Center`
                    }
                    // 9. Shodan (internet-wide exploitation scanning)
                    else if (urlLower.includes('shodan.io')) {
                        exploitType = 'Shodan Detection'
                        exploitIcon = 'mdi-radar'
                        exploitColor = 'warning'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Vulnerable systems detected on Shodan`
                    }
                    // 10. GreyNoise (internet scanning/exploitation)
                    else if (urlLower.includes('greynoise.io')) {
                        exploitType = 'GreyNoise Detection'
                        exploitIcon = 'mdi-radar'
                        exploitColor = 'warning'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Active scanning detected by GreyNoise`
                    }
                    // 11. AttackerKB (exploitation evidence)
                    else if (urlLower.includes('attackerkb.com')) {
                        exploitType = 'AttackerKB'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Exploitation assessment on AttackerKB`
                    }
                    // 12. Vulners (exploit aggregator)
                    else if (urlLower.includes('vulners.com')) {
                        exploitType = 'Vulners'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Exploit published on Vulners`
                    }
                    // 13. 0day.today
                    else if (urlLower.includes('0day.today')) {
                        exploitType = '0day.today'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Exploit published on 0day.today`
                    }
                    // 14. Seebug
                    else if (urlLower.includes('seebug.org')) {
                        exploitType = 'Seebug'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Exploit published on Seebug`
                    }
                    // 15. Generic PoC (when explicitly tagged)
                    else if (refCategory === 'poc') {
                        exploitType = 'PoC'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Proof of Concept published`
                    }
                    // 16. Generic Exploit tag (catch-all for arbitrary tags)
                    else if (ref.tags?.includes('Exploit')) {
                        exploitType = 'Exploit'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Exploit evidence (tagged)`
                    }
                    // 17. Type-based detection (ref.type === 'exploit')
                    else if (ref.type?.toLowerCase() === 'exploit') {
                        exploitType = 'Exploit'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Exploit published`
                    }
                    // 18. Sighting evidence (CrowdSec, honeypots, etc.)
                    else if (ref.type?.toLowerCase() === 'sighting') {
                        exploitType = 'Sighting'
                        exploitDescription = (ref.title && !isUUID(ref.title)) ? ref.title : `Active exploitation sighting`
                        exploitIcon = 'mdi-radar'
                        exploitColor = 'error'
                    }

                    events.push({
                        time: exploitTimestamp,
                        value: `${exploitType} Published`,
                        description: exploitDescription,
                        icon: exploitIcon,
                        color: exploitColor,
                        type: 'exploit',
                        source: refSource,
                        exploitUrl: refUrl,
                        exploitTitle: ref.title,
                        exploitType: exploitType,
                        exploitId: ref.exploitDbId || ref.extractedData?.exploitId,
                        exploitDbAuthor: ref.exploitDbAuthor,
                        exploitDbPlatform: ref.exploitDbPlatform,
                        exploitDbType: ref.exploitDbType,
                        exploitDbPort: ref.exploitDbPort,
                        exploitDbVerified: ref.exploitDbVerified,
                        repository: ref.extractedData?.repoOwner && ref.extractedData?.repoName
                            ? `${ref.extractedData.repoOwner}/${ref.extractedData.repoName}`
                            : undefined,
                        // VulnerabilityLab enrichment (if VL date was used)
                        vlId: ref.vlId || undefined,
                        vlExploitationTechnique: ref.vlExploitationTechnique || undefined,
                        vlAuthenticationType: ref.vlAuthenticationType || undefined,
                        vlUserInteraction: ref.vlUserInteraction || undefined,
                        vlAuthor: ref.vlAuthor || undefined,
                        // GitHub Gist enrichment (if Gist date was used)
                        gistId: ref.gistId || undefined,
                        gistFilesCount: ref.gistFilesCount || undefined,
                        gistPublic: ref.gistPublic !== null && ref.gistPublic !== undefined ? (ref.gistPublic === 1) : undefined
                    })
                    seenTimestamps.add(eventKey)
                }
            }
        }
    }

    // Process CVE 5.1 affected versions from rawDataJSON for patch release events
    sources.forEach((source, sourceIndex) => {
        if (!source.rawDataJSON) return

        try {
            const rawData = JSON.parse(source.rawDataJSON)
            const affected = rawData?.containers?.cna?.affected || []

            for (const affectedItem of affected) {
                const product = affectedItem.product || 'Unknown'
                const vendor = affectedItem.vendor || source.affectedVendor || 'Unknown'
                const repo = affectedItem.repo || null
                const versions = affectedItem.versions || []

                // Process versions with changes array (contains unaffected status transitions)
                for (const versionInfo of versions) {
                    if (versionInfo.changes && Array.isArray(versionInfo.changes)) {
                        for (const change of versionInfo.changes) {
                            if (change.status === 'unaffected' && change.at) {
                                // This is a fixed version, but we don't have a timestamp
                                // We could use source.dateUpdated as an approximation
                                const patchTimestamp = source.dateUpdated || source.datePublished
                                if (patchTimestamp) {
                                    const eventKey = patchTimestamp + sourceIndex + 60000
                                    if (!seenTimestamps.has(eventKey)) {
                                        events.push({
                                            time: patchTimestamp,
                                            value: 'Version Fix Released',
                                            description: `${vendor} ${product} version ${change.at} is unaffected`,
                                            icon: 'mdi-package-variant-closed-check',
                                            color: 'success',
                                            type: 'patch',
                                            source: source.source,
                                            fixedVersion: change.at,
                                            product: product,
                                            vendor: vendor,
                                            repo: repo
                                        })
                                        seenTimestamps.add(eventKey)
                                    }
                                }
                            }
                        }
                    }

                    // Process lessThan (indicates upper bound for affected versions)
                    if (versionInfo.lessThan && versionInfo.status === 'affected') {
                        const patchTimestamp = source.dateUpdated || source.datePublished
                        if (patchTimestamp) {
                            const eventKey = patchTimestamp + sourceIndex + 61000
                            if (!seenTimestamps.has(eventKey)) {
                                events.push({
                                    time: patchTimestamp,
                                    value: 'Version Fix Released',
                                    description: `Fixed in ${vendor} ${product} version ${versionInfo.lessThan}`,
                                    icon: 'mdi-package-variant-closed-check',
                                    color: 'success',
                                    type: 'patch',
                                    source: source.source,
                                    fixedVersion: versionInfo.lessThan,
                                    product: product,
                                    vendor: vendor,
                                    repo: repo
                                })
                                seenTimestamps.add(eventKey)
                            }
                        }
                    }
                }
            }
        } catch (e) {
            logger?.warn(`Failed to parse CVE 5.1 affected versions for timeline from ${source.source}:`, e)
        }
    })

    // Add KEV event
    if (kevData?.dateAdded) {
        const kevTimestamp = kevData.dateAdded
        if (!seenTimestamps.has(kevTimestamp)) {
            events.push({
                time: kevTimestamp,
                value: 'Added to CISA KEV Catalog',
                description: kevData?.requiredAction,
                icon: 'mdi-shield-alert',
                color: 'error',
                type: 'source',
                source: 'CISA KEV'
            })
            seenTimestamps.add(kevTimestamp)
        }
    }

    if (kevData?.dueDate) {
        const kevTimestamp = kevData.dueDate
        if (!seenTimestamps.has(kevTimestamp)) {
            events.push({
                time: kevTimestamp,
                value: 'Due Date for CISA KEV Catalog',
                description: kevData?.requiredAction,
                icon: 'mdi-shield-alert',
                color: 'error',
                type: 'source',
                source: 'CISA KEV'
            })
            seenTimestamps.add(kevTimestamp)
        }
    }

    // Add VulnCheck KEV events with XDB exploits and reported exploitations
    if (vulnCheckKevData && vulnCheckKevData.length > 0) {
        vulnCheckKevData.forEach((vulnCheckKev, kevIndex) => {
            // Add VulnCheck KEV added event
            if (vulnCheckKev.dateAdded) {
                const eventKey = vulnCheckKev.dateAdded + kevIndex + 100000
                if (!seenTimestamps.has(eventKey)) {
                    events.push({
                        time: vulnCheckKev.dateAdded,
                        value: 'Added to VulnCheck KEV',
                        description: vulnCheckKev.shortDescription || 'Known exploited vulnerability',
                        icon: 'mdi-shield-alert',
                        color: 'error',
                        type: 'source',
                        source: 'VulnCheck KEV',
                        reportedExploitedByCanaries: vulnCheckKev.reportedExploitedByVulnCheckCanaries
                    })
                    seenTimestamps.add(eventKey)
                }
            }

            // Add VulnCheck XDB exploit events
            if (vulnCheckKev.xdbExploits && vulnCheckKev.xdbExploits.length > 0) {
                vulnCheckKev.xdbExploits.forEach((xdb: any, xdbIndex: number) => {
                    const eventKey = xdb.dateAdded + kevIndex + xdbIndex + 110000
                    if (!seenTimestamps.has(eventKey)) {
                        events.push({
                            time: xdb.dateAdded,
                            value: 'VulnCheck XDB Exploit Published',
                            description: xdb.exploitType ? `${xdb.exploitType} exploit` : 'Exploit published in VulnCheck XDB',
                            icon: 'mdi-bug-outline',
                            color: 'error',
                            type: 'exploit',
                            source: 'VulnCheck XDB',
                            exploitUrl: xdb.xdbUrl,
                            xdbId: xdb.xdbId,
                            exploitType: xdb.exploitType,
                            cloneSshUrl: xdb.cloneSshUrl
                        })
                        seenTimestamps.add(eventKey)
                    }
                })
            }

            // Add VulnCheck Reported Exploitation events
            if (vulnCheckKev.reportedExploitations && vulnCheckKev.reportedExploitations.length > 0) {
                vulnCheckKev.reportedExploitations.forEach((exp: any, expIndex: number) => {
                    const eventKey = exp.dateAdded + kevIndex + expIndex + 120000
                    if (!seenTimestamps.has(eventKey)) {
                        events.push({
                            time: exp.dateAdded,
                            value: 'Exploitation Reported',
                            description: 'Active exploitation reported by VulnCheck threat intelligence',
                            icon: 'mdi-alert-octagon',
                            color: 'error',
                            type: 'exploit',
                            source: 'VulnCheck',
                            reportUrl: exp.url
                        })
                        seenTimestamps.add(eventKey)
                    }
                })
            }
        })
    }

    // Add CrowdSec sighting events (honeypot detections)
    if (crowdSecSightings && crowdSecSightings.length > 0) {
        crowdSecSightings.forEach((sighting: any, sightingIndex: number) => {
            // Use firstSeen timestamp for timeline event
            if (sighting.firstSeen) {
                const eventKey = sighting.firstSeen + sightingIndex + 130000
                if (!seenTimestamps.has(eventKey)) {
                    // Build description from sighting details
                    const descParts: string[] = []

                    if (sighting.ip) {
                        descParts.push(`IP: ${sighting.ip}`)
                    }

                    if (sighting.reputation) {
                        descParts.push(`Reputation: ${sighting.reputation}`)
                    }

                    if (sighting.locationCountry) {
                        descParts.push(`Location: ${sighting.locationCountry}`)
                    }

                    if (sighting.behaviorsCsv) {
                        const behaviors = sighting.behaviorsCsv.split(',').slice(0, 2)
                        descParts.push(`Behaviors: ${behaviors.join(', ')}`)
                    }

                    events.push({
                        time: sighting.firstSeen,
                        value: 'CrowdSec Detection',
                        description: descParts.length > 0
                            ? descParts.join(' | ')
                            : 'Active exploitation detected by CrowdSec honeypot',
                        icon: 'mdi-radar',
                        color: 'error',
                        type: 'exploit',
                        source: 'CrowdSec',
                        sightingDetails: {
                            ip: sighting.ip,
                            reputation: sighting.reputation,
                            confidence: sighting.confidence,
                            locationCountry: sighting.locationCountry,
                            locationCity: sighting.locationCity,
                            asName: sighting.asName,
                            behaviors: sighting.behaviorsCsv,
                            attackDetails: sighting.attackDetailsCsv,
                            firstSeen: sighting.firstSeen,
                            lastSeen: sighting.lastSeen
                        }
                    })
                    seenTimestamps.add(eventKey)
                }
            }
        })
    }

    // Add latest OpenSSF Scorecard event (if history exists)
    if (scorecardHistory && scorecardHistory.length > 0) {
        const latestScorecard = scorecardHistory[scorecardHistory.length - 1]
        const scorecardTimestamp = toUnixTimestamp(latestScorecard.date)

        if (scorecardTimestamp && !seenTimestamps.has(scorecardTimestamp)) {
            const scorePercent = ((latestScorecard.score / 10) * 100).toFixed(0)
            events.push({
                time: scorecardTimestamp,
                value: 'OpenSSF Security Scorecard',
                description: `${scorePercent}% (${latestScorecard.failingCount} failing checks)`,
                icon: 'mdi-shield-check',
                color: latestScorecard.score >= 7 ? 'success' : latestScorecard.score >= 5 ? 'warning' : 'error',
                type: 'scorecard',
                source: 'OpenSSF Scorecard',
                scorecardScore: latestScorecard.score,
                scorecardFailingCount: latestScorecard.failingCount
            })
            seenTimestamps.add(scorecardTimestamp)
        }
    }

    // Sort events by time
    const sortedEvents = events.sort((a, b) => a.time - b.time)

    // Calculate patch age (days since first patch event)
    const firstPatchEvent = sortedEvents.find(e => e.type === 'patch')
    if (firstPatchEvent) {
        const now = Math.floor(Date.now() / 1000)
        const patchAge = Math.floor((now - firstPatchEvent.time) / 86400) // Days

        // Add patch age to all patch events
        sortedEvents.forEach(event => {
            if (event.type === 'patch') {
                event.patchAge = patchAge
                event.firstPatchTime = firstPatchEvent.time
            }
        })
    }

    return sortedEvents
}

/**
 * Extract affected packages from CVE sources for registry-based version discovery
 *
 * Parses CVE 5.1 format data to extract affected packages with their ecosystems and version ranges.
 * Filters out exploit/poc repositories.
 *
 * @param sources - Array of CVE source data
 * @param aliasData - Array of alias data for ecosystem detection
 * @param logger - Logger instance
 * @returns Array of affected package information with ranges
 */
interface AffectedPackageInfo {
    ecosystem: string
    packageName: string
    vendor?: string
    repo?: string
    affectedRange?: string
}

const extractAffectedPackagesFromSources = (
    sources: any[],
    aliasData: any[],
    logger: any
): AffectedPackageInfo[] => {
    const affectedPackages: AffectedPackageInfo[] = []
    const seen = new Set<string>() // Deduplication key: ecosystem:packageName

    // Helper to extract ecosystem from affected item
    const extractEcosystem = (affectedItem: any, vendor: string, product: string): string => {
        // 1. Check for explicit ecosystem in version data
        if (affectedItem.versions && Array.isArray(affectedItem.versions) && affectedItem.versions.length > 0) {
            const firstVersion = affectedItem.versions[0]
            if (firstVersion.versionType) {
                const vt = firstVersion.versionType.toLowerCase()
                if (vt.includes('npm') || vt === 'node') return 'npm'
                if (vt.includes('pypi') || vt.includes('python') || vt === 'pip') return 'pypi'
                if (vt.includes('maven') || vt === 'java') return 'maven'
                if (vt.includes('gem') || vt.includes('ruby')) return 'rubygems'
                if (vt.includes('nuget') || vt === 'dotnet') return 'nuget'
                if (vt.includes('cargo') || vt === 'rust') return 'cargo'
                if (vt.includes('go') || vt === 'golang') return 'go'
            }
        }

        // 2. Check for package ecosystem field
        if (affectedItem.packageEcosystem) {
            return affectedItem.packageEcosystem.toLowerCase()
        }

        // 3. Heuristic: Common vendor to ecosystem mappings
        const vendorLower = vendor.toLowerCase()
        if (vendorLower === 'npm' || product.toLowerCase().includes('node')) return 'npm'
        if (vendorLower === 'pypi' || vendorLower === 'python') return 'pypi'
        if (vendorLower === 'maven' || vendorLower === 'apache') return 'maven'
        if (vendorLower === 'rubygems' || vendorLower === 'ruby') return 'rubygems'
        if (vendorLower === 'cargo' || vendorLower === 'rust') return 'cargo'

        // 4. Fallback to generic
        return 'generic'
    }

    // Helper to build affected range from version info
    const buildAffectedRange = (versions: any[]): string | undefined => {
        const ranges: string[] = []

        for (const versionInfo of versions) {
            // Only process affected versions
            if (versionInfo.status !== 'affected') continue

            // Case 1: lessThan indicates: all versions < this are affected
            if (versionInfo.lessThan) {
                ranges.push(`< ${versionInfo.lessThan}`)
            }

            // Case 2: lessThanOrEqual indicates: all versions <= this are affected
            if (versionInfo.lessThanOrEqual) {
                ranges.push(`<= ${versionInfo.lessThanOrEqual}`)
            }

            // Case 3: Specific version is affected
            if (versionInfo.version && !versionInfo.lessThan && !versionInfo.lessThanOrEqual) {
                ranges.push(`= ${versionInfo.version}`)
            }
        }

        // If no ranges found, return undefined
        if (ranges.length === 0) return undefined

        // Join multiple ranges with OR logic (simplified for now)
        return ranges.join(' || ')
    }

    // Process each source
    for (const source of sources) {
        if (!source.rawDataJSON) continue

        try {
            const rawData = JSON.parse(source.rawDataJSON)
            const affected = rawData?.containers?.cna?.affected || []

            for (const affectedItem of affected) {
                const product = affectedItem.product || affectedItem.packageName || 'unknown'
                const vendor = affectedItem.vendor || source.affectedVendor || ''
                const repo = affectedItem.repo || null
                const versions = affectedItem.versions || []

                // CRITICAL: Skip affected items from exploit/PoC repositories
                if (repo) {
                    const categorized = categorizeURL(repo)
                    if (categorized.category.type === 'exploit' || categorized.category.type === 'poc') {
                        logger?.debug(`[ExtractAffected] Skipping exploit/poc repo: ${repo}`)
                        continue
                    }
                }

                // Extract ecosystem
                const ecosystem = extractEcosystem(affectedItem, vendor, product)

                // Skip if ecosystem is generic and no package name
                if (ecosystem === 'generic' && !affectedItem.packageName) {
                    continue
                }

                // Build affected range
                const affectedRange = buildAffectedRange(versions)

                // Only include packages with affected ranges
                if (!affectedRange) {
                    logger?.debug(`[ExtractAffected] No affected range for ${ecosystem}:${product}`)
                    continue
                }

                // Deduplicate by ecosystem:packageName
                const key = `${ecosystem}:${product}`
                if (seen.has(key)) {
                    continue
                }
                seen.add(key)

                affectedPackages.push({
                    ecosystem,
                    packageName: product,
                    vendor,
                    repo,
                    affectedRange
                })

                logger?.debug(`[ExtractAffected] Found affected package: ${ecosystem}:${product} (range: ${affectedRange})`)
            }
        } catch (error: any) {
            logger?.warn(`[ExtractAffected] Failed to parse rawDataJSON for source:`, error.message)
        }
    }

    logger?.info(`[ExtractAffected] Extracted ${affectedPackages.length} affected packages`)
    return affectedPackages
}

/**
 * Generate patch intelligence from CVE data, KEV data, CWE data, AI analysis, and references
 * Enhanced with registry-based version discovery
 */
const generatePatchIntelligence = async (
    sources: any[],
    aliasData: any[],
    kevData: any | null,
    cwes: any[],
    agentInferences: any[],
    references: any[],
    logger: any,
    dependencies?: BuildCVEDependencies,
    normalizedCveId?: string
): Promise<PatchIntelligence> => {
    // Helper: Detect version type (commit hash vs semver vs range)
    const detectVersionType = (version: string): 'commit' | 'semver' | 'range' | 'unknown' => {
        if (!version) return 'unknown'

        // Check for git commit hash (40 hex chars OR 7-40 hex chars with at least one letter)
        // Full SHA-1 hash (40 chars)
        if (/^[a-f0-9]{40}$/i.test(version)) return 'commit'

        // Short hash (7-40 chars) - MUST contain at least one letter (a-f) to avoid matching
        // pure numeric strings like dates (20240101), build numbers (1234567), etc.
        if (/^[a-f0-9]{7,40}$/i.test(version) && /[a-f]/i.test(version) && !/\d+\.\d+/.test(version)) {
            return 'commit'
        }

        // Check for semver pattern
        if (/^\d+\.\d+(\.\d+)?/.test(version)) return 'semver'

        // Check for range indicators
        if (version.includes('<') || version.includes('>') || version.includes('*')) return 'range'

        return 'unknown'
    }

    // Helper: Extract real package ecosystem from CVE metadata
    const extractEcosystem = (affectedItem: any, vendor: string, product: string): string => {
        // 1. Check for explicit ecosystem in version data
        if (affectedItem.versions && Array.isArray(affectedItem.versions) && affectedItem.versions.length > 0) {
            const firstVersion = affectedItem.versions[0]
            if (firstVersion.versionType) {
                const vt = firstVersion.versionType.toLowerCase()
                if (vt.includes('npm') || vt === 'node') return 'npm'
                if (vt.includes('pypi') || vt.includes('python') || vt === 'pip') return 'PyPI'
                if (vt.includes('maven') || vt === 'java') return 'Maven'
                if (vt.includes('gem') || vt.includes('ruby')) return 'RubyGems'
                if (vt.includes('nuget') || vt === 'dotnet') return 'NuGet'
                if (vt.includes('cargo') || vt === 'rust') return 'crates.io'
                if (vt.includes('go') || vt === 'golang') return 'Go'
            }
        }

        // 2. Check for package ecosystem field
        if (affectedItem.packageEcosystem) {
            return affectedItem.packageEcosystem
        }

        // 3. Heuristic: Common vendor to ecosystem mappings
        const vendorLower = vendor.toLowerCase()
        if (vendorLower === 'npm' || product.toLowerCase().includes('node')) return 'npm'
        if (vendorLower === 'pypi' || vendorLower === 'python') return 'PyPI'
        if (vendorLower === 'maven' || vendorLower === 'apache') return 'Maven'

        // 4. Fallback to product name if it looks like a known ecosystem
        const productLower = product.toLowerCase()
        if (productLower === 'npm') return 'npm'
        if (productLower === 'pypi' || productLower === 'pip') return 'PyPI'

        // 5. Final fallback to vendor name
        return vendor
    }

    const intel: PatchIntelligence = {
        hasPatch: false,
        sources: []
    }

    // Track all commits with their sources for deduplication
    const commitMap = new Map<string, { source: string, preference: number }>()

    // Track all version fixes with their sources for deduplication
    const versionFixMap = new Map<string, {
        ecosystem: string,
        packageName: string,
        version: string,
        versionType: 'commit' | 'semver' | 'range' | 'unknown',
        statement: string,
        source: string,
        preference: number
    }>()

    // Check references for Patch tag, fix category, or fix-related URLs
    for (const ref of references) {
        const refSource = ref.source || 'VVD'
        const refPreference = getSourcePreference(refSource)

        // IMPORTANT: Explicitly EXCLUDE exploit/poc references from patch detection
        // Exploit repositories (e.g., nuclei-templates) are NOT patches!
        const isExploitOrPoc = ref.category && (ref.category.toLowerCase() === 'exploit' || ref.category.toLowerCase() === 'poc')

        if (isExploitOrPoc) {
            // Skip exploit/poc references entirely - they are NOT patches
            logger?.debug(`[PatchIntel] Skipping exploit/poc reference: ${ref.url}`)
            continue
        }

        const isPatchRef = (ref.tags && Array.isArray(ref.tags) && (ref.tags.includes('Patch') || ref.tags.includes('FIX'))) ||
            (ref.category && ref.category.toLowerCase() === 'fix')

        // Check for Patch/FIX tag or fix category
        if (isPatchRef) {
            intel.hasPatch = true
            if (!intel.sources.includes(refSource)) {
                intel.sources.push(refSource)
            }
        }

        // Check for commit/pull URLs - track commits if they're patch-related
        if (ref.url) {
            const commitMatch = ref.url.match(/\/commit\/([a-f0-9]{7,40})/i) ||
                ref.url.match(/\/info\/([a-f0-9]{7,40})/i) ||
                ref.url.match(/\/changeset\/([a-f0-9]{7,40})/i)
            if (commitMatch && isPatchRef) {
                const hash = commitMatch[1]
                const existing = commitMap.get(hash)

                // Use this commit if we don't have one or if this source has higher preference
                if (!existing || refPreference > existing.preference) {
                    commitMap.set(hash, { source: refSource, preference: refPreference })
                }

                intel.hasPatch = true
            }
        }
    }

    // Helper to process affected versions from a source
    const processAffectedVersions = (source: any, sourceLabel: string) => {
        const srcPreference = getSourcePreference(sourceLabel)

        // First, try to parse CVE 5.1 format from rawDataJSON
        if (source.rawDataJSON) {
            try {
                const rawData = JSON.parse(source.rawDataJSON)
                const affected = rawData?.containers?.cna?.affected || []

                for (const affectedItem of affected) {
                    const product = affectedItem.product || 'Unknown'
                    const vendor = affectedItem.vendor || source.affectedVendor || 'Unknown'
                    const repo = affectedItem.repo || null
                    const versions = affectedItem.versions || []
                    const defaultStatus = affectedItem.defaultStatus || 'affected'

                    // CRITICAL: Skip affected items from exploit/PoC repositories
                    // These are NOT the vulnerable software, they're exploit code!
                    if (repo) {
                        const categorized = categorizeURL(repo)
                        if (categorized.category.type === 'exploit' || categorized.category.type === 'poc') {
                            logger?.debug(`[PatchIntel] Skipping affected item from exploit/poc repo: ${repo}`)
                            continue // Skip this affected item and all its versions
                        }
                    }

                    // Extract proper ecosystem for this affected item
                    const ecosystem = extractEcosystem(affectedItem, vendor, product)

                    // Check for patches in version data
                    for (const versionInfo of versions) {
                        // Check for unaffected status
                        if (versionInfo.status === 'unaffected') {
                            intel.hasPatch = true

                            const fixedVersion = versionInfo.version
                            if (fixedVersion) {
                                const versionType = detectVersionType(fixedVersion)
                                const key = `${vendor}:${product}:${fixedVersion}`
                                const existing = versionFixMap.get(key)

                                // Generate statement based on version type
                                let statement = ''
                                if (versionType === 'commit') {
                                    statement = `Fixed in ${vendor} ${product} commit ${fixedVersion.substring(0, 7)}`
                                } else {
                                    statement = `${ecosystem} ${product} version ${fixedVersion} is not affected`
                                }

                                if (!existing || srcPreference > existing.preference) {
                                    versionFixMap.set(key, {
                                        ecosystem,
                                        packageName: product,
                                        version: fixedVersion,
                                        versionType,
                                        statement,
                                        source: sourceLabel,
                                        preference: srcPreference
                                    })
                                }
                            }
                        }

                        // Check for lessThan (indicates fixed version)
                        if (versionInfo.lessThan && versionInfo.status === 'affected') {
                            intel.hasPatch = true

                            const fixedVersion = versionInfo.lessThan
                            const versionType = detectVersionType(fixedVersion)
                            const key = `${vendor}:${product}:${fixedVersion}`
                            const existing = versionFixMap.get(key)

                            // Generate statement based on version type
                            let statement = ''
                            if (versionType === 'commit') {
                                statement = `Fixed in ${vendor} ${product} commit ${fixedVersion.substring(0, 7)}`
                            } else {
                                statement = `Fixed in ${ecosystem} ${product} version ${fixedVersion}`
                            }

                            if (!existing || srcPreference > existing.preference) {
                                versionFixMap.set(key, {
                                    ecosystem,
                                    packageName: product,
                                    version: fixedVersion,
                                    versionType,
                                    statement,
                                    source: sourceLabel,
                                    preference: srcPreference
                                })
                            }
                        }

                        // Check for changes array with unaffected status
                        if (versionInfo.changes && Array.isArray(versionInfo.changes)) {
                            for (const change of versionInfo.changes) {
                                if (change.status === 'unaffected' && change.at) {
                                    intel.hasPatch = true

                                    const fixedVersion = change.at
                                    const versionType = detectVersionType(fixedVersion)
                                    const key = `${vendor}:${product}:${fixedVersion}`
                                    const existing = versionFixMap.get(key)

                                    // Generate statement based on version type
                                    let statement = ''
                                    if (versionType === 'commit') {
                                        statement = `Fixed in ${vendor} ${product} commit ${fixedVersion.substring(0, 7)}`
                                    } else {
                                        statement = `Fixed in ${ecosystem} ${product} version ${fixedVersion}`
                                    }

                                    if (!existing || srcPreference > existing.preference) {
                                        versionFixMap.set(key, {
                                            ecosystem,
                                            packageName: product,
                                            version: fixedVersion,
                                            versionType,
                                            statement,
                                            source: sourceLabel,
                                            preference: srcPreference
                                        })
                                    }
                                }
                            }
                        }
                    }

                    // If repo is available and we found patches, track it
                    if (repo && intel.hasPatch && !intel.sources.includes(sourceLabel)) {
                        intel.sources.push(sourceLabel)
                    }
                }
            } catch (e) {
                logger?.warn(`Failed to parse CVE 5.1 affected versions from ${sourceLabel}:`, e)
            }
        }

        // Fallback: try legacy affectedVersions field
        if (source.affectedVersions) {
            try {
                const versions = typeof source.affectedVersions === 'string'
                    ? JSON.parse(source.affectedVersions)
                    : source.affectedVersions

                if (Array.isArray(versions)) {
                    for (const versionInfo of versions) {
                        // Check for fixed versions or patches
                        if (versionInfo.status === 'unaffected' || versionInfo.lessThan || versionInfo.changes) {
                            intel.hasPatch = true

                            const ecosystem = source.affectedProduct || 'Unknown'
                            const packageName = source.affectedProduct || 'Unknown'
                            const fixedVersion = versionInfo.lessThan || versionInfo.version

                            if (fixedVersion) {
                                const key = `${ecosystem}:${packageName}:${fixedVersion}`
                                const existing = versionFixMap.get(key)

                                // Track version statement with source attribution
                                let statement = ''
                                if (versionInfo.lessThan) {
                                    statement = `Fixed in ${ecosystem} ${packageName} version ${fixedVersion}`
                                } else if (versionInfo.version && versionInfo.status === 'unaffected') {
                                    statement = `${ecosystem} ${packageName} version ${versionInfo.version} is not affected`
                                }

                                // Use this version if we don't have one or if this source has higher preference
                                if (!existing || srcPreference > existing.preference) {
                                    versionFixMap.set(key, {
                                        ecosystem,
                                        packageName,
                                        version: fixedVersion,
                                        statement,
                                        source: sourceLabel,
                                        preference: srcPreference
                                    })
                                }
                            }
                        }
                    }
                }
            } catch (e) {
                logger?.warn(`Failed to parse affected versions from ${sourceLabel}:`, e)
            }
        }

        // Check for commit hash in references (from rawDataJSON)
        if (source.rawDataJSON) {
            try {
                const rawData = JSON.parse(source.rawDataJSON)
                const refs = rawData?.containers?.cna?.references || rawData?.references || []

                for (const ref of refs) {
                    if (ref.url && (ref.url.includes('/commit/') || ref.url.includes('/pull/'))) {
                        // IMPORTANT: Check if this is an exploit/PoC repository before treating it as a patch
                        // Use categorizeURL to determine the URL type
                        const categorized = categorizeURL(ref.url)
                        const isExploitOrPoc = categorized.category.type === 'exploit' || categorized.category.type === 'poc'

                        if (isExploitOrPoc) {
                            // Skip exploit/PoC commits - they are NOT patches!
                            logger?.debug(`[PatchIntel] Skipping exploit/PoC commit from rawData: ${ref.url}`)
                            continue
                        }

                        const commitMatch = ref.url.match(/\/commit\/([a-f0-9]{7,40})/i)
                        if (commitMatch) {
                            const hash = commitMatch[1]
                            const existing = commitMap.get(hash)

                            // Use this commit if we don't have one or if this source has higher preference
                            if (!existing || srcPreference > existing.preference) {
                                commitMap.set(hash, { source: sourceLabel, preference: srcPreference })
                            }

                            intel.hasPatch = true
                        }
                    }
                }
            } catch (e) {
                logger?.warn(`Failed to extract commit hash from ${sourceLabel}:`, e)
            }
        }
    }

    // Extract patch information from primary sources
    for (const source of sources) {
        processAffectedVersions(source, source.source)
    }

    // Extract patch information from alias data
    for (const alias of aliasData) {
        processAffectedVersions(alias, alias.source)
    }

    // NEW: Augment with registry-discovered versions
    if (dependencies?.prisma && normalizedCveId) {
        try {
            logger?.info(`[PatchIntel] Starting registry-based version discovery for ${normalizedCveId}`)

            // Import RegistryVersionDiscovery
            const { RegistryVersionDiscovery } = await import('./registryVersionDiscovery')

            // Extract affected packages from sources
            const affectedPackages = extractAffectedPackagesFromSources(sources, aliasData, logger)

            if (affectedPackages.length > 0) {
                logger?.info(`[PatchIntel] Found ${affectedPackages.length} affected packages for registry discovery`)

                // Create discovery service
                const registryDiscovery = new RegistryVersionDiscovery({
                    prisma: dependencies.prisma,
                    logger: logger
                })

                // Discover fixed versions for each affected package
                for (const affectedPkg of affectedPackages) {
                    if (!affectedPkg.affectedRange) continue

                    logger?.debug(`[PatchIntel] Discovering versions for ${affectedPkg.ecosystem}:${affectedPkg.packageName}`)

                    try {
                        const discovered = await registryDiscovery.discoverFixedVersions({
                            cveId: normalizedCveId,
                            ecosystem: affectedPkg.ecosystem as any,
                            packageName: affectedPkg.packageName,
                            affectedRange: affectedPkg.affectedRange,
                            vendor: affectedPkg.vendor
                        })

                        // Add discovered fixed versions to versionFixMap with medium confidence
                        for (const fixedVersion of discovered.fixedVersions) {
                            const versionType = detectVersionType(fixedVersion.version)
                            const key = `${affectedPkg.vendor || affectedPkg.ecosystem}:${affectedPkg.packageName}:${fixedVersion.version}`
                            const existing = versionFixMap.get(key)

                            // Use registry-inferred fix if we don't have one from CVE data
                            if (!existing) {
                                const statement = `${affectedPkg.ecosystem} ${affectedPkg.packageName} version ${fixedVersion.version} is outside affected range`

                                versionFixMap.set(key, {
                                    ecosystem: affectedPkg.ecosystem,
                                    packageName: affectedPkg.packageName,
                                    version: fixedVersion.version,
                                    versionType,
                                    statement,
                                    source: `Registry (${discovered.source})`,
                                    preference: 50 // Medium preference - lower than CVE-declared fixes
                                })

                                intel.hasPatch = true
                            }
                        }

                        logger?.info(`[PatchIntel] Added ${discovered.fixedVersions.length} registry-discovered fixes for ${affectedPkg.ecosystem}:${affectedPkg.packageName}`)
                    } catch (error: any) {
                        logger?.warn(`[PatchIntel] Registry discovery failed for ${affectedPkg.ecosystem}:${affectedPkg.packageName}:`, error.message)
                    }
                }
            } else {
                logger?.debug(`[PatchIntel] No affected packages found for registry discovery`)
            }
        } catch (error: any) {
            logger?.error(`[PatchIntel] Registry-based version discovery error:`, error)
        }
    } else {
        logger?.debug(`[PatchIntel] Skipping registry discovery (missing dependencies or cveId)`)
    }

    // Extract remediation advice from KEV
    if (kevData?.requiredAction) {
        intel.remediationAdvice = kevData.requiredAction
        if (!intel.sources.includes('CISA KEV')) {
            intel.sources.push('CISA KEV')
        }
    }

    // Extract CWE mitigations
    if (cwes && cwes.length > 0) {
        intel.cweRemediations = cwes
            .filter(cwe => cwe.cweId)
            .map(cwe => `${cwe.cweId}: ${cwe.description || 'See CWE database for mitigation strategies'}`)
    }

    // Extract Pix AI analysis
    if (agentInferences && agentInferences.length > 0) {
        const pixAnalyses: string[] = []
        const affectedFunctions: string[] = []

        for (const inference of agentInferences) {
            if (inference.pix?.response) {
                try {
                    const response = typeof inference.pix.response === 'string'
                        ? JSON.parse(inference.pix.response)
                        : inference.pix.response

                    // Extract analysis text
                    if (response.analysis || response.remediation || response.summary) {
                        pixAnalyses.push(response.analysis || response.remediation || response.summary)
                    }

                    // Extract affected functions
                    if (response.affectedFunctions && Array.isArray(response.affectedFunctions)) {
                        affectedFunctions.push(...response.affectedFunctions)
                    }

                    // Check for patch indicators in AI response
                    const fullText = JSON.stringify(response).toLowerCase()
                    if (fullText.includes('patch') || fullText.includes('fix') || fullText.includes('update')) {
                        intel.hasPatch = true
                        if (!intel.sources.includes('Pix AI')) {
                            intel.sources.push('Pix AI')
                        }
                    }
                } catch (e) {
                    logger?.warn('Failed to parse Pix response:', e)
                }
            }
        }

        if (pixAnalyses.length > 0) {
            intel.pixAnalysis = pixAnalyses.join('\n\n')
        }

        if (affectedFunctions.length > 0) {
            intel.affectedFunctions = [...new Set(affectedFunctions)]
        }
    }

    // Build commits array from commitMap
    if (commitMap.size > 0) {
        intel.commits = Array.from(commitMap.entries())
            .sort((a, b) => b[1].preference - a[1].preference)
            .map(([hash, data]) => ({
                hash,
                source: data.source,
                url: references.find(ref => ref.url?.includes(hash))?.url
            }))

        // Add sources from commits
        for (const commit of intel.commits) {
            if (!intel.sources.includes(commit.source)) {
                intel.sources.push(commit.source)
            }
        }
    }

    // Build versionFixes array from versionFixMap
    if (versionFixMap.size > 0) {
        intel.versionFixes = Array.from(versionFixMap.values())
            .sort((a, b) => b.preference - a.preference)
            .map(fix => ({
                ecosystem: fix.ecosystem,
                packageName: fix.packageName,
                version: fix.version,
                versionType: fix.versionType,
                statement: fix.statement,
                source: fix.source,
                repo: undefined // Can be added if we track repo URLs
            }))

        // Add sources from version fixes
        for (const fix of intel.versionFixes) {
            if (!intel.sources.includes(fix.source)) {
                intel.sources.push(fix.source)
            }
        }
    }

    // Build comprehensive remediation advice only if there's additional context beyond version fixes
    if (!intel.remediationAdvice) {
        const advice: string[] = []

        // Only add KEV remediation if it exists (it's already set above)
        // Only add commit-based remediation if we have commits but no version fixes
        if (intel.commits && intel.commits.length > 0 && (!intel.versionFixes || intel.versionFixes.length === 0)) {
            advice.push(`Apply security patch from commit ${intel.commits[0].hash.substring(0, 7)}`)
        }

        // Add affected functions review if available
        if (intel.affectedFunctions && intel.affectedFunctions.length > 0) {
            advice.push(`Review code calling these functions: ${intel.affectedFunctions.join(', ')}`)
        }

        // Only set remediationAdvice if we have something beyond the version fixes
        if (advice.length > 0) {
            intel.remediationAdvice = advice.join('. ')
        }
    }

    return intel
}

/**
 * Enrich package metadata using Google OSI (deps.dev API)
 * Cache-first strategy: Check database first, call API if not cached
 *
 * @param prisma Prisma client
 * @param ecosystem Package ecosystem (e.g., NPM, PyPI, Maven)
 * @param packageName Package name
 * @param packageVersion Package version
 * @param logger Logger instance
 * @returns Enriched dependency with publishedAt, provenances, and attestations
 */
const enrichPackageMetadata = async (
    prisma: PrismaClient,
    ecosystem: string,
    packageName: string,
    packageVersion: string,
    logger: any
): Promise<any | null> => {
    try {
        // Generate dependency key
        let dependencyKey = `${ecosystem.toUpperCase()}:${packageName}:${packageVersion}`

        // Check if already enriched in database (cache-first strategy)
        const existingDependency = await prisma.dependency.findFirst({
            where: {
                packageEcosystem: ecosystem.toUpperCase(),
                name: packageName,
                version: packageVersion
            },
            include: {
                slsaProvenances: true,
                attestations: true
            }
        })

        // If already enriched (has publishedAt), return cached data
        if (existingDependency && existingDependency.publishedAt) {
            logger?.debug(`Using cached package data for ${dependencyKey}`)
            return {
                key: existingDependency.key,
                ecosystem: existingDependency.packageEcosystem,
                name: existingDependency.name,
                version: existingDependency.version,
                license: existingDependency.license,
                publishedAt: existingDependency.publishedAt,
                slsaProvenances: existingDependency.slsaProvenances.map(p => ({
                    sourceRepository: p.sourceRepository,
                    commit: p.commit,
                    url: p.url,
                    verified: p.verified === 1
                })),
                attestations: existingDependency.attestations.map(a => ({
                    type: a.type,
                    url: a.url,
                    verified: a.verified === 1,
                    sourceRepository: a.sourceRepository,
                    commit: a.commit
                }))
            }
        }

        // Not cached, call Google OSI API
        logger?.info(`Fetching package metadata from Google OSI for ${dependencyKey}`)
        const depsDevClient = new DepsDevClient({ logger })
        const versionData = await depsDevClient.getVersion(ecosystem, packageName, packageVersion)

        if (!versionData) {
            logger?.warn(`No package metadata found for ${dependencyKey}`)
            return null
        }

        // Parse publishedAt timestamp
        const publishedAt = versionData.publishedAt ? toUnixTimestamp(versionData.publishedAt) : null

        // Store or update dependency with enriched data
        if (existingDependency) {
            // Update existing dependency
            await prisma.dependency.update({
                where: { key: existingDependency.key },
                data: {
                    license: versionData.licenses?.[0] || existingDependency.license,
                    publishedAt
                }
            })

            dependencyKey = existingDependency.key
        } else {
            // Create new dependency
            await prisma.dependency.create({
                data: {
                    key: dependencyKey,
                    name: packageName,
                    version: packageVersion,
                    packageEcosystem: ecosystem.toUpperCase(),
                    license: versionData.licenses?.[0] || null,
                    publishedAt
                }
            })
        }

        // Store SLSA Provenances
        const slsaProvenances: any[] = []
        if (versionData.slsaProvenances && versionData.slsaProvenances.length > 0) {
            for (const provenance of versionData.slsaProvenances) {
                // Check if already exists
                const existing = await prisma.dependencySLSAProvenance.findFirst({
                    where: {
                        dependencyKey,
                        commit: provenance.commit,
                        url: provenance.url
                    }
                })

                if (!existing) {
                    const created = await prisma.dependencySLSAProvenance.create({
                        data: {
                            dependencyKey,
                            sourceRepository: provenance.sourceRepository,
                            commit: provenance.commit,
                            url: provenance.url,
                            verified: provenance.verified ? 1 : 0,
                            createdAt: Math.floor(Date.now() / 1000)
                        }
                    })
                    slsaProvenances.push({
                        sourceRepository: created.sourceRepository,
                        commit: created.commit,
                        url: created.url,
                        verified: created.verified === 1
                    })
                } else {
                    slsaProvenances.push({
                        sourceRepository: existing.sourceRepository,
                        commit: existing.commit,
                        url: existing.url,
                        verified: existing.verified === 1
                    })
                }
            }
        }

        // Store Attestations
        const attestations: any[] = []
        if (versionData.attestations && versionData.attestations.length > 0) {
            for (const attestation of versionData.attestations) {
                // Check if already exists
                const existing = await prisma.dependencyAttestation.findFirst({
                    where: {
                        dependencyKey,
                        type: attestation.type,
                        url: attestation.url
                    }
                })

                if (!existing) {
                    const created = await prisma.dependencyAttestation.create({
                        data: {
                            dependencyKey,
                            type: attestation.type,
                            url: attestation.url,
                            verified: attestation.verified ? 1 : 0,
                            sourceRepository: attestation.sourceRepository || null,
                            commit: attestation.commit || null,
                            createdAt: Math.floor(Date.now() / 1000)
                        }
                    })
                    attestations.push({
                        type: created.type,
                        url: created.url,
                        verified: created.verified === 1,
                        sourceRepository: created.sourceRepository,
                        commit: created.commit
                    })
                } else {
                    attestations.push({
                        type: existing.type,
                        url: existing.url,
                        verified: existing.verified === 1,
                        sourceRepository: existing.sourceRepository,
                        commit: existing.commit
                    })
                }
            }
        }

        logger?.info(`Successfully enriched package ${dependencyKey} with ${slsaProvenances.length} provenances and ${attestations.length} attestations`)

        return {
            key: dependencyKey,
            ecosystem: ecosystem.toUpperCase(),
            name: packageName,
            version: packageVersion,
            license: versionData.licenses?.[0] || null,
            publishedAt,
            slsaProvenances,
            attestations
        }
    } catch (error) {
        logger?.error(`Failed to enrich package ${ecosystem}:${packageName}@${packageVersion}:`, error)
        return null
    }
}

/**
 * Extract and enrich package information from CVE sources
 *
 * @param sources CVE metadata sources
 * @param aliasData Alias CVE data
 * @param prisma Prisma client
 * @param logger Logger instance
 * @returns Array of enriched package metadata
 */
const extractAndEnrichPackages = async (
    sources: any[],
    aliasData: any[],
    prisma: PrismaClient,
    logger: any
): Promise<any[]> => {
    const enrichedPackages: any[] = []
    const seenPackages = new Set<string>()

    // Helper to extract packages from affected versions
    const extractPackages = async (source: any) => {
        if (!source.affectedVersions) return

        try {
            const versions = typeof source.affectedVersions === 'string'
                ? JSON.parse(source.affectedVersions)
                : source.affectedVersions

            if (!Array.isArray(versions)) return

            for (const versionInfo of versions) {
                // Try to extract ecosystem from various fields
                let ecosystem: string | null = null
                let packageName: string | null = null

                // Check collectionURL for ecosystem hints
                if (versionInfo.collectionURL) {
                    const url = versionInfo.collectionURL.toLowerCase()
                    if (url.includes('npmjs.com') || url.includes('registry.npmjs.org')) {
                        ecosystem = 'NPM'
                    } else if (url.includes('pypi.org')) {
                        ecosystem = 'PyPI'
                    } else if (url.includes('crates.io')) {
                        ecosystem = 'Cargo'
                    } else if (url.includes('maven') || url.includes('mvnrepository')) {
                        ecosystem = 'Maven'
                    } else if (url.includes('nuget.org')) {
                        ecosystem = 'NuGet'
                    } else if (url.includes('rubygems.org')) {
                        ecosystem = 'RubyGems'
                    } else if (url.includes('golang.org') || url.includes('pkg.go.dev')) {
                        ecosystem = 'Go'
                    }
                }

                // Extract package name from packageName or affected product
                packageName = versionInfo.packageName || source.affectedProduct

                // Skip if we don't have both ecosystem and packageName
                if (!ecosystem || !packageName) continue

                // Try to find fixed version
                const fixedVersion = versionInfo.lessThan || versionInfo.version
                if (!fixedVersion) continue

                // Create unique key for deduplication
                const packageKey = `${ecosystem}:${packageName}:${fixedVersion}`
                if (seenPackages.has(packageKey)) continue
                seenPackages.add(packageKey)

                // Enrich package metadata
                const enriched = await enrichPackageMetadata(
                    prisma,
                    ecosystem,
                    packageName,
                    fixedVersion,
                    logger
                )

                if (enriched) {
                    enrichedPackages.push(enriched)
                }
            }
        } catch (e) {
            logger?.warn(`Failed to extract packages from affected versions:`, e)
        }
    }

    // Extract from primary sources
    for (const source of sources) {
        await extractPackages(source)
    }

    // Extract from alias data
    for (const alias of aliasData) {
        await extractPackages(alias)
    }

    return enrichedPackages
}

/**
 * Build comprehensive CVE data structure including all sources, CVSS, EPSS, CESS
 * Normalizes cveId to uppercase for case-insensitive lookup
 */
export async function buildCVEData(
    cveId: string,
    dependencies: BuildCVEDependencies,
    context: BuildCVEDataContext = {},
    options: BuildCVEDataOptions = {}
) {
    const { orgId = 'public-vdb', memberId = 'public-vdb' } = context
    const {
        collectAliases = true,
        includeAI = true,
        includeFileLinks = true
    } = options

    // Normalize cveId to uppercase for case-insensitive lookup
    const normalizedCveId = cveId.trim().toUpperCase()

    // Get ALL CVE metadata sources
    const allSources = await dependencies.prisma.cVEMetadata.findMany({
        where: { cveId: normalizedCveId },
        include: {
            cna: true,
            fileLink: true,
            adp: {
                include: {
                    adp: true
                }
            },
            references: true,
            metrics: true // Include metrics to get CVSS scores
        }
    })

    if (!allSources || allSources.length === 0) {
        return null
    }

    // Build sources array (using let to allow deduplication reassignment later)
    let sources = allSources.map(cveMetadata => {
        let affectedVersions = null
        let cpes = null

        try {
            if (cveMetadata.affectedVersionsJSON && cveMetadata.affectedVersionsJSON !== 'null') {
                const allVersions = JSON.parse(cveMetadata.affectedVersionsJSON)

                // Filter out unaffected versions - they belong in patchIntelligence, not affectedVersions
                // This prevents contradictions like showing "unaffected" commits in "Affected Versions" section
                if (Array.isArray(allVersions)) {
                    affectedVersions = allVersions.filter(v => {
                        // Only include versions that are actually affected
                        // Skip: status === 'unaffected'
                        return v.status !== 'unaffected'
                    })
                } else {
                    affectedVersions = allVersions
                }
            }
        } catch (e) {
            dependencies.logger?.warn(`Failed to parse affectedVersionsJSON for ${cveMetadata.cveId}:`, e)
        }

        try {
            if (cveMetadata.cpesJSON && cveMetadata.cpesJSON !== 'null') {
                cpes = JSON.parse(cveMetadata.cpesJSON)
            }
        } catch (e) {
            dependencies.logger?.warn(`Failed to parse cpesJSON for ${cveMetadata.cveId}:`, e)
        }

        // Find the highest CVSS score from metrics (preferred) or fallback to deprecated vectorString
        let highestVector = cveMetadata.vectorString
        let highestScore: number | null = null
        let highestVersion = null

        if (cveMetadata.metrics && cveMetadata.metrics.length > 0) {
            // Find metric with highest baseScore
            let maxScore = -1
            for (const metric of cveMetadata.metrics) {
                // ALWAYS recalculate score instead of trusting stored baseScore
                // This fixes data quality issues where baseScore was incorrectly stored as 0
                let score = calculateCvssScore(metric.vectorString)

                // Fallback to stored baseScore only if calculation fails and baseScore is valid (not 0)
                if (score === null && metric.baseScore && metric.baseScore > 0) {
                    score = metric.baseScore
                }

                if (score !== null && score > maxScore) {
                    maxScore = score
                    highestScore = score
                    highestVector = metric.vectorString
                    highestVersion = getCvssVersion(metric.vectorString)
                }
            }
        }

        // Fallback to deprecated vectorString if no metrics found or all failed
        if (highestScore === null && cveMetadata.vectorString) {
            highestScore = calculateCvssScore(cveMetadata.vectorString)
            highestVersion = getCvssVersion(cveMetadata.vectorString)
        }

        return {
            source: normalizeSourceName(cveMetadata.source),
            cveId: cveMetadata.cveId,
            dataVersion: cveMetadata.dataVersion,
            state: cveMetadata.state,
            datePublished: cveMetadata.datePublished,
            dateUpdated: cveMetadata.dateUpdated,
            dateReserved: cveMetadata.dateReserved,
            vectorString: highestVector,
            cvssVersion: highestVersion,
            score: highestScore,
            title: cveMetadata.title,
            sourceAdvisoryRef: cveMetadata.sourceAdvisoryRef,
            affectedVendor: cveMetadata.affectedVendor,
            affectedProduct: cveMetadata.affectedProduct,
            affectedVersions,
            cpes,
            cna: cveMetadata.cna ? {
                shortName: cveMetadata.cna.shortName
            } : null,
            fileLink: cveMetadata.fileLink ? {
                url: cveMetadata.fileLink.url,
                contentType: cveMetadata.fileLink.contentType
            } : null,
            adp: cveMetadata.adp.map(adpRel => ({
                shortName: adpRel.adp.shortName,
                title: adpRel.adp.title
            })),
            lastFetchedAt: cveMetadata.lastFetchedAt,
            fetchCount: cveMetadata.fetchCount,
            rawDataJSON: cveMetadata.rawDataJSON
        }
    })

    // Get merged CVE metadata from all sources (Vulnetix aggregated view)
    // CRITICAL: Skip merging for GCVE IDs since they are already Vulnetix-native
    const mergedMetadata = !normalizedCveId.startsWith('GCVE-')
        ? await mergeCVEMetadata(dependencies.prisma, normalizedCveId, dependencies.logger)
        : null

    // Create Vulnetix source as the first source (aggregated from all sources)
    // Skip for GCVE IDs to avoid duplicates (GCVE sources are already 'vvd'/Vulnetix)
    if (mergedMetadata && !normalizedCveId.startsWith('GCVE-')) {
        // Find the metric with the highest baseScore (prefer calculated scores over null/undefined)
        let highestMetric = null
        let highestScore = -1

        if (mergedMetadata.metrics && mergedMetadata.metrics.length > 0) {
            for (const metric of mergedMetadata.metrics) {
                const score = metric.baseScore || calculateCvssScore(metric.vectorString)
                if (score !== null && score > highestScore) {
                    highestScore = score
                    highestMetric = metric
                }
            }
        }

        const vulnetixSource: any = {
            source: 'Vulnetix',
            cveId: mergedMetadata.cveId,
            dataVersion: null,
            state: mergedMetadata.state,
            datePublished: mergedMetadata.datePublished,
            dateUpdated: mergedMetadata.dateUpdated,
            dateReserved: mergedMetadata.dateReserved,
            vectorString: highestMetric?.vectorString || null,
            cvssVersion: highestMetric ? getCvssVersion(highestMetric.vectorString) : null,
            score: highestScore >= 0 ? highestScore : null,
            title: mergedMetadata.title,
            sourceAdvisoryRef: null,
            affectedVendor: mergedMetadata.affected && mergedMetadata.affected.length > 0
                ? mergedMetadata.affected[0].vendor
                : null,
            affectedProduct: mergedMetadata.affected && mergedMetadata.affected.length > 0
                ? mergedMetadata.affected[0].product
                : null,
            affectedVersions: mergedMetadata.affected && mergedMetadata.affected.length > 0
                ? mergedMetadata.affected[0].versions
                : null,
            cpes: mergedMetadata.affected && mergedMetadata.affected.length > 0
                ? mergedMetadata.affected[0].cpes
                : null,
            cna: null,
            fileLink: null,
            adp: [],
            lastFetchedAt: allSources && allSources.length > 0 ? allSources[0].lastFetchedAt : null,
            fetchCount: allSources && allSources.length > 0 ? allSources[0].fetchCount : 0,
            rawDataJSON: JSON.stringify({
                descriptions: mergedMetadata.descriptions,
                cwes: mergedMetadata.cwes,
                metrics: mergedMetadata.metrics,
                affected: mergedMetadata.affected,
                references: mergedMetadata.references,
                impacts: mergedMetadata.impacts,
                sources: mergedMetadata.sources
            }),
            gcveId: null // Will be populated if GCVE ID exists or is generated
        }

        // Prepend Vulnetix source to the beginning of sources array
        sources.unshift(vulnetixSource)

        // Generate or lookup GCVE identifier for Vulnetix-sourced CVEs
        // CRITICAL: Never generate GCVE ID if the CVE ID is already a GCVE ID
        dependencies.logger?.info(`[GCVE] Checking GCVE generation conditions: r2artifacts=${!!dependencies.r2artifacts}, prisma=${!!dependencies.prisma}`)
        if (dependencies.r2artifacts && dependencies.prisma && !normalizedCveId.startsWith('GCVE-')) {
            try {
                dependencies.logger?.info(`[GCVE] Starting GCVE ID lookup/generation for ${normalizedCveId}`)
                // Check if GCVE ID already exists
                const existingGcve = await lookupGcveId(
                    dependencies.prisma,
                    normalizedCveId,
                    'Vulnetix'
                )

                if (existingGcve) {
                    // Add existing GCVE ID to the Vulnetix source
                    vulnetixSource.gcveId = existingGcve.gcveId
                    dependencies.logger?.info(`[GCVE] Found existing GCVE ID: ${existingGcve.gcveId} for ${normalizedCveId}`)
                } else {
                    dependencies.logger?.info(`[GCVE] No existing GCVE ID found, generating new one for ${normalizedCveId}`)
                    // Generate new GCVE ID
                    const gcveResult = await generateGcveId(
                        dependencies.prisma,
                        dependencies.r2artifacts,
                        normalizedCveId,
                        'Vulnetix'
                    )

                    if (gcveResult.success && gcveResult.gcveId) {
                        vulnetixSource.gcveId = gcveResult.gcveId
                        dependencies.logger?.info(`[GCVE] Generated new GCVE ID: ${gcveResult.gcveId} for ${normalizedCveId}`)

                        // Store CVE data in CVEList v5 format to R2
                        const cveListV5Data = {
                            dataType: 'CVE_RECORD',
                            dataVersion: '5.1',
                            cveMetadata: {
                                cveId: normalizedCveId,
                                gcveId: gcveResult.gcveId,
                                assignerOrgId: 'vulnetix',
                                assignerShortName: 'VVD',
                                state: mergedMetadata.state || 'PUBLISHED',
                                datePublished: mergedMetadata.datePublished
                                    ? new Date(mergedMetadata.datePublished * 1000).toISOString()
                                    : new Date().toISOString(),
                                dateUpdated: mergedMetadata.dateUpdated
                                    ? new Date(mergedMetadata.dateUpdated * 1000).toISOString()
                                    : undefined
                            },
                            containers: {
                                cna: {
                                    providerMetadata: {
                                        orgId: 'vulnetix',
                                        shortName: 'VVD'
                                    },
                                    title: mergedMetadata.title || normalizedCveId,
                                    descriptions: mergedMetadata.descriptions?.map(desc => ({
                                        lang: desc.lang || 'en',
                                        value: desc.value
                                    })) || [],
                                    affected: mergedMetadata.affected?.map(aff => {
                                        const affected: any = {}
                                        if (aff.vendor) affected.vendor = aff.vendor
                                        if (aff.product) affected.product = aff.product
                                        if (aff.versions) affected.versions = aff.versions
                                        if (aff.cpes) affected.cpes = aff.cpes
                                        return affected
                                    }) || [],
                                    references: mergedMetadata.references?.map(ref => ({
                                        url: ref.url,
                                        name: ref.title,
                                        tags: ref.type ? [ref.type.toLowerCase()] : undefined
                                    })) || [],
                                    metrics: mergedMetadata.metrics?.map(metric => {
                                        const metricObj: any = {}
                                        const metricType = metric.metricType?.replace('.', '_')
                                        if (metricType && ['cvssV2_0', 'cvssV3_0', 'cvssV3_1', 'cvssV4_0'].includes(metricType)) {
                                            metricObj[metricType] = {
                                                version: metric.metricType?.replace('cvssV', '').replace('_', '.'),
                                                vectorString: metric.vectorString,
                                                baseScore: metric.baseScore,
                                                baseSeverity: metric.baseSeverity
                                            }
                                        }
                                        return metricObj
                                    }).filter(m => Object.keys(m).length > 0) || [],
                                    problemTypes: mergedMetadata.cwes?.length > 0 ? [{
                                        descriptions: mergedMetadata.cwes.map(cwe => ({
                                            type: cwe.descriptionType || 'CWE',
                                            cweId: cwe.cweId,
                                            lang: cwe.lang || 'en',
                                            description: cwe.description || cwe.cweId
                                        }))
                                    }] : []
                                }
                            }
                        }

                        const storeResult = await storeGcveCveListV5(
                            dependencies.r2artifacts,
                            gcveResult.gcveId,
                            cveListV5Data
                        )

                        if (storeResult.success) {
                            dependencies.logger?.info(`[GCVE] Stored CVEList v5 data to R2: ${storeResult.r2Key}`)
                        } else {
                            dependencies.logger?.error(`[GCVE] Failed to store CVEList v5 data to R2: ${storeResult.error}`)
                        }
                    } else {
                        dependencies.logger?.error(`[GCVE] Failed to generate GCVE ID for ${normalizedCveId}: ${gcveResult.error}`)
                    }
                }
            } catch (error) {
                dependencies.logger?.error(`[GCVE] Error processing GCVE ID for ${normalizedCveId}:`, error)
            }
        } else {
            dependencies.logger?.warn(`[GCVE] Skipping GCVE generation - missing dependencies: r2artifacts=${!!dependencies.r2artifacts}, prisma=${!!dependencies.prisma}`)
        }
    }

    // Fetch CVSS data from linked Findings
    const findingsWithCvss = await dependencies.prisma.finding.findMany({
        where: {
            aliases: {
                contains: normalizedCveId
            }
        },
        select: {
            uuid: true,
            orgId: true,
            modifiedAt: true,
            customCvssVector: true,
            customCvssScore: true,
            triage: {
                orderBy: {
                    lastObserved: 'desc'
                },
                select: {
                    cvssVector: true,
                    cvssScore: true,
                    cvssSource: true,
                    lastObserved: true
                }
            }
        },
        orderBy: {
            modifiedAt: 'desc'
        }
    })

    // Collect distinct CVSS vectors
    const cvssFromFindings: any[] = []
    const seenVectors = new Set<string>()

    for (const finding of findingsWithCvss) {
        if (finding.customCvssVector && !seenVectors.has(finding.customCvssVector)) {
            seenVectors.add(finding.customCvssVector)
            const triage = latestTriage(finding.triage);
            cvssFromFindings.push({
                source: triage?.cvssSource,
                vectorString: triage.cvssVector,
                cvssVersion: getCvssVersion(triage.cvssVector),
                score: triage.cvssScore,
            })
        }

        if (finding.triage && finding.triage.length > 0) {
            // Iterate through all triage entries to collect CVSS data for each version
            for (const triage of finding.triage) {
                if (triage.cvssVector && !seenVectors.has(triage.cvssVector)) {
                    seenVectors.add(triage.cvssVector)
                    cvssFromFindings.push({
                        source: triage.cvssSource || 'Vulnetix',
                        vectorString: triage.cvssVector,
                        cvssVersion: getCvssVersion(triage.cvssVector),
                        score: triage.cvssScore,
                        lastObserved: triage.lastObserved,
                        orgId: finding.orgId
                    })
                }
            }
        }
    }

    // Fetch CVEImpact data with CAPEC attack patterns
    dependencies.logger?.info(`Fetching CAPEC attack patterns for ${normalizedCveId}`)
    const impactData = await dependencies.prisma.cVEImpact.findMany({
        where: { cveId: normalizedCveId },
        include: {
            descriptions: true
        },
        orderBy: { createdAt: 'desc' }
    })

    const capecPatterns: any[] = []
    const seenCapecIds = new Set<string>()

    for (const impact of impactData) {
        if (impact.capecId && !seenCapecIds.has(impact.capecId)) {
            seenCapecIds.add(impact.capecId)

            // Extract CAPEC number from ID (e.g., "CAPEC-123" -> "123")
            const capecNumber = impact.capecId.replace(/^CAPEC-/i, '')

            capecPatterns.push({
                capecId: impact.capecId,
                capecNumber,
                containerType: impact.containerType,
                adpOrgId: impact.adpOrgId,
                source: impact.source,
                descriptions: impact.descriptions.map(desc => ({
                    lang: desc.lang,
                    value: desc.value
                })),
                // CAPEC database URLs
                url: `https://capec.mitre.org/data/definitions/${capecNumber}.html`,
                cweUrl: `https://cwe.mitre.org/data/definitions/${capecNumber}.html`
            })
        }
    }

    dependencies.logger?.info(`Found ${capecPatterns.length} CAPEC attack patterns for ${normalizedCveId}`)

    // Collect ALL CVSS vectors from all sources (NO deduplication)
    // Frontend will compute distinct vectors just-in-time as needed
    const allCvssVectors: any[] = []

    // Add CVSS from all CVEMetadata sources
    for (const source of sources) {
        if (source.vectorString && source.cvssVersion) {
            allCvssVectors.push({
                source: normalizeSourceName(source.source),
                vectorString: source.vectorString,
                cvssVersion: source.cvssVersion,
                score: calculateCvssScore(source.vectorString),
                lastObserved: source.dateUpdated || source.datePublished
            })
        }
    }

    // Add CVSS from Findings
    for (const cvss of cvssFromFindings) {
        if (cvss.cvssVersion) {
            allCvssVectors.push(cvss)
        }
    }

    // Fetch CESS history (only for CVE IDs)
    let cessHistory = await dependencies.prisma.cessScore.findMany({
        where: { cve: normalizedCveId },
        orderBy: { dateString: 'desc' }
    })

    if (normalizedCveId.startsWith('CVE-') && isCessStale(cessHistory)) {
        const cess = new CESS(dependencies.env?.CESS_API_URL)
        try {
            await cess.fetchHistory(dependencies.prisma, orgId, memberId, normalizedCveId)
            cessHistory = await dependencies.prisma.cessScore.findMany({
                where: { cve: normalizedCveId },
                orderBy: { dateString: 'desc' }
            })
        } catch (error) {
            dependencies.logger?.error(`Failed to fetch ESS history for ${normalizedCveId}:`, error)
        }
    }

    // Fetch EPSS history (only for CVE IDs)
    let epssHistory = await dependencies.prisma.epssScore.findMany({
        where: { cve: normalizedCveId },
        orderBy: { dateString: 'desc' }
    })

    if (normalizedCveId.startsWith('CVE-') && isEpssStale(epssHistory)) {
        const epss = new EPSS()
        try {
            await epss.fetchTimeSeries(dependencies.prisma, orgId, memberId, normalizedCveId)
            epssHistory = await dependencies.prisma.epssScore.findMany({
                where: { cve: normalizedCveId },
                orderBy: { dateString: 'desc' }
            })
        } catch (error) {
            dependencies.logger?.error(`Failed to fetch EPSS time series for ${normalizedCveId}:`, error)
        }
    }

    // Extract references from CVEMetadataReferences table (enriched data)
    const allReferences: any[] = []
    const seenReferenceUrls = new Set<string>()
    const referencesToProcess: Array<{ source: string, url: string, type?: string, title?: string, referenceSource: string }> = []

    // Temporary set to collect extracted identifiers from references (before allAliases is initialized)
    const extractedIdentifiers = new Set<string>()

    // Add enriched references from CVEMetadataReferences table
    for (const cveMetadata of allSources) {
        if (cveMetadata.references && cveMetadata.references.length > 0) {
            cveMetadata.references.forEach(ref => {
                if (ref.url && !seenReferenceUrls.has(ref.url)) {
                    seenReferenceUrls.add(ref.url)

                    // Categorize the URL
                    const categorized = categorizeURL(ref.url)

                    // Extract vulnerability identifiers from the URL and extracted data
                    if (categorized.category.extractedData) {
                        const extractedData = categorized.category.extractedData

                        for (const pattern of identifierPatterns) {
                            const identifierValue = extractedData[pattern]
                            if (identifierValue && typeof identifierValue === 'string') {
                                const normalizedId = identifierValue.trim().toUpperCase()
                                // Add to temporary set if not the main CVE ID
                                if (normalizedId && normalizedId !== normalizedCveId) {
                                    extractedIdentifiers.add(normalizedId)
                                    dependencies.logger?.info(`Extracted alias from reference: ${normalizedId} (source: ${pattern})`)
                                }
                            }
                        }
                    }

                    allReferences.push({
                        uuid: ref.uuid || undefined, // Database UUID for enrichment updates
                        url: ref.url,
                        name: ref.title || null,
                        title: ref.title || null,
                        tags: ref.type ? [ref.type] : [],
                        source: ref.referenceSource,
                        // Add enrichment data from CVEMetadataReferences
                        httpStatus: ref.httpStatus || undefined,
                        deadLink: ref.deadLink || undefined,
                        deadLinkCheckedAt: ref.deadLinkCheckedAt || undefined,
                        createdAt: ref.createdAt || undefined,
                        type: ref.type,
                        // Add URL categorization data (enhanced from categorizeURL)
                        category: categorized.category.type,
                        categoryConfidence: categorized.category.confidence,
                        subcategory: categorized.category.subcategory,
                        extractedData: categorized.category.extractedData,
                        // Add GitHub PR enrichment fields
                        prDiffUrl: ref.prDiffUrl || undefined,
                        prState: ref.prState || undefined,
                        prAuthor: ref.prAuthor || undefined,
                        prLabels: ref.prLabels ? JSON.parse(ref.prLabels) : undefined,
                        prMergedAt: ref.prMergedAt || undefined,
                        prMergeCommitSha: ref.prMergeCommitSha || undefined,
                        prRepoHealth: ref.prRepoHealth ? JSON.parse(ref.prRepoHealth) : undefined,
                        // Add GitHub Commit enrichment fields
                        commitAuthorEmail: ref.commitAuthorEmail || undefined,
                        commitAuthorLogin: ref.commitAuthorLogin || undefined,
                        commitVerified: ref.commitVerified !== null ? (ref.commitVerified === 1) : undefined,
                        commitHealth: ref.commitHealth ? JSON.parse(ref.commitHealth) : undefined,
                        // Add ExploitDB enrichment fields
                        exploitDbId: ref.exploitDbId || undefined,
                        exploitDbAuthor: ref.exploitDbAuthor || undefined,
                        exploitDbDate: ref.exploitDbDate || undefined,
                        exploitDbPlatform: ref.exploitDbPlatform || undefined,
                        exploitDbType: ref.exploitDbType || undefined,
                        exploitDbPort: ref.exploitDbPort || undefined,
                        exploitDbVerified: ref.exploitDbVerified !== null ? (ref.exploitDbVerified === 1) : undefined,
                        // Add GitHub Gist enrichment fields
                        gistId: ref.gistId || undefined,
                        gistPublic: ref.gistPublic !== null ? (ref.gistPublic === 1) : undefined,
                        gistFilesCount: ref.gistFilesCount || undefined,
                        gistFiles: ref.gistFiles || undefined,
                        gistComments: ref.gistComments || undefined,
                        gistUpdatedAt: ref.gistUpdatedAt || undefined,
                        // Add VulnerabilityLab enrichment fields
                        vlId: ref.vlId || undefined,
                        vlTitle: ref.vlTitle || undefined,
                        vlCreatedAt: ref.vlCreatedAt || undefined,
                        vlUpdatedAt: ref.vlUpdatedAt || undefined,
                        vlExploitationTechnique: ref.vlExploitationTechnique || undefined,
                        vlAuthenticationType: ref.vlAuthenticationType || undefined,
                        vlUserInteraction: ref.vlUserInteraction || undefined,
                        vlAuthor: ref.vlAuthor || undefined
                    })
                }
            })
        }
    }

    // Fallback: Extract references from rawDataJSON if no enriched data
    for (const source of sources) {
        if (source.rawDataJSON) {
            try {
                const rawData = JSON.parse(source.rawDataJSON)
                const cveReferences = rawData?.containers?.cna?.references || rawData?.references || []

                // Ensure cveReferences is an array before calling forEach
                if (Array.isArray(cveReferences)) {
                    cveReferences.forEach((ref: any) => {
                        if (ref.url && !seenReferenceUrls.has(ref.url)) {
                            seenReferenceUrls.add(ref.url)

                            // Add to processing queue for full enrichment
                            referencesToProcess.push({
                                source: normalizeSourceName(source.source),
                                url: ref.url,
                                type: Array.isArray(ref.tags) ? ref.tags[0] : ref.type,
                                title: ref.name,
                                referenceSource: normalizeSourceName(source.source)
                            })

                            // Categorize the URL for immediate use
                            const categorized = categorizeURL(ref.url)

                            // Extract vulnerability identifiers from the URL and extracted data
                            if (categorized.category.extractedData) {
                                const extractedData = categorized.category.extractedData

                                for (const pattern of identifierPatterns) {
                                    const identifierValue = extractedData[pattern]
                                    if (identifierValue && typeof identifierValue === 'string') {
                                        const normalizedId = identifierValue.trim().toUpperCase()
                                        // Add to temporary set if not the main CVE ID
                                        if (normalizedId && normalizedId !== normalizedCveId) {
                                            extractedIdentifiers.add(normalizedId)
                                            dependencies.logger?.info(`Extracted alias from reference (rawData): ${normalizedId} (source: ${pattern})`)
                                        }
                                    }
                                }
                            }

                            allReferences.push({
                                url: ref.url,
                                name: ref.name || null,
                                tags: ref.tags || [],
                                source: normalizeSourceName(source.source),
                                createdAt: ref.createdAt || undefined,
                                // Add URL categorization data
                                category: categorized.category.type,
                                categoryConfidence: categorized.category.confidence,
                                subcategory: categorized.category.subcategory,
                                extractedData: categorized.category.extractedData
                            })
                        }
                    })
                }
            } catch (e) {
                dependencies.logger?.warn(`Failed to parse rawDataJSON for references from ${source.source}:`, e)
            }
        }
    }

    // Enrich references on-demand if missing enrichment data (ExploitDB, GitHub Gist, etc.)
    await enrichReferencesOnDemand(allReferences, dependencies, dependencies.logger)

    // Use recursive alias collection if enabled
    let allAliases = new Set<string>()

    // Merge extracted identifiers from references into allAliases
    extractedIdentifiers.forEach(id => allAliases.add(id))
    if (extractedIdentifiers.size > 0) {
        dependencies.logger?.info(`Merged ${extractedIdentifiers.size} extracted identifiers from references into aliases`)
    }

    if (collectAliases) {
        dependencies.logger?.info(`Recursively collecting aliases for ${normalizedCveId}`)
        allAliases = await collectAllAliases(dependencies.prisma, normalizedCveId, dependencies.logger)

        // Re-merge extracted identifiers after recursive collection (in case collectAllAliases creates new Set)
        extractedIdentifiers.forEach(id => allAliases.add(id))
        dependencies.logger?.info(`Collected ${allAliases.size} total aliases for ${normalizedCveId}`)
    } else {
        // Fallback to simple alias collection (backward compatibility)
        try {
            const aliasRelations = await dependencies.prisma.cVEAlias.findMany({
                where: {
                    OR: [
                        { primaryCveId: normalizedCveId },
                        { aliasCveId: normalizedCveId }
                    ]
                },
                distinct: ['aliasCveId', 'primaryCveId']
            })

            aliasRelations.forEach(relation => {
                if (relation.primaryCveId !== normalizedCveId) {
                    allAliases.add(relation.primaryCveId.toUpperCase())
                }
                if (relation.aliasCveId !== normalizedCveId) {
                    allAliases.add(relation.aliasCveId.toUpperCase())
                }
            })

            dependencies?.logger?.info(`Found ${allAliases.size} aliases from CVEAlias database for ${normalizedCveId}`)
        } catch (e) {
            dependencies.logger?.warn(`Failed to query CVEAlias table for ${normalizedCveId}:`, e)
        }

        // Supplement with aliases from rawDataJSON (for backward compatibility)
        for (const source of sources) {
            if (source.rawDataJSON) {
                try {
                    const rawData = JSON.parse(source.rawDataJSON)
                    const cveAliases = Array.isArray(rawData?.aliases) ? rawData.aliases : []
                    const computedAliases = Array.isArray(rawData?.computedAliases) ? rawData.computedAliases : []

                    const allSourceAliases = [...cveAliases, ...computedAliases]

                    allSourceAliases.forEach((alias: string) => {
                        const normalizedAlias = alias.toUpperCase()
                        if (normalizedAlias && normalizedAlias !== normalizedCveId) {
                            allAliases.add(normalizedAlias)
                        }
                    })
                } catch (e) {
                    dependencies.logger?.warn(`Failed to parse rawDataJSON for aliases from ${source.source}:`, e)
                }
            }
        }
    }

    // Fetch CWE/ProblemType data
    const problemTypes = await dependencies.prisma.cVEProblemType.findMany({
        where: { cveId: normalizedCveId },
        orderBy: { createdAt: 'desc' }
    })

    const cwes: any[] = []
    const seenCweIds = new Set<string>()

    for (const problemType of problemTypes) {
        if (problemType.cweId && !seenCweIds.has(problemType.cweId)) {
            seenCweIds.add(problemType.cweId)
            cwes.push({
                cweId: problemType.cweId,
                description: problemType.description,
                descriptionType: problemType.descriptionType,
                containerType: problemType.containerType,
                adpOrgId: problemType.adpOrgId,
                source: problemType.source,
                lang: problemType.lang
            })
        }
    }

    // Add references from Finding data and collect agentInferences
    const findingsWithReferences = await dependencies.prisma.finding.findMany({
        where: {
            aliases: {
                contains: normalizedCveId
            }
        },
        include: {
            references: true,
            agentInferences: {
                include: {
                    pix: true
                },
                orderBy: {
                    createdAt: 'desc'
                }
            }
        }
    })

    // ALWAYS fetch public-vdb Finding for AI inferences (if it exists)
    // This is where VDB AI analyses are stored
    const publicVdbFinding = await dependencies.prisma.finding.findFirst({
        where: {
            detectionTitle: normalizedCveId,
            OR: [
                { aliases: { contains: normalizedCveId } },
            ]
        },
        include: {
            agentInferences: {
                include: {
                    pix: true
                },
                orderBy: {
                    createdAt: 'desc'
                }
            }
        }
    })

    // Add public-vdb Finding to the list if it exists and isn't already included
    if (publicVdbFinding && !findingsWithReferences.some(f => f.uuid === publicVdbFinding.uuid)) {
        findingsWithReferences.push(publicVdbFinding as any)
    }

    // Collect agentInferences (PixLog data)
    const allAgentInferences: any[] = []

    for (const finding of findingsWithReferences) {
        // Add finding aliases
        if (finding.aliases) {
            try {
                const findingAliases = JSON.parse(finding.aliases)
                if (finding.detectionTitle !== normalizedCveId) {
                    findingAliases.push(finding.detectionTitle)
                }
                findingAliases.forEach((alias: string) => {
                    const normalizedAlias = alias.toUpperCase()
                    if (normalizedAlias && normalizedAlias !== normalizedCveId) {
                        allAliases.add(normalizedAlias)
                    }
                })
            } catch (e) {
                dependencies.logger?.warn('Failed to parse finding aliases:', e)
            }
        }

        // Add finding references
        if (finding.references && finding.references.length > 0) {
            finding.references.forEach(ref => {
                if (ref.url && !seenReferenceUrls.has(ref.url)) {
                    seenReferenceUrls.add(ref.url)

                    // Add to processing queue if not already in CVEMetadataReferences
                    referencesToProcess.push({
                        source: 'vvd',
                        url: ref.url,
                        type: ref.type,
                        title: ref.title,
                        referenceSource: ref.source || 'VVD'
                    })

                    // Categorize the URL for immediate use
                    const categorized = categorizeURL(ref.url)

                    // Extract vulnerability identifiers from the URL and extracted data
                    if (categorized.category.extractedData) {
                        const extractedData = categorized.category.extractedData

                        for (const pattern of identifierPatterns) {
                            const identifierValue = extractedData[pattern]
                            if (identifierValue && typeof identifierValue === 'string') {
                                const normalizedId = identifierValue.trim().toUpperCase()
                                // Add to temporary set if not the main CVE ID
                                if (normalizedId && normalizedId !== normalizedCveId) {
                                    extractedIdentifiers.add(normalizedId)
                                    dependencies.logger?.info(`Extracted alias from finding reference: ${normalizedId} (source: ${pattern})`)
                                }
                            }
                        }
                    }

                    allReferences.push({
                        url: ref.url,
                        name: ref.title || null,
                        tags: ref.type ? [ref.type] : [],
                        source: ref.source || 'VVD',
                        createdAt: ref.createdAt || undefined,
                        // Add URL categorization data
                        category: categorized.category.type,
                        categoryConfidence: categorized.category.confidence,
                        subcategory: categorized.category.subcategory,
                        extractedData: categorized.category.extractedData,
                        // Add ExploitDB enrichment fields from FindingReferences
                        exploitDbId: ref.exploitDbId || undefined,
                        exploitDbAuthor: ref.exploitDbAuthor || undefined,
                        exploitDbDate: ref.exploitDbDate || undefined,
                        exploitDbPlatform: ref.exploitDbPlatform || undefined,
                        exploitDbType: ref.exploitDbType || undefined,
                        exploitDbPort: ref.exploitDbPort || undefined,
                        exploitDbVerified: ref.exploitDbVerified !== null ? (ref.exploitDbVerified === 1) : undefined
                    })
                }
            })
        }

        // Add agentInferences from this finding (filter by includeAI option)
        if (includeAI && finding.agentInferences && finding.agentInferences.length > 0) {
            // Include all AI inferences from this finding
            finding.agentInferences.forEach(inference => {
                allAgentInferences.push(inference)
            })
        }
    }

    // Fetch full data for all aliases
    const aliasDataArray: any[] = []
    const aliasArray = Array.from(allAliases).sort()
    const aliasesWithoutMetadata: string[] = []

    for (const aliasId of aliasArray) {
        // Skip if it's the same as the primary CVE ID
        if (aliasId === cveId) continue

        // Get data for each alias
        const aliasMetadata = await dependencies.prisma.cVEMetadata.findFirst({
            where: { cveId: aliasId },
            include: {
                references: true
            }
        })

        if (aliasMetadata) {
            aliasDataArray.push({
                id: aliasId,
                source: aliasMetadata.source,
                title: aliasMetadata.title,
                datePublished: aliasMetadata.datePublished,
                dateUpdated: aliasMetadata.dateUpdated,
                dateReserved: aliasMetadata.dateReserved,
                vectorString: aliasMetadata.vectorString,
                cvssVersion: getCvssVersion(aliasMetadata.vectorString),
                score: calculateCvssScore(aliasMetadata.vectorString),
                affectedVendor: aliasMetadata.affectedVendor,
                affectedProduct: aliasMetadata.affectedProduct,
                referenceCount: aliasMetadata.references?.length || 0,
                hasR2Data: await checkR2DataExists(aliasId, aliasMetadata.source)
            })
        } else {
            // Track aliases without metadata for processing
            aliasesWithoutMetadata.push(aliasId)
            dependencies.logger?.info(`Alias ${aliasId} has no metadata yet, will attempt to fetch`)
        }
    }

    // Process aliases without metadata through VulnProcessor
    if (aliasesWithoutMetadata.length > 0) {
        dependencies.logger?.info(`Processing ${aliasesWithoutMetadata.length} aliases without metadata`)

        // Import VulnProcessor dynamically to avoid circular dependencies
        const { createVulnProcessor } = await import('./vulnProcessor')

        for (const aliasId of aliasesWithoutMetadata) {
            try {
                dependencies.logger?.info(`Fetching metadata for alias: ${aliasId}`)

                // Create processor with appropriate settings for each alias type
                const processor = createVulnProcessor(dependencies.prisma, {
                    enableCVEOrg: aliasId.startsWith('CVE-'),
                    enableOSV: true,
                    enableGitHubAdvisory: aliasId.startsWith('GHSA-'),
                    enableEPSS: aliasId.startsWith('CVE-'),
                    enableCESS: aliasId.startsWith('CVE-'),
                    enableEUVD: aliasId.startsWith('CVE-'),
                    enableKEV: aliasId.startsWith('CVE-'),
                    enableCrowdSec: false, // Don't fetch CrowdSec for alias enrichment
                    enableCisaVulnrichment: aliasId.startsWith('CVE-'),
                    enableNistNvd: aliasId.startsWith('CVE-'),
                    enableAnchoreADP: aliasId.startsWith('CVE-'),
                    enableGoogleOsi: false, // Disabled for aliases
                    enableAIInference: false, // Don't run AI inference for aliases
                    enableUrlCategorization: true,
                    autoSave: true,
                    forceRefresh: false, // Only fetch if doesn't exist
                    orgId: context.orgId || 'public-vdb',
                    memberId: context.memberId || 'public-vdb',
                    jwtCredentials: dependencies.jwtCredentials,
                })

                const result = await processor.process(aliasId, dependencies.logger, null)

                if (result.success) {
                    dependencies.logger?.info(`Successfully fetched metadata for ${aliasId}: sources=${result.sources.join(',')}`)

                    // Retry fetching metadata after processing
                    const aliasMetadata = await dependencies.prisma.cVEMetadata.findFirst({
                        where: { cveId: aliasId },
                        include: {
                            references: true
                        }
                    })

                    if (aliasMetadata) {
                        aliasDataArray.push({
                            id: aliasId,
                            source: aliasMetadata.source,
                            title: aliasMetadata.title,
                            datePublished: aliasMetadata.datePublished,
                            dateUpdated: aliasMetadata.dateUpdated,
                            dateReserved: aliasMetadata.dateReserved,
                            vectorString: aliasMetadata.vectorString,
                            cvssVersion: getCvssVersion(aliasMetadata.vectorString),
                            score: calculateCvssScore(aliasMetadata.vectorString),
                            affectedVendor: aliasMetadata.affectedVendor,
                            affectedProduct: aliasMetadata.affectedProduct,
                            referenceCount: aliasMetadata.references?.length || 0,
                            hasR2Data: await checkR2DataExists(aliasId, aliasMetadata.source)
                        })
                        dependencies.logger?.info(`Added ${aliasId} to aliasDataArray after processing`)
                    } else {
                        dependencies.logger?.warn(`VulnProcessor succeeded but no metadata found for ${aliasId}`)
                    }
                } else {
                    dependencies.logger?.warn(`Failed to fetch metadata for ${aliasId}: ${result.error}`)
                }
            } catch (error) {
                dependencies.logger?.error(`Error processing alias ${aliasId}:`, error)
            }
        }

        dependencies.logger?.info(`Completed processing ${aliasesWithoutMetadata.length} aliases, ${aliasDataArray.length} total aliases with data`)
    }

    // ============================================================================
    // PHASE 1: DETERMINE GCVE IDENTIFIER
    // Check if any identifier (supplied + aliases) exists in GcveIssuance/GcveAlias
    // ============================================================================
    let gcveIdentifier: string | null = null
    const allIdentifiers = [normalizedCveId, ...aliasArray]

    dependencies.logger?.info(`[GCVE Lookup] Checking ${allIdentifiers.length} identifiers for GCVE association`)

    for (const identifier of allIdentifiers) {
        // Check GcveIssuance by cveId (primary CVE → GCVE mapping)
        const gcveByPrimary = await lookupGcveId(dependencies.prisma, identifier)
        if (gcveByPrimary) {
            gcveIdentifier = gcveByPrimary.gcveId
            dependencies.logger?.info(`[GCVE Lookup] Found GCVE ${gcveIdentifier} via GcveIssuance for ${identifier}`)
            break
        }

        // Check GcveAlias by aliasCveId (alias → GCVE mapping)
        const gcveByAlias = await dependencies.prisma.gcveAlias.findFirst({
            where: { aliasCveId: identifier }
        })
        if (gcveByAlias) {
            gcveIdentifier = gcveByAlias.gcveId
            dependencies.logger?.info(`[GCVE Lookup] Found GCVE ${gcveIdentifier} via GcveAlias for ${identifier}`)
            break
        }
    }

    // Add GCVE to identifiers list if found and not already present
    if (gcveIdentifier && !allIdentifiers.includes(gcveIdentifier)) {
        allIdentifiers.push(gcveIdentifier)
        dependencies.logger?.info(`[GCVE Lookup] Added GCVE ${gcveIdentifier} to identifiers list for metadata fetch`)
    }

    // ============================================================================
    // PHASE 2: FETCH CVEMetadata FOR ALL IDENTIFIERS
    // Aggregate sources from all identifiers (supplied + aliases + GCVE)
    // ============================================================================
    const additionalSources: any[] = []
    const identifiersToFetch = allIdentifiers.filter(id => id !== normalizedCveId)

    dependencies.logger?.info(`[Multi-Identifier Fetch] Fetching CVEMetadata for ${identifiersToFetch.length} additional identifiers`)

    for (const identifier of identifiersToFetch) {
        const identifierMetadata = await dependencies.prisma.cVEMetadata.findMany({
            where: { cveId: identifier },
            include: {
                cna: true,
                fileLink: true,
                adp: {
                    include: {
                        adp: true
                    }
                },
                references: true,
                metrics: true
            }
        })

        if (identifierMetadata.length > 0) {
            dependencies.logger?.info(`[Multi-Identifier Fetch] Found ${identifierMetadata.length} source(s) for ${identifier}`)

            // Transform each CVEMetadata record to source format (same logic as line 1825-1990)
            for (const cveMetadata of identifierMetadata) {
                let affectedVersions = null
                let cpes = null

                try {
                    if (cveMetadata.affectedVersionsJSON && cveMetadata.affectedVersionsJSON !== 'null') {
                        const allVersions = JSON.parse(cveMetadata.affectedVersionsJSON)
                        if (Array.isArray(allVersions)) {
                            affectedVersions = allVersions.filter(v => v.status !== 'unaffected')
                        } else {
                            affectedVersions = allVersions
                        }
                    }
                } catch (e) {
                    dependencies.logger?.warn(`Failed to parse affectedVersionsJSON for ${cveMetadata.cveId}:`, e)
                }

                try {
                    if (cveMetadata.cpesJSON && cveMetadata.cpesJSON !== 'null') {
                        cpes = JSON.parse(cveMetadata.cpesJSON)
                    }
                } catch (e) {
                    dependencies.logger?.warn(`Failed to parse cpesJSON for ${cveMetadata.cveId}:`, e)
                }

                // Find highest CVSS score from metrics
                let highestVector = cveMetadata.vectorString
                let highestScore: number | null = null
                let highestVersion = null

                if (cveMetadata.metrics && cveMetadata.metrics.length > 0) {
                    let maxScore = -1
                    for (const metric of cveMetadata.metrics) {
                        let score = calculateCvssScore(metric.vectorString)
                        if (score === null && metric.baseScore && metric.baseScore > 0) {
                            score = metric.baseScore
                        }
                        if (score !== null && score > maxScore) {
                            maxScore = score
                            highestScore = score
                            highestVector = metric.vectorString
                            highestVersion = getCvssVersion(metric.vectorString)
                        }
                    }
                }

                if (highestScore === null && cveMetadata.vectorString) {
                    highestScore = calculateCvssScore(cveMetadata.vectorString)
                    highestVersion = getCvssVersion(cveMetadata.vectorString)
                }

                additionalSources.push({
                    source: normalizeSourceName(cveMetadata.source),
                    cveId: cveMetadata.cveId,
                    dataVersion: cveMetadata.dataVersion,
                    state: cveMetadata.state,
                    datePublished: cveMetadata.datePublished,
                    dateUpdated: cveMetadata.dateUpdated,
                    dateReserved: cveMetadata.dateReserved,
                    vectorString: highestVector,
                    cvssVersion: highestVersion,
                    score: highestScore,
                    title: cveMetadata.title,
                    sourceAdvisoryRef: cveMetadata.sourceAdvisoryRef,
                    affectedVendor: cveMetadata.affectedVendor,
                    affectedProduct: cveMetadata.affectedProduct,
                    affectedVersions: affectedVersions,
                    cpes: cpes,
                    cna: cveMetadata.cna ? {
                        shortName: cveMetadata.cna.shortName
                    } : null,
                    fileLink: cveMetadata.fileLink ? {
                        url: cveMetadata.fileLink.url,
                        contentType: cveMetadata.fileLink.contentType
                    } : null,
                    adp: cveMetadata.adp.map(adpRel => ({
                        shortName: adpRel.adp.shortName,
                        title: adpRel.adp.title
                    })),
                    lastFetchedAt: cveMetadata.lastFetchedAt,
                    fetchCount: cveMetadata.fetchCount,
                    rawDataJSON: cveMetadata.rawDataJSON
                })
            }
        } else {
            dependencies.logger?.info(`[Multi-Identifier Fetch] No CVEMetadata found for ${identifier}`)
        }
    }

    // Merge additional sources into main sources array
    if (additionalSources.length > 0) {
        sources.push(...additionalSources)
        dependencies.logger?.info(`[Multi-Identifier Fetch] Added ${additionalSources.length} source(s) from additional identifiers`)
        dependencies.logger?.info(`[Multi-Identifier Fetch] Total sources before deduplication: ${sources.length}`)
    }

    // ============================================================================
    // PHASE 3: DEDUPLICATE SOURCES BY NORMALIZED SOURCE NAME
    // Merge sources with the same normalized name to eliminate duplicates from
    // alias fetching and source name normalization collisions
    // ============================================================================
    dependencies.logger?.info(`[Source Deduplication] Deduplicating ${sources.length} sources by normalized name`)
    sources = deduplicateCVESources(sources)
    dependencies.logger?.info(`[Source Deduplication] Deduplicated to ${sources.length} unique sources`)

    // Extract and enrich package metadata from affected versions
    dependencies.logger?.info(`Extracting and enriching packages for ${normalizedCveId}`)
    const enrichedPackages = await extractAndEnrichPackages(
        sources,
        aliasDataArray,
        dependencies.prisma,
        dependencies.logger
    )
    dependencies.logger?.info(`Enriched ${enrichedPackages.length} packages for ${normalizedCveId}`)

    // Add CVSS from all aliases
    for (const alias of aliasDataArray) {
        if (alias.vectorString && alias.cvssVersion) {
            allCvssVectors.push({
                source: `${alias.source} (${alias.cveId})`,
                vectorString: alias.vectorString,
                cvssVersion: alias.cvssVersion,
                score: alias.score || calculateCvssScore(alias.vectorString),
                lastObserved: alias.dateUpdated || alias.datePublished
            })
        }
    }

    // Sort by CVSS version (highest first)
    allCvssVectors.sort((a, b) => {
        return parseFloat(b.cvssVersion) - parseFloat(a.cvssVersion)
    })

    // Process references through storeCVEMetadataReference to ensure full enrichment
    if (referencesToProcess.length > 0) {
        dependencies.logger?.info(`Processing ${referencesToProcess.length} references for enrichment`)

        for (const ref of referencesToProcess) {
            try {
                // Check if this reference needs enrichment (ExploitDB, Gist, PR, Commit)
                const needsEnrichment = ref.url.includes('exploit-db.com') ||
                    ref.url.includes('gist.github.com') ||
                    ref.url.includes('/commit/') ||
                    ref.url.includes('/pull/')

                await storeCVEMetadataReference(
                    dependencies.prisma,
                    normalizedCveId,
                    ref.source,
                    {
                        url: ref.url,
                        type: ref.type,
                        title: ref.title
                    },
                    ref.referenceSource,
                    dependencies.logger,
                    false, // Don't check HTTP status for performance
                    needsEnrichment,  // Force refresh for enrichable references to trigger enrichment
                    dependencies.jwtCredentials
                )
            } catch (error) {
                dependencies.logger?.warn(`Failed to process reference ${ref.url}:`, error)
            }
        }

        // Re-fetch references after processing to get enriched data
        if (referencesToProcess.length > 0) {
            dependencies.logger?.info('Re-fetching references after enrichment')
            const enrichedSources = await dependencies.prisma.cVEMetadata.findMany({
                where: { cveId: normalizedCveId },
                include: {
                    references: true
                }
            })

            // Update allReferences with enriched data
            const updatedReferences: any[] = []
            const updatedSeenUrls = new Set<string>()

            for (const cveMetadata of enrichedSources) {
                if (cveMetadata.references && cveMetadata.references.length > 0) {
                    cveMetadata.references.forEach(ref => {
                        if (ref.url && !updatedSeenUrls.has(ref.url)) {
                            updatedSeenUrls.add(ref.url)

                            // Categorize the URL for enhanced data
                            const categorized = categorizeURL(ref.url)

                            updatedReferences.push({
                                url: ref.url,
                                name: ref.title || null,
                                title: ref.title || null,
                                tags: ref.type ? [ref.type] : [],
                                source: ref.referenceSource,
                                // Add enrichment data from CVEMetadataReferences
                                httpStatus: ref.httpStatus || undefined,
                                deadLink: ref.deadLink || undefined,
                                deadLinkCheckedAt: ref.deadLinkCheckedAt || undefined,
                                createdAt: ref.createdAt || undefined,
                                type: ref.type,
                                // Add URL categorization data (enhanced from categorizeURL)
                                category: categorized.category.type,
                                categoryConfidence: categorized.category.confidence,
                                subcategory: categorized.category.subcategory,
                                extractedData: categorized.category.extractedData,
                                // Add GitHub PR enrichment fields
                                prDiffUrl: ref.prDiffUrl || undefined,
                                prState: ref.prState || undefined,
                                prAuthor: ref.prAuthor || undefined,
                                prLabels: ref.prLabels ? JSON.parse(ref.prLabels) : undefined,
                                prMergedAt: ref.prMergedAt || undefined,
                                prMergeCommitSha: ref.prMergeCommitSha || undefined,
                                prRepoHealth: ref.prRepoHealth ? JSON.parse(ref.prRepoHealth) : undefined,
                                // Add GitHub Commit enrichment fields
                                commitAuthorEmail: ref.commitAuthorEmail || undefined,
                                commitAuthorLogin: ref.commitAuthorLogin || undefined,
                                commitVerified: ref.commitVerified !== null ? (ref.commitVerified === 1) : undefined,
                                commitHealth: ref.commitHealth ? JSON.parse(ref.commitHealth) : undefined,
                                // Add GitHub Gist enrichment fields
                                gistId: ref.gistId || undefined,
                                gistPublic: ref.gistPublic !== null ? (ref.gistPublic === 1) : undefined,
                                gistFilesCount: ref.gistFilesCount || undefined,
                                gistFiles: ref.gistFiles ? JSON.parse(ref.gistFiles) : undefined,
                                gistComments: ref.gistComments || undefined,
                                gistUpdatedAt: ref.gistUpdatedAt || undefined,
                                // Add ExploitDB enrichment fields
                                exploitDbId: ref.exploitDbId || undefined,
                                exploitDbAuthor: ref.exploitDbAuthor || undefined,
                                exploitDbDate: ref.exploitDbDate || undefined,
                                exploitDbPlatform: ref.exploitDbPlatform || undefined,
                                exploitDbType: ref.exploitDbType || undefined,
                                exploitDbPort: ref.exploitDbPort || undefined,
                                exploitDbVerified: ref.exploitDbVerified !== null ? (ref.exploitDbVerified === 1) : undefined
                            })
                        }
                    })
                }
            }

            // Replace allReferences with enriched version
            allReferences.length = 0
            allReferences.push(...updatedReferences)
        }
    }

    // Helper to check if R2 data exists (placeholder - actual implementation would check R2)
    async function checkR2DataExists(id: string, source: string): Promise<boolean> {
        // Check based on source type
        if (id.startsWith('CVE-')) return true // CVE data likely exists
        if (id.startsWith('GHSA-')) return source === 'github' || source === 'osv'
        if (id.startsWith('PYSEC-')) return source === 'osv'
        return false
    }

    // Generate download links for all identifiers if includeFileLinks is enabled
    const downloadLinks: Record<string, any> = {}

    if (includeFileLinks) {
        // Add links for primary identifier
        const allIdentifiers = [normalizedCveId, ...aliasArray]

        for (const identifier of allIdentifiers) {
            const identifierLinks: Record<string, string> = {}

            // Determine which sources are available for this identifier
            const identifierSources = sources.filter(s => s.cveId === identifier).map(s => s.source)
            const aliasSource = aliasDataArray.find(a => a.id === identifier)?.source

            if (identifierSources.length > 0 || aliasSource) {
                const availableSources = new Set([...identifierSources, aliasSource].filter(Boolean))

                // Generate links based on available sources and identifier type
                if (identifier.startsWith('CVE-')) {
                    identifierLinks.cvelistv5 = `/api/vdb/file/${identifier}/cvelistv5.json`
                    identifierLinks.epss = `/api/vdb/file/${identifier}/epss.json`
                    identifierLinks.cess = `/api/vdb/file/${identifier}/cess.json`
                    identifierLinks.euvd = `/api/vdb/file/${identifier}/euvd.json`
                }

                if (identifier.startsWith('GHSA-')) {
                    identifierLinks.ghsa = `/api/vdb/file/${identifier}/ghsa.json`
                }

                // Always include OSV, OpenVEX, and CycloneDX as they support multiple ID types
                identifierLinks.osv = `/api/vdb/file/${identifier}/osv.json`
                identifierLinks.openvex = `/api/vdb/file/${identifier}/openvex.json`
                identifierLinks.cyclonedx = `/api/vdb/file/${identifier}/cyclonedx-vdr.json`

                downloadLinks[identifier] = identifierLinks
            }
        }
    }

    // ============================================================================
    // PHASE 3: DETERMINE SUBJECT IDENTIFIER PRIORITY
    // Priority: GCVE > CVE > supplied identifier
    // ============================================================================
    let subjectIdentifier = normalizedCveId

    if (gcveIdentifier) {
        // Priority 1: Use GCVE identifier if found
        subjectIdentifier = gcveIdentifier
        dependencies.logger?.info(`[Subject Identifier] Using GCVE identifier: ${subjectIdentifier}`)
    } else {
        // Priority 2: Use CVE identifier if found in aliases and supplied is not CVE
        const cveAlias = aliasArray.find(alias => alias.startsWith('CVE-'))
        if (cveAlias && !normalizedCveId.startsWith('CVE-')) {
            subjectIdentifier = cveAlias
            dependencies.logger?.info(`[Subject Identifier] Using CVE alias as subject: ${subjectIdentifier}`)
        } else {
            dependencies.logger?.info(`[Subject Identifier] Using supplied identifier: ${subjectIdentifier}`)
        }
    }

    const response: any = {
        cveId: subjectIdentifier,
        gcveId: gcveIdentifier || undefined,
        sources,
        cvss: {
            // All CVSS vectors from all sources (no deduplication)
            // Frontend computes distinct vectors just-in-time as needed
            all: allCvssVectors
        },
        cwes: cwes.length > 0 ? cwes : undefined,
        capecPatterns: capecPatterns.length > 0 ? capecPatterns : undefined,
        references: allReferences.length > 0 ? allReferences : undefined,
        aliases: aliasArray.length > 0 ? aliasArray : undefined,
        aliasData: aliasDataArray.length > 0 ? aliasDataArray : undefined,
        // Add download links for all identifiers and sources (if includeFileLinks enabled)
        downloadLinks: includeFileLinks ? downloadLinks : undefined,
        // Add agentInferences to _finding for VDB public page
        _finding: allAgentInferences.length > 0 ? {
            agentInferences: allAgentInferences
        } : undefined,
        // Add enriched package data from Google OSI
        packages: enrichedPackages.length > 0 ? enrichedPackages : undefined
    }

    if (cessHistory && cessHistory.length > 0) {
        const latestCess = cessHistory[0]
        response.cess = {
            current: {
                score: latestCess.score,
                percentile: latestCess.probabilityExploitUsage,
                date: latestCess.dateString,
                timelineDate: latestCess.timelineDate,
                modelVersion: latestCess.modelVersion,
                probabilityExploitUsage: latestCess.probabilityExploitUsage,
                probabilityExploitUsageVariation: latestCess.probabilityExploitUsageVariation
            },
            history: cessHistory.reverse().map(c => ({
                date: c.dateString,
                timelineDate: c.timelineDate,
                score: c.score,
                percentile: c.probabilityExploitUsage,
                probabilityExploitUsage: c.probabilityExploitUsage,
                probabilityExploitUsageVariation: c.probabilityExploitUsageVariation,
                fetchedAt: c.fetchedAt,
                modelVersion: c.modelVersion,
                latestEntry: c.latestEntry
            }))
        }
    }

    if (epssHistory && epssHistory.length > 0) {
        const latestEpss = epssHistory[0]
        response.epss = {
            current: {
                score: latestEpss.score,
                percentile: latestEpss.percentile,
                date: latestEpss.dateString,
                modelVersion: latestEpss.modelVersion
            },
            history: epssHistory.reverse().map(e => ({
                date: e.dateString,
                score: e.score,
                percentile: e.percentile,
                fetchedAt: e.fetchedAt,
                modelVersion: e.modelVersion
            }))
        }
    }

    // Fetch SSVC decisions from SSVCDecision table and SSVC metrics from CVEMetric table
    dependencies.logger?.info(`Fetching SSVC data for ${normalizedCveId}`)

    // 1. Fetch SSVC decisions from SSVCDecision table
    const ssvcDecisions = await dependencies.prisma.sSVCDecision.findMany({
        where: {
            cveId: normalizedCveId
        },
        include: {
            finding: {
                select: {
                    uuid: true,
                    detectionTitle: true,
                    orgId: true
                }
            }
        },
        orderBy: {
            timestamp: 'desc'
        }
    })

    // 2. Fetch SSVC metrics from CVEMetric table
    const ssvcMetrics = await dependencies.prisma.cVEMetric.findMany({
        where: {
            cveId: normalizedCveId,
            metricType: 'other',
            otherType: 'ssvc'
        },
        orderBy: {
            createdAt: 'desc'
        }
    })

    // Process SSVC data if found
    const ssvcData: any[] = []

    // Add SSVC decisions to response
    if (ssvcDecisions && ssvcDecisions.length > 0) {
        // Use allReferences array for on-the-fly override calculation
        const references = allReferences || []

        for (const decision of ssvcDecisions) {
            let options = {}
            let sourceData = null
            try {
                options = JSON.parse(decision.optionsJSON)
            } catch (e) {
                dependencies.logger?.warn(`Failed to parse SSVC options JSON for decision ${decision.uuid}:`, e)
            }

            // Parse sourceDataJSON to check for Vulnetix override metadata
            try {
                if (decision.sourceDataJSON) {
                    sourceData = JSON.parse(decision.sourceDataJSON)
                }
            } catch (e) {
                dependencies.logger?.warn(`Failed to parse SSVC sourceDataJSON for decision ${decision.uuid}:`, e)
            }

            // If no override metadata exists but we have references, calculate it on-the-fly
            let vulnetixOverride = sourceData?.vulnetixOverride
            if (!vulnetixOverride && references.length > 0 && decision.source === 'CISA_ADP') {
                try {
                    // Import the override logic (will be tree-shaken if not used)
                    const { applyVulnetixOverride } = await import('@shared/ssvc-exploit-detector')

                    const referenceData = references.map((ref: any) => ({
                        url: ref.url,
                        type: ref.type,
                        subcategory: undefined,
                        referenceSource: ref.referenceSource,
                        title: ref.title
                    }))

                    const overrideResult = applyVulnetixOverride(options, referenceData)

                    if (overrideResult.wasOverridden) {
                        vulnetixOverride = {
                            wasOverridden: true,
                            originalExploitation: options.Exploitation || options.exploitation,
                            overriddenExploitation: overrideResult.options.Exploitation || overrideResult.options.exploitation,
                            reason: overrideResult.overrideReason,
                            sources: overrideResult.overrideSources,
                            calculatedOnTheFly: true // Flag to indicate this was calculated during buildCVEData
                        }

                        // Update options with overridden values
                        options = overrideResult.options

                        dependencies.logger?.info(`[buildCVEData] Applied on-the-fly Vulnetix override for ${normalizedCveId}: ${vulnetixOverride.originalExploitation} → ${vulnetixOverride.overriddenExploitation}`)
                    }
                } catch (error) {
                    dependencies.logger?.warn(`Failed to apply on-the-fly SSVC override for ${normalizedCveId}:`, error)
                }
            }

            ssvcData.push({
                type: 'decision',
                source: decision.source,
                methodology: decision.methodology,
                methodologyVersion: decision.methodologyVer,
                decisionOutcome: decision.decisionOutcome,
                priority: decision.priority,
                options,
                timestamp: decision.timestamp,
                findingUuid: decision.findingUuid,
                orgId: decision.finding?.orgId,
                // Include Vulnetix override metadata if present
                vulnetixOverride
            })
        }
    }

    // Add SSVC metrics to response
    if (ssvcMetrics && ssvcMetrics.length > 0) {
        // Use allReferences array for on-the-fly override calculation
        const references = allReferences || []

        for (const metric of ssvcMetrics) {
            let content: any = {}
            try {
                if (metric.otherContent) {
                    content = JSON.parse(metric.otherContent)
                }
            } catch (e) {
                dependencies.logger?.warn(`Failed to parse SSVC metric content for ${metric.uuid}:`, e)
            }

            // Check if this is a CISA SSVC metric and if we should apply override
            let vulnetixOverride = null
            if (references.length > 0 &&
                content.options &&
                (metric.adpOrgId === '134c704f-9b21-4f2e-91b3-4a467353bcc0' || content.role?.includes('CISA'))) {
                try {
                    // Import the override logic
                    const { applyVulnetixOverride } = await import('@shared/ssvc-exploit-detector')

                    // Convert options array to object format
                    const optionsObj: Record<string, string> = {}
                    if (Array.isArray(content.options)) {
                        for (const opt of content.options) {
                            const key = Object.keys(opt)[0]
                            optionsObj[key] = opt[key]
                        }
                    }

                    const referenceData = references.map((ref: any) => ({
                        url: ref.url,
                        type: ref.type,
                        subcategory: undefined,
                        referenceSource: ref.referenceSource,
                        title: ref.title
                    }))

                    const overrideResult = applyVulnetixOverride(optionsObj, referenceData)

                    if (overrideResult.wasOverridden) {
                        vulnetixOverride = {
                            wasOverridden: true,
                            originalExploitation: optionsObj.Exploitation || optionsObj.exploitation,
                            overriddenExploitation: overrideResult.options.Exploitation || overrideResult.options.exploitation,
                            reason: overrideResult.overrideReason,
                            sources: overrideResult.overrideSources,
                            calculatedOnTheFly: true
                        }

                        // Update content.options with overridden values
                        const updatedOptions = []
                        for (const [key, value] of Object.entries(overrideResult.options)) {
                            updatedOptions.push({ [key]: value })
                        }
                        content.options = updatedOptions

                        dependencies.logger?.info(`[buildCVEData] Applied on-the-fly Vulnetix override to SSVC metric for ${normalizedCveId}: ${vulnetixOverride.originalExploitation} → ${vulnetixOverride.overriddenExploitation}`)
                    }
                } catch (error) {
                    dependencies.logger?.warn(`Failed to apply on-the-fly SSVC override to metric for ${normalizedCveId}:`, error)
                }
            }

            ssvcData.push({
                type: 'metric',
                source: metric.source,
                containerType: metric.containerType,
                adpOrgId: metric.adpOrgId,
                content,
                createdAt: metric.createdAt,
                // Include Vulnetix override metadata if present
                vulnetixOverride
            })
        }
    }

    // Deduplicate SSVC data (same SSVC from multiple sources)
    // Priority: decision > metric, and prefer entries with override data
    if (ssvcData.length > 0) {
        const deduplicatedSsvc: any[] = []
        const seenKeys = new Set<string>()

        // Sort to prioritize: 1) decisions over metrics, 2) entries with override, 3) newer entries
        const sortedSsvc = ssvcData.sort((a, b) => {
            // Prioritize decisions over metrics
            if (a.type === 'decision' && b.type === 'metric') return -1
            if (a.type === 'metric' && b.type === 'decision') return 1

            // Prioritize entries with override
            if (a.vulnetixOverride && !b.vulnetixOverride) return -1
            if (!a.vulnetixOverride && b.vulnetixOverride) return 1

            // Prioritize newer entries
            const aTime = a.timestamp || a.createdAt || 0
            const bTime = b.timestamp || b.createdAt || 0
            return bTime - aTime
        })

        for (const entry of sortedSsvc) {
            // Create a unique key based on methodology and role
            let key = ''
            if (entry.type === 'decision') {
                key = `${entry.methodology}_${entry.source}`
            } else if (entry.type === 'metric') {
                const role = entry.content?.role || 'unknown'
                const adpOrgId = entry.adpOrgId || 'unknown'
                key = `${role}_${adpOrgId}`
            }

            // Only add if we haven't seen this SSVC variant before
            if (key && !seenKeys.has(key)) {
                seenKeys.add(key)
                deduplicatedSsvc.push(entry)
            }
        }

        response.ssvc = deduplicatedSsvc
        dependencies.logger?.info(`Found ${ssvcData.length} SSVC entries, deduplicated to ${deduplicatedSsvc.length} for ${normalizedCveId}`)
    }

    // Fetch CrowdSec Threat Intelligence for all identifiers (CVE + aliases)
    dependencies.logger?.info(`Fetching CrowdSec threat intelligence for ${normalizedCveId} and ${aliasArray.length} aliases`)

    const crowdSecSightings = await dependencies.prisma.crowdSecSighting.findMany({
        where: {
            cveId: { in: allIdentifiers }
        },
        include: {
            crowdSecLog: {
                select: {
                    uuid: true,
                    createdAt: true,
                    url: true,
                    totalItems: true
                }
            }
        },
        orderBy: [
            { crowdSecLog: { createdAt: 'desc' } },
            { createdAt: 'desc' }
        ]
    })

    if (crowdSecSightings && crowdSecSightings.length > 0) {
        dependencies.logger?.info(`Found ${crowdSecSightings.length} CrowdSec sightings`)

        // Group sightings by crowdSecLogUuid to create snapshots
        const snapshotMap = new Map<string, any>()

        for (const sighting of crowdSecSightings) {
            const logUuid = sighting.crowdSecLogUuid

            if (!snapshotMap.has(logUuid)) {
                snapshotMap.set(logUuid, {
                    logUuid,
                    createdAt: sighting.crowdSecLog.createdAt,
                    cveId: sighting.cveId,
                    url: sighting.crowdSecLog.url,
                    totalSightings: 0,
                    uniqueIPs: new Set<string>(),
                    uniqueCountries: new Set<string>(),
                    sightings: [],
                    // Accumulators for averages
                    scoreLastMonthAgg: { aggressiveness: 0, threat: 0, trust: 0, count: 0 },
                    scoreLastWeekAgg: { aggressiveness: 0, threat: 0, trust: 0, count: 0 },
                    scoreLastDayAgg: { aggressiveness: 0, threat: 0, trust: 0, count: 0 },
                    // Tracking for top items
                    behaviorsCount: new Map<string, number>(),
                    mitreTechniquesCount: new Map<string, number>(),
                    countriesCount: new Map<string, number>(),
                    reputationCounts: { malicious: 0, suspicious: 0, known: 0, safe: 0, unknown: 0 }
                })
            }

            const snapshot = snapshotMap.get(logUuid)!
            snapshot.totalSightings++
            snapshot.uniqueIPs.add(sighting.ip)

            if (sighting.locationCountry) {
                snapshot.uniqueCountries.add(sighting.locationCountry)
                const count = snapshot.countriesCount.get(sighting.locationCountry) || 0
                snapshot.countriesCount.set(sighting.locationCountry, count + 1)
            }

            // Aggregate scores
            if (sighting.scoreLastMonthAggressiveness !== null || sighting.scoreLastMonthThreat !== null || sighting.scoreLastMonthTrust !== null) {
                snapshot.scoreLastMonthAgg.aggressiveness += sighting.scoreLastMonthAggressiveness || 0
                snapshot.scoreLastMonthAgg.threat += sighting.scoreLastMonthThreat || 0
                snapshot.scoreLastMonthAgg.trust += sighting.scoreLastMonthTrust || 0
                snapshot.scoreLastMonthAgg.count++
            }

            if (sighting.scoreLastWeekAggressiveness !== null || sighting.scoreLastWeekThreat !== null || sighting.scoreLastWeekTrust !== null) {
                snapshot.scoreLastWeekAgg.aggressiveness += sighting.scoreLastWeekAggressiveness || 0
                snapshot.scoreLastWeekAgg.threat += sighting.scoreLastWeekThreat || 0
                snapshot.scoreLastWeekAgg.trust += sighting.scoreLastWeekTrust || 0
                snapshot.scoreLastWeekAgg.count++
            }

            if (sighting.scoreLastDayAggressiveness !== null || sighting.scoreLastDayThreat !== null || sighting.scoreLastDayTrust !== null) {
                snapshot.scoreLastDayAgg.aggressiveness += sighting.scoreLastDayAggressiveness || 0
                snapshot.scoreLastDayAgg.threat += sighting.scoreLastDayThreat || 0
                snapshot.scoreLastDayAgg.trust += sighting.scoreLastDayTrust || 0
                snapshot.scoreLastDayAgg.count++
            }

            // Count behaviors
            if (sighting.behaviorsCsv) {
                const behaviors = sighting.behaviorsCsv.split(',').filter(b => b.trim())
                for (const behavior of behaviors) {
                    const count = snapshot.behaviorsCount.get(behavior) || 0
                    snapshot.behaviorsCount.set(behavior, count + 1)
                }
            }

            // Count MITRE techniques
            if (sighting.mitreTechniquesCsv) {
                const techniques = sighting.mitreTechniquesCsv.split(',').filter(t => t.trim())
                for (const technique of techniques) {
                    const count = snapshot.mitreTechniquesCount.get(technique) || 0
                    snapshot.mitreTechniquesCount.set(technique, count + 1)
                }
            }

            // Count reputation
            if (sighting.reputation) {
                const rep = sighting.reputation.toLowerCase()
                if (rep.includes('malicious')) {
                    snapshot.reputationCounts.malicious++
                } else if (rep.includes('suspicious')) {
                    snapshot.reputationCounts.suspicious++
                } else if (rep.includes('known')) {
                    snapshot.reputationCounts.known++
                } else if (rep.includes('safe')) {
                    snapshot.reputationCounts.safe++
                } else {
                    snapshot.reputationCounts.unknown++
                }
            }

            // Add full sighting data
            snapshot.sightings.push({
                uuid: sighting.uuid,
                cveId: sighting.cveId,
                ip: sighting.ip,
                reputation: sighting.reputation,
                confidence: sighting.confidence,
                backgroundNoiseScore: sighting.backgroundNoiseScore,
                asName: sighting.asName,
                asNum: sighting.asNum,
                ipRange24: sighting.ipRange24,
                ipRange24Reputation: sighting.ipRange24Reputation,
                ipRange24Score: sighting.ipRange24Score,
                locationCountry: sighting.locationCountry,
                locationCity: sighting.locationCity,
                locationLat: sighting.locationLat,
                locationLon: sighting.locationLon,
                reverseDns: sighting.reverseDns,
                behaviorsCsv: sighting.behaviorsCsv,
                attackDetailsCsv: sighting.attackDetailsCsv,
                classificationsCsv: sighting.classificationsCsv,
                mitreTechniquesCsv: sighting.mitreTechniquesCsv,
                targetCountriesJSON: sighting.targetCountriesJSON,
                firstSeen: sighting.firstSeen,
                lastSeen: sighting.lastSeen,
                falsePositivesCount: sighting.falsePositivesCount,
                scoreLastDayAggressiveness: sighting.scoreLastDayAggressiveness,
                scoreLastDayThreat: sighting.scoreLastDayThreat,
                scoreLastDayTrust: sighting.scoreLastDayTrust,
                scoreLastWeekAggressiveness: sighting.scoreLastWeekAggressiveness,
                scoreLastWeekThreat: sighting.scoreLastWeekThreat,
                scoreLastWeekTrust: sighting.scoreLastWeekTrust,
                scoreLastMonthAggressiveness: sighting.scoreLastMonthAggressiveness,
                scoreLastMonthThreat: sighting.scoreLastMonthThreat,
                scoreLastMonthTrust: sighting.scoreLastMonthTrust,
                createdAt: sighting.createdAt,
                updatedAt: sighting.updatedAt
            })
        }

        // Convert snapshots to final format with aggregates
        const snapshots = Array.from(snapshotMap.values()).map(snapshot => {
            // Calculate averages
            const avgScoreLastMonth = snapshot.scoreLastMonthAgg.count > 0 ? {
                aggressiveness: Math.round(snapshot.scoreLastMonthAgg.aggressiveness / snapshot.scoreLastMonthAgg.count),
                threat: Math.round(snapshot.scoreLastMonthAgg.threat / snapshot.scoreLastMonthAgg.count),
                trust: Math.round(snapshot.scoreLastMonthAgg.trust / snapshot.scoreLastMonthAgg.count)
            } : null

            const avgScoreLastWeek = snapshot.scoreLastWeekAgg.count > 0 ? {
                aggressiveness: Math.round(snapshot.scoreLastWeekAgg.aggressiveness / snapshot.scoreLastWeekAgg.count),
                threat: Math.round(snapshot.scoreLastWeekAgg.threat / snapshot.scoreLastWeekAgg.count),
                trust: Math.round(snapshot.scoreLastWeekAgg.trust / snapshot.scoreLastWeekAgg.count)
            } : null

            const avgScoreLastDay = snapshot.scoreLastDayAgg.count > 0 ? {
                aggressiveness: Math.round(snapshot.scoreLastDayAgg.aggressiveness / snapshot.scoreLastDayAgg.count),
                threat: Math.round(snapshot.scoreLastDayAgg.threat / snapshot.scoreLastDayAgg.count),
                trust: Math.round(snapshot.scoreLastDayAgg.trust / snapshot.scoreLastDayAgg.count)
            } : null

            // Get top behaviors
            const topBehaviors = Array.from(snapshot.behaviorsCount.entries())
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([name, count]) => ({ name, count }))

            // Get top MITRE techniques
            const topMitreTechniques = Array.from(snapshot.mitreTechniquesCount.entries())
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([id, count]) => ({ id, count }))

            // Get top countries
            const topCountries = Array.from(snapshot.countriesCount.entries())
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([code, count]) => ({ code, count }))

            return {
                logUuid: snapshot.logUuid,
                createdAt: snapshot.createdAt,
                cveId: snapshot.cveId,
                url: snapshot.url,
                totalSightings: snapshot.totalSightings,
                uniqueIPs: snapshot.uniqueIPs.size,
                uniqueCountries: snapshot.uniqueCountries.size,
                sightings: snapshot.sightings,
                aggregates: {
                    avgScoreLastMonth,
                    avgScoreLastWeek,
                    avgScoreLastDay,
                    topBehaviors,
                    topMitreTechniques,
                    topCountries,
                    reputationBreakdown: snapshot.reputationCounts
                }
            }
        })

        // Sort snapshots by createdAt desc (most recent first)
        snapshots.sort((a, b) => b.createdAt - a.createdAt)

        // Aggregate stats for card generator
        let aggregatedTotalSightings = 0
        let earliestFirstSeen: number | undefined = undefined

        for (const snapshot of snapshots) {
            aggregatedTotalSightings += snapshot.totalSightings
            for (const sighting of snapshot.sightings) {
                if (sighting.firstSeen) {
                    if (!earliestFirstSeen || sighting.firstSeen < earliestFirstSeen) {
                        earliestFirstSeen = sighting.firstSeen
                    }
                }
            }
        }

        response.crowdsec = {
            snapshots,
            latestSnapshot: snapshots.length > 0 ? snapshots[0].createdAt : null,
            totalSnapshots: snapshots.length,
            totalSightings: aggregatedTotalSightings,
            firstSeen: earliestFirstSeen
        }

        dependencies.logger?.info(`Built ${snapshots.length} CrowdSec snapshots with ${aggregatedTotalSightings} total sightings for ${normalizedCveId}`)
    }

    let kevData = null
    // Fetch KEV data (CISA Known Exploited Vulnerabilities)
    if (normalizedCveId.startsWith('CVE-')) {
        kevData = await dependencies.prisma.kev.findFirst({
            where: {
                cveID: normalizedCveId,
                source: `CISA`
            }
        })

        if (kevData) {
            response.kev = {
                cveID: kevData.cveID,
                source: kevData.source,
                vendorProject: kevData.vendorProject,
                product: kevData.product,
                vulnerabilityName: kevData.vulnerabilityName,
                dateAdded: kevData.dateAdded,
                shortDescription: kevData.shortDescription,
                requiredAction: kevData.requiredAction,
                dueDate: kevData.dueDate,
                knownRansomwareCampaignUse: kevData.knownRansomwareCampaignUse,
                notes: kevData.notes,
                cwes: kevData.cwesJSON ? JSON.parse(kevData.cwesJSON) : undefined,
                catalogVersion: kevData.catalogVersion,
                catalogReleaseDate: kevData.catalogReleaseDate
            }
        }
    }

    // Fetch VulnCheck KEV data with XDB exploits and reported exploitations
    let vulnCheckKevData: any[] = []
    if (normalizedCveId.startsWith('CVE-')) {
        const vulnCheckKevRecords = await dependencies.prisma.vulnCheckKEVCVE.findMany({
            where: {
                cveId: normalizedCveId
            },
            include: {
                kev: {
                    include: {
                        xdbExploits: true,
                        reportedExploitations: true
                    }
                }
            }
        })

        vulnCheckKevData = vulnCheckKevRecords.map(record => ({
            uuid: record.kev.uuid,
            vendorProject: record.kev.vendorProject,
            product: record.kev.product,
            shortDescription: record.kev.shortDescription,
            vulnerabilityName: record.kev.vulnerabilityName,
            requiredAction: record.kev.requiredAction,
            knownRansomwareCampaignUse: record.kev.knownRansomwareCampaignUse,
            reportedExploitedByVulnCheckCanaries: record.kev.reportedExploitedByVulnCheckCanaries,
            dateAdded: record.kev.dateAdded,
            xdbExploits: record.kev.xdbExploits.map(xdb => ({
                xdbId: xdb.xdbId,
                xdbUrl: xdb.xdbUrl,
                dateAdded: xdb.dateAdded,
                exploitType: xdb.exploitType,
                cloneSshUrl: xdb.cloneSshUrl
            })),
            reportedExploitations: record.kev.reportedExploitations.map(exp => ({
                url: exp.url,
                dateAdded: exp.dateAdded
            }))
        }))

        if (vulnCheckKevData.length > 0) {
            response.vulnCheckKev = vulnCheckKevData
            dependencies.logger?.info(`Found ${vulnCheckKevData.length} VulnCheck KEV records for ${normalizedCveId}`)
        }
    }

    if (kevData) {

        // KEV Data Enrichment: Fill gaps in CVE data with KEV information

        // 1. Merge KEV CWEs with existing CWEs (as distinct Set)
        if (kevData.cwesJSON) {
            try {
                const kevCwes = JSON.parse(kevData.cwesJSON)
                if (Array.isArray(kevCwes)) {
                    for (const kevCweId of kevCwes) {
                        if (!seenCweIds.has(kevCweId)) {
                            seenCweIds.add(kevCweId)
                            cwes.push({
                                cweId: kevCweId,
                                description: `From CISA KEV`,
                                descriptionType: 'text',
                                containerType: 'kev',
                                adpOrgId: null,
                                source: 'CISA',
                                lang: 'en'
                            })
                        }
                    }
                    // Update response with merged CWEs
                    response.cwes = cwes.length > 0 ? cwes : undefined
                }
            } catch (e) {
                dependencies.logger?.warn('Failed to parse KEV cwesJSON:', e)
            }
        }

        // 2. Fill missing vendor/product in sources from KEV data
        for (const source of sources) {
            // Use KEV vendorProject if product is missing
            if (!source.affectedProduct && kevData.product) {
                source.affectedProduct = kevData.product
            }
            // Use KEV vendor if vendor is missing
            if (!source.affectedVendor && kevData.vendorProject) {
                // Extract vendor from vendorProject (format: "vendor_project")
                source.affectedVendor = kevData.vendorProject.replaceAll('_', '')
            }
            // Use KEV shortDescription if title is empty
            if (!source.title && kevData.shortDescription) {
                source.title = kevData.shortDescription
            }
        }
    }

    // Fetch VulnCheck KEV data with XDB exploits and reported exploitations
    dependencies.logger?.info(`Fetching VulnCheck KEV data for ${normalizedCveId}`)
    const vulnCheckKevCves = await dependencies.prisma.vulnCheckKEVCVE.findMany({
        where: {
            cveId: normalizedCveId
        },
        include: {
            kev: {
                include: {
                    xdbExploits: true,
                    reportedExploitations: true,
                    cwes: true
                }
            }
        }
    })

    if (vulnCheckKevCves && vulnCheckKevCves.length > 0) {
        dependencies.logger?.info(`Found ${vulnCheckKevCves.length} VulnCheck KEV entries for ${normalizedCveId}`)

        // Deduplicate by kevUuid (multiple CVEs may link to same KEV entry)
        const uniqueKevMap = new Map<string, any>()

        for (const kevCve of vulnCheckKevCves) {
            if (kevCve.kev && !uniqueKevMap.has(kevCve.kevUuid)) {
                const kev = kevCve.kev

                uniqueKevMap.set(kevCve.kevUuid, {
                    uuid: kev.uuid,
                    vendorProject: kev.vendorProject,
                    product: kev.product,
                    shortDescription: kev.shortDescription,
                    vulnerabilityName: kev.vulnerabilityName,
                    requiredAction: kev.requiredAction,
                    knownRansomwareCampaignUse: kev.knownRansomwareCampaignUse,
                    reportedExploitedByVulnCheckCanaries: kev.reportedExploitedByVulnCheckCanaries,
                    dateAdded: kev.dateAdded,
                    createdAt: kev.createdAt,
                    // XDB Exploits
                    xdbExploits: kev.xdbExploits.map(xdb => ({
                        uuid: xdb.uuid,
                        xdbId: xdb.xdbId,
                        xdbUrl: xdb.xdbUrl,
                        dateAdded: xdb.dateAdded,
                        exploitType: xdb.exploitType,
                        cloneSshUrl: xdb.cloneSshUrl,
                        createdAt: xdb.createdAt
                    })),
                    // Reported Exploitations
                    reportedExploitations: kev.reportedExploitations.map(rep => ({
                        uuid: rep.uuid,
                        url: rep.url,
                        dateAdded: rep.dateAdded,
                        createdAt: rep.createdAt
                    })),
                    // CWE Mappings
                    cweMappings: kev.cwes.map(cweMapping => ({
                        uuid: cweMapping.uuid,
                        cweId: cweMapping.cweId
                    }))
                })
            }
        }

        // Convert map to array and add to response
        const vulnCheckKevArray = Array.from(uniqueKevMap.values())

        if (vulnCheckKevArray.length > 0) {
            response.vulnCheckKev = {
                entries: vulnCheckKevArray,
                totalEntries: vulnCheckKevArray.length
            }

            dependencies.logger?.info(`Added ${vulnCheckKevArray.length} VulnCheck KEV entries with ${vulnCheckKevArray.reduce((sum, k) => sum + k.xdbExploits.length, 0)} XDB exploits and ${vulnCheckKevArray.reduce((sum, k) => sum + k.reportedExploitations.length, 0)} reported exploitations`)
        }
    } else {
        dependencies.logger?.info(`No VulnCheck KEV data found for ${normalizedCveId}`)
        // Generate patch intelligence without KEV data
        dependencies.logger?.info(`Generating patch intelligence for ${normalizedCveId} (no KEV check)`)
        const patchIntel = await generatePatchIntelligence(
            sources,
            aliasDataArray,
            null,
            cwes,
            allAgentInferences,
            allReferences,
            dependencies.logger,
            dependencies,
            normalizedCveId
        )

        // Add patch intelligence to response
        response.patchIntelligence = patchIntel

        dependencies.logger?.info(`Patch intelligence for ${normalizedCveId}: hasPatch=${patchIntel.hasPatch}, sources=[${patchIntel.sources.join(', ')}]`)
    }

    // Generate patch intelligence AFTER KEV data is processed
    dependencies.logger?.info(`Generating patch intelligence for ${normalizedCveId}`)
    const patchIntel = await generatePatchIntelligence(
        sources,
        aliasDataArray,
        kevData || null,
        cwes,
        allAgentInferences,
        allReferences,
        dependencies.logger,
        dependencies,
        normalizedCveId
    )

    // Add patch intelligence to response
    response.patchIntelligence = patchIntel

    dependencies.logger?.info(`Patch intelligence for ${normalizedCveId}: hasPatch=${patchIntel.hasPatch}, sources=[${patchIntel.sources.join(', ')}]`)

    // Fetch ALL OpenSSF Scorecard data for all affected packages (BEFORE timeline so we can include history)
    dependencies.logger?.info(`Fetching OpenSSF Scorecards for ${normalizedCveId}`)
    const allScorecardData = await dependencies.prisma.cVEMetadata.findMany({
        where: {
            cveId: normalizedCveId,
            scorecardUuid: { not: null }
        },
        include: {
            scorecard: {
                include: {
                    checks: true
                }
            }
        },
        orderBy: {
            dateUpdated: `desc`
        }
    })

    if (allScorecardData && allScorecardData.length > 0) {
        const uniqueScorecards = new Map<string, any>()
        const repositoryIds = new Set<number>()

        // Deduplicate scorecards by UUID (multiple CVE sources might link to same scorecard)
        for (const data of allScorecardData) {
            if (data.scorecard && !uniqueScorecards.has(data.scorecard.uuid)) {
                const scorecard = data.scorecard

                // Track repository IDs for history fetching
                if (scorecard.githubRepositoryId) {
                    repositoryIds.add(scorecard.githubRepositoryId)
                }

                uniqueScorecards.set(scorecard.uuid, {
                    uuid: scorecard.uuid,
                    date: scorecard.date,
                    githubRepositoryId: scorecard.githubRepositoryId,
                    repository: {
                        name: scorecard.repositoryName,
                        commit: scorecard.repositoryCommit
                    },
                    scorecard: {
                        version: scorecard.scorecardVersion,
                        commit: scorecard.scorecardCommit
                    },
                    overallScore: scorecard.overallScore,
                    metadata: scorecard.metadata ? JSON.parse(scorecard.metadata) : [],
                    checks: scorecard.checks.map(check => ({
                        name: check.name,
                        documentation: {
                            shortDescription: check.shortDescription,
                            url: check.documentationUrl
                        },
                        score: check.score,
                        reason: check.reason,
                        details: check.details ? JSON.parse(check.details) : []
                    })),
                    createdAt: scorecard.createdAt
                })
            }
        }

        // Fetch scorecard history for each repository
        dependencies.logger?.info(`Fetching scorecard history for ${repositoryIds.size} repositories`)
        const scorecardHistoryMap = new Map<number, any[]>()

        for (const repoId of Array.from(repositoryIds)) {
            try {
                const allScorecards = await dependencies.prisma.openSSFScorecard.findMany({
                    where: {
                        githubRepositoryId: repoId
                    },
                    include: {
                        checks: true
                    },
                    orderBy: {
                        date: `asc` // Ascending order for history
                    }
                })

                // Process scorecard history: aggregate by day and calculate failing checks
                const historyByDay = new Map<string, { score: number; failingCount: number; date: string }>()

                for (const historyScorecard of allScorecards) {
                    // Convert Unix timestamp to YYYY-MM-DD format
                    const dateObj = new Date(historyScorecard.date * 1000)
                    const dateString = dateObj.toISOString().split(`T`)[0] // YYYY-MM-DD

                    // Count failing checks (score < 4)
                    const failingCount = historyScorecard.checks.filter(check => check.score >= 0 && check.score < 4).length

                    // Only keep one entry per day (the latest for that day)
                    historyByDay.set(dateString, {
                        score: historyScorecard.overallScore,
                        failingCount,
                        date: dateString
                    })
                }

                // Convert to array and store in map
                const historyArray = Array.from(historyByDay.values()).sort((a, b) =>
                    a.date.localeCompare(b.date) // Sort by date ascending
                )

                scorecardHistoryMap.set(repoId, historyArray)
                dependencies.logger?.debug(`Found ${historyArray.length} history datapoints for repository ${repoId}`)
            } catch (error) {
                dependencies.logger?.error(`Failed to fetch scorecard history for repository ${repoId}:`, error)
            }
        }

        // Attach history to each scorecard
        const scorecardsWithHistory = Array.from(uniqueScorecards.values()).map(scorecard => {
            const history = scorecard.githubRepositoryId
                ? scorecardHistoryMap.get(scorecard.githubRepositoryId) || []
                : []

            return {
                ...scorecard,
                history
            }
        })

        response.scorecards = scorecardsWithHistory
        dependencies.logger?.info(`Found ${response.scorecards.length} unique OpenSSF Scorecard(s) with history for ${normalizedCveId}`)
    } else {
        response.scorecards = []
        dependencies.logger?.info(`No OpenSSF Scorecards found for ${normalizedCveId}`)
    }

    // Fetch GitHub repositories linked to this CVE through affected packages
    dependencies.logger?.info(`Fetching GitHub repositories and dependency trees for ${normalizedCveId}`)
    const affectedPackages = await dependencies.prisma.cVEAffected.findMany({
        where: {
            cveId: normalizedCveId,
            OR: [
                { packageName: { not: null } },
                { repo: { not: null } }
            ]
        },
        select: {
            uuid: true,
            packageName: true,
            repo: true,
            vendor: true,
            product: true,
            containerType: true,
            adpOrgId: true,
            modules: true,
            programFiles: true,
            programRoutines: true,
            platforms: true,
            collectionURL: true
        }
    })

    const githubRepositories: any[] = []
    const processedRepoIds = new Set<number>()

    for (const affected of affectedPackages) {
        // Try to find GitHub repository by repo URL or package name
        const repoQueries: any[] = []

        if (affected.repo) {
            // Extract owner/repo from URL
            const repoMatch = affected.repo.match(/github\.com[/:]([\w-]+)\/([\w.-]+?)(?:\.git)?(?:\/|$)/)
            if (repoMatch) {
                const [, owner, repo] = repoMatch
                repoQueries.push({ fullName: `${owner}/${repo}` })
            }
        }

        if (affected.packageName && repoQueries.length === 0) {
            // Try to find by package name in repository name
            repoQueries.push({
                name: { contains: affected.packageName, mode: 'insensitive' }
            })
        }

        if (repoQueries.length > 0) {
            try {
                const repos = await dependencies.prisma.gitHubRepository.findMany({
                    where: {
                        OR: repoQueries
                    },
                    include: {
                        githubUser: true,
                        githubOrganization: true,
                        languages: {
                            include: {
                                language: true
                            }
                        },
                        // Note: 'topics' is a scalar JSON field, not a relation
                        openssfScorecards: {
                            orderBy: {
                                date: 'desc'
                            },
                            take: 1
                        },
                        dependencies: {
                            include: {
                                dependency: {
                                    include: {
                                        dependencies: {
                                            include: {
                                                dependency: true
                                            }
                                        },
                                        childOf: true
                                    }
                                }
                            },
                            orderBy: {
                                detectedAt: 'desc'
                            }
                        }
                    },
                    take: 5 // Limit to 5 repositories per affected package to avoid explosion
                })

                for (const repo of repos) {
                    if (processedRepoIds.has(repo.id)) continue
                    processedRepoIds.add(repo.id)

                    // Build dependency tree (2 levels deep)
                    const dependencyTree: any[] = []
                    const processedDeps = new Set<string>()

                    for (const repoDep of repo.dependencies) {
                        const dep = repoDep.dependency
                        if (processedDeps.has(dep.key)) continue
                        processedDeps.add(dep.key)

                        const node: any = {
                            key: dep.key,
                            name: dep.name,
                            version: dep.version,
                            license: dep.license,
                            packageEcosystem: dep.packageEcosystem,
                            isDirect: repoDep.isDirect === 1,
                            isTransitive: repoDep.isTransitive === 1,
                            isDev: repoDep.isDev === 1,
                            manifestFile: repoDep.manifestFile,
                            scope: repoDep.scope,
                            detectedAt: repoDep.detectedAt,
                            children: []
                        }

                        // Add second level dependencies
                        for (const childRel of dep.dependencies) {
                            if (childRel.dependency && !processedDeps.has(childRel.dependency.key)) {
                                node.children.push({
                                    key: childRel.dependency.key,
                                    name: childRel.dependency.name,
                                    version: childRel.dependency.version,
                                    license: childRel.dependency.license,
                                    packageEcosystem: childRel.dependency.packageEcosystem
                                })
                            }
                        }

                        dependencyTree.push(node)
                    }

                    githubRepositories.push({
                        id: repo.id,
                        name: repo.name,
                        fullName: repo.fullName,
                        description: repo.description,
                        htmlUrl: repo.htmlUrl,
                        private: repo.private,
                        fork: repo.fork,
                        archived: repo.archived,
                        disabled: repo.disabled,
                        owner: repo.ownerType === 'User' ? {
                            type: 'User',
                            login: repo.githubUser?.login,
                            avatarUrl: repo.githubUser?.avatarUrl,
                            htmlUrl: repo.githubUser?.htmlUrl
                        } : {
                            type: 'Organization',
                            login: repo.githubOrganization?.login,
                            avatarUrl: repo.githubOrganization?.avatarUrl,
                            htmlUrl: repo.githubOrganization?.htmlUrl
                        },
                        languages: repo.languages.map(l => ({
                            name: l.language.displayName,
                            bytesOfCode: l.bytesOfCode,
                            percentage: l.percentage
                        })),
                        topics: repo.topics.map(t => t.topic.name),
                        stars: repo.stargazersCount,
                        watchers: repo.watchersCount,
                        forks: repo.forksCount,
                        openIssues: repo.openIssuesCount,
                        defaultBranch: repo.defaultBranch,
                        license: repo.license,
                        visibility: repo.visibility,
                        createdAt: repo.createdAt,
                        updatedAt: repo.updatedAt,
                        pushedAt: repo.pushedAt,
                        scorecard: repo.openssfScorecards[0] ? {
                            overallScore: repo.openssfScorecards[0].overallScore,
                            date: repo.openssfScorecards[0].date
                        } : null,
                        affectedPackage: {
                            packageName: affected.packageName,
                            vendor: affected.vendor,
                            product: affected.product,
                            containerType: affected.containerType,
                            adpOrgId: affected.adpOrgId,
                            modules: affected.modules ? JSON.parse(affected.modules) : null,
                            programFiles: affected.programFiles ? JSON.parse(affected.programFiles) : null,
                            programRoutines: affected.programRoutines ? JSON.parse(affected.programRoutines) : null,
                            platforms: affected.platforms ? JSON.parse(affected.platforms) : null,
                            collectionURL: affected.collectionURL
                        },
                        dependencyTree: dependencyTree,
                        dependencyCount: {
                            total: dependencyTree.length,
                            direct: dependencyTree.filter(d => d.isDirect).length,
                            transitive: dependencyTree.filter(d => d.isTransitive).length,
                            dev: dependencyTree.filter(d => d.isDev).length
                        }
                    })

                    dependencies.logger?.info(`Found GitHub repository ${repo.fullName} with ${dependencyTree.length} dependencies`)
                }
            } catch (error) {
                dependencies.logger?.error(`Failed to fetch GitHub repositories for affected package ${affected.packageName}:`, error)
            }
        }
    }

    if (githubRepositories.length > 0) {
        response.githubRepositories = githubRepositories
        dependencies.logger?.info(`Found ${githubRepositories.length} GitHub repositories with dependency trees for ${normalizedCveId}`)
    }

    // Extract aggregated scorecard history for timeline events
    // Combine history from all repositories and deduplicate by date
    let aggregatedScorecardHistory: any[] | null = null
    if (response.scorecards && response.scorecards.length > 0) {
        const historyByDate = new Map<string, { score: number; failingCount: number; date: string }>()

        for (const scorecard of response.scorecards) {
            if (scorecard.history && scorecard.history.length > 0) {
                for (const entry of scorecard.history) {
                    // If we already have an entry for this date, average the scores
                    const existing = historyByDate.get(entry.date)
                    if (existing) {
                        // Average the scores and sum the failing counts
                        historyByDate.set(entry.date, {
                            score: (existing.score + entry.score) / 2,
                            failingCount: existing.failingCount + entry.failingCount,
                            date: entry.date
                        })
                    } else {
                        historyByDate.set(entry.date, { ...entry })
                    }
                }
            }
        }

        if (historyByDate.size > 0) {
            aggregatedScorecardHistory = Array.from(historyByDate.values()).sort((a, b) =>
                a.date.localeCompare(b.date)
            )
            dependencies.logger?.info(`Aggregated ${aggregatedScorecardHistory.length} scorecard history datapoints for timeline`)
        }
    }

    // Build vulnerability timeline from all sources, aliases, and scorecard history
    dependencies.logger?.info(`Building vulnerability timeline for ${normalizedCveId}`)
    const timeline = await buildVulnerabilityTimeline(
        normalizedCveId,
        sources,
        aliasDataArray,
        epssHistory,
        cessHistory,
        kevData,
        aggregatedScorecardHistory,
        allReferences,
        vulnCheckKevData,
        crowdSecSightings,
        dependencies,
        dependencies.logger
    )
    response.timeline = timeline
    dependencies.logger?.info(`Built timeline with ${timeline.length} events for ${normalizedCveId}`)

    // Extract exploit events from timeline for card generator
    const exploitEvents = timeline.filter((e: any) => e.type === 'exploit')
    if (exploitEvents.length > 0) {
        response._exploits = exploitEvents.map((e: any) => ({
            dateAdded: e.time,
            source: e.source || e.exploitType || 'Unknown',
            title: e.exploitTitle || e.value || 'Exploit',
            type: e.exploitType,
            // Optional enrichment fields
            ...(e.exploitUrl && { url: e.exploitUrl }),
            ...(e.exploitId && { exploitId: e.exploitId }),
            ...(e.exploitDbAuthor && { author: e.exploitDbAuthor }),
            ...(e.exploitDbPlatform && { platform: e.exploitDbPlatform }),
            ...(e.exploitDbVerified && { verified: e.exploitDbVerified }),
        }))
        dependencies.logger?.info(`Extracted ${response._exploits.length} exploits from timeline for ${normalizedCveId}`)
    }

    return response
}

/**
 * Build comprehensive Finding data structure
 */
export async function buildFindingData(prisma: PrismaClient, findingId: string, logger: any) {
    // Complex LIKE patterns may be less efficient, so we split the query
    // First try exact match on findingId
    let finding = await prisma.finding.findFirst({
        where: { findingId },
        include: {
            repositories: {
                include: {
                    githubRepository: {
                        include: {
                            branches: true,
                            openssfScorecards: true
                        }
                    }
                }
            },
            triage: {
                orderBy: { lastObserved: 'desc' },
                take: 5
            },
            spdx: true,
            cdx: true,
            references: true
        }
    })

    if (!finding) {
        return null
    }

    // Parse JSON fields
    let aliases = null
    let related = null
    let cwes = null

    try {
        if (finding.aliases) aliases = JSON.parse(finding.aliases)
    } catch (e) {
        logger?.warn('Failed to parse aliases:', e)
    }

    try {
        if (finding.related) related = JSON.parse(finding.related)
    } catch (e) {
        logger?.warn('Failed to parse related:', e)
    }

    try {
        if (finding.cwes) cwes = JSON.parse(finding.cwes)
    } catch (e) {
        logger?.warn('Failed to parse cwes:', e)
    }

    // Map the first repository from the array to 'repo' for backward compatibility
    const repo = finding.repositories?.[0]?.githubRepository || null

    return {
        ...finding,
        aliases,
        related,
        cwes,
        repo
    }
}
