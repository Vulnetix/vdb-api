/**
 * VDB Identifier Management System
 *
 * VDB identifiers follow the format: VDB-YYYY-N
 * - VDB: Vulnetix Database prefix
 * - YYYY: Current calendar year
 * - N: Sequential numeric counter (auto-incremented)
 *
 * These identifiers are used for:
 * 1. CVE records created via the admin UI
 * 2. Tracking custom vulnerability records
 * 3. R2 storage paths for CVE JSON files
 */

import type { PrismaClient } from '@prisma/client'

/**
 * VDB identifier components
 */
export interface VdbIdentifier {
    prefix: `VDB` // Fixed prefix
    year: number // Calendar year (YYYY)
    sequence: number // Sequential number
    full: string // Complete identifier: VDB-YYYY-N
}

/**
 * R2 path configuration for different vulnerability sources
 */
export interface VdbR2PathConfig {
    source: string // Source identifier (cve.org, osv, github, etc.)
    basePath: string // Base R2 path for this source
    getPath: (identifier: string) => string // Function to generate full path
}

/**
 * Parse a VDB identifier string into components
 * @param vdbId VDB identifier (e.g., "VDB-2025-1")
 * @returns Parsed components or null if invalid
 */
export const parseVdbIdentifier = (vdbId: string): VdbIdentifier | null => {
    const pattern = /^VDB-(\d{4})-(\d+)$/
    const match = vdbId.trim().toUpperCase().match(pattern)

    if (!match) {
        return null
    }

    const year = parseInt(match[1], 10)
    const sequence = parseInt(match[2], 10)

    return {
        prefix: `VDB`,
        year,
        sequence,
        full: `VDB-${year}-${sequence}`
    }
}

/**
 * Validate a VDB identifier format
 * @param vdbId VDB identifier to validate
 * @returns true if valid, false otherwise
 */
export const isValidVdbIdentifier = (vdbId: string): boolean => {
    return parseVdbIdentifier(vdbId) !== null
}

/**
 * Generate the next VDB identifier for the current year
 * @param prisma Prisma client
 * @param year Optional year (defaults to current year)
 * @returns Next VDB identifier
 */
export const generateNextVdbIdentifier = async (
    prisma: PrismaClient,
    year?: number
): Promise<string> => {
    const currentYear = year || new Date().getFullYear()

    // Find the highest sequence number for the current year
    // VDB identifiers are stored in CVEMetadata.cveId with source='vdb'
    const latestRecord = await prisma.cVEMetadata.findFirst({
        where: {
            source: `vdb`,
            cveId: {
                startsWith: `VDB-${currentYear}-`
            }
        },
        orderBy: {
            cveId: `desc`
        },
        select: {
            cveId: true
        }
    })

    let nextSequence = 1

    if (latestRecord) {
        const parsed = parseVdbIdentifier(latestRecord.cveId)
        if (parsed) {
            nextSequence = parsed.sequence + 1
        }
    }

    return `VDB-${currentYear}-${nextSequence}`
}

/**
 * R2 path configurations for different vulnerability sources
 * Matches existing R2 structure used in VulnProcessor
 */
export const vdbR2PathConfigs: Record<string, VdbR2PathConfig> = {
    'vdb': {
        source: `vdb`,
        basePath: `vdb`,
        getPath: (identifier: string) => `vdb/${identifier}.json`
    },
    'cve.org': {
        source: `cve.org`,
        basePath: `cve-org`,
        getPath: (identifier: string) => `cve-org/${identifier}.json`
    },
    'osv': {
        source: `osv`,
        basePath: `osv`,
        getPath: (identifier: string) => `osv/${identifier}.json`
    },
    'github': {
        source: `github`,
        basePath: `github`,
        getPath: (identifier: string) => `github/${identifier}.json`
    },
    'google-osi': {
        source: `google-osi`,
        basePath: `google-osi`,
        getPath: (identifier: string) => `google-osi/${identifier}.json`
    },
    'nist-nvd': {
        source: `nist-nvd`,
        basePath: `nist-nvd`,
        getPath: (identifier: string) => `nist-nvd/${identifier}.json`
    },
    'euvd': {
        source: `euvd`,
        basePath: `euvd`,
        getPath: (identifier: string) => `euvd/${identifier}.json`
    },
    'kev': {
        source: `kev`,
        basePath: `kev`,
        getPath: (identifier: string) => `kev/${identifier}.json`
    },
    'anchore-adp': {
        source: `anchore-adp`,
        basePath: `anchore-adp`,
        getPath: (identifier: string) => `anchore-adp/${identifier}.json`
    }
}

/**
 * Construct legacy GitHub-style R2 path for CVE files
 * Format: cves_YYYY_Xxxx_CVE-YYYY-NNNN.json (matches GitHub cvelistV5 structure)
 * Example: cves_2024_0xxx_CVE-2024-0109.json
 * @param cveId CVE identifier (e.g., CVE-2024-0109)
 * @returns Legacy R2 path or null if invalid CVE format
 */
const getLegacyCvePath = (cveId: string): string | null => {
    const match = cveId.match(/^CVE-(\d{4})-(\d+)$/)
    if (!match) return null

    const year = match[1]
    const number = match[2]

    // Create xxxxx subfolder (e.g., "0109" → "0xxx", "12345" → "12xxx")
    const subfolder = number.slice(0, -3).padStart(number.length - 3, '0') + 'xxx'

    return `cves_${year}_${subfolder}_${cveId}.json`
}

/**
 * Get R2 paths for a vulnerability identifier
 * Derives source from identifier prefix and returns possible R2 paths
 * @param identifier Vulnerability identifier (CVE-*, GHSA-*, VDB-*, etc.)
 * @returns Array of possible R2 paths to check
 */
export const getR2PathsForIdentifier = (identifier: string): string[] => {
    const trimmed = identifier.trim()
    // For GHSA, use proper case normalization, otherwise uppercase
    const normalizedId = trimmed.toUpperCase().startsWith('GHSA-')
        ? normalizeGhsaIdentifier(trimmed)
        : trimmed.toUpperCase()
    const paths: string[] = []

    // VDB identifiers - stored in vdb/ path
    if (normalizedId.startsWith(`VDB-`)) {
        const config = vdbR2PathConfigs['vdb']
        paths.push(config.getPath(normalizedId))
        return paths
    }

    // CVE identifiers - could be in multiple sources
    if (normalizedId.startsWith(`CVE-`)) {
        // Check all sources that might have CVE data
        paths.push(vdbR2PathConfigs['cve.org'].getPath(normalizedId))
        paths.push(vdbR2PathConfigs['nist-nvd'].getPath(normalizedId))
        paths.push(vdbR2PathConfigs['kev'].getPath(normalizedId))
        paths.push(vdbR2PathConfigs['osv'].getPath(normalizedId))

        // Add legacy GitHub-style path for backward compatibility
        const legacyPath = getLegacyCvePath(normalizedId)
        if (legacyPath) {
            paths.push(legacyPath)
        }

        return paths
    }

    // GHSA identifiers - GitHub Advisory
    if (normalizedId.startsWith(`GHSA-`)) {
        paths.push(vdbR2PathConfigs['github'].getPath(normalizedId))
        paths.push(vdbR2PathConfigs['osv'].getPath(normalizedId))
        return paths
    }

    // EUVD identifiers
    if (normalizedId.startsWith(`EUVD-`)) {
        paths.push(vdbR2PathConfigs['euvd'].getPath(normalizedId))
        return paths
    }

    // PYSEC, GO, RUSTSEC, GSD, etc. - OSV
    const osvPrefixes = [`PYSEC-`, `GO-`, `RUSTSEC-`, `GSD-`, `OSV-`, `MAVEN-`, `NPM-`]
    if (osvPrefixes.some(prefix => normalizedId.startsWith(prefix))) {
        paths.push(vdbR2PathConfigs['osv'].getPath(normalizedId))
        return paths
    }

    // Unknown prefix - try all sources
    return Object.values(vdbR2PathConfigs).map(config => config.getPath(normalizedId))
}

/**
 * Normalize GHSA identifier to correct case format
 * GHSA identifiers are case-sensitive in some APIs (e.g., deps.dev)
 * Format: GHSA-xxxx-xxxx-xxxx (uppercase prefix, lowercase identifier)
 *
 * @param ghsaId GHSA identifier in any case
 * @returns Normalized GHSA identifier (GHSA-xxxx-xxxx-xxxx)
 *
 * @example
 * normalizeGhsaIdentifier('ghsa-968p-4wvh-cqc8') // returns 'GHSA-968p-4wvh-cqc8'
 * normalizeGhsaIdentifier('GHSA-968P-4WVH-CQC8') // returns 'GHSA-968p-4wvh-cqc8'
 * normalizeGhsaIdentifier('GHSA-968p-4wvh-cqc8') // returns 'GHSA-968p-4wvh-cqc8'
 */
export const normalizeGhsaIdentifier = (ghsaId: string): string => {
    const trimmed = ghsaId.trim()

    // Check if it's a GHSA identifier
    if (!trimmed.toUpperCase().startsWith('GHSA-')) {
        return trimmed
    }

    // Split into prefix and identifier parts
    const parts = trimmed.split('-')
    if (parts.length !== 4) {
        return trimmed // Invalid format, return as-is
    }

    // Normalize: uppercase prefix, lowercase identifier
    return `GHSA-${parts[1].toLowerCase()}-${parts[2].toLowerCase()}-${parts[3].toLowerCase()}`
}

/**
 * Get source name from identifier prefix
 * @param identifier Vulnerability identifier
 * @returns Source name (for display purposes)
 */
export const getSourceFromIdentifier = (identifier: string): string => {
    const normalizedId = identifier.trim().toUpperCase()

    if (normalizedId.startsWith(`VVD-`)) return `Vulnetix VDB`
    if (normalizedId.startsWith(`CVE-`)) return `Mitre`
    if (normalizedId.startsWith(`GHSA-`)) return `GitHub Advisory`
    if (normalizedId.startsWith(`PYSEC-`)) return `PyPI Security`
    if (normalizedId.startsWith(`GO-`)) return `Go Vulnerabilities`
    if (normalizedId.startsWith(`RUSTSEC-`)) return `Rust Security`
    if (normalizedId.startsWith(`GSD-`)) return `Global Security Database`
    if (normalizedId.startsWith(`OSV-`)) return `OSV`
    if (normalizedId.startsWith(`EUVD-`)) return `EU Vulnerability Database`
    if (normalizedId.startsWith(`MAVEN-`)) return `Maven Central`
    if (normalizedId.startsWith(`NPM-`)) return `npm Registry`

    return `Unknown`
}

/**
 * Store raw JSON data to R2 with appropriate path
 * @param r2adapter R2 bucket adapter
 * @param identifier Vulnerability identifier
 * @param source Source identifier (vdb, cve.org, osv, etc.)
 * @param jsonData JSON data to store
 * @param logger Optional logger
 */
export const storeVulnJsonToR2 = async (
    r2adapter: any,
    identifier: string,
    source: string,
    jsonData: any,
    logger?: {
        info: (message: string, data?: any) => void
        warn: (message: string, data?: any) => void
        error: (message: string, data?: any) => void
    }
): Promise<void> => {
    const trimmed = identifier.trim()
    // For GHSA, use proper case normalization, otherwise uppercase
    const normalizedId = trimmed.toUpperCase().startsWith('GHSA-')
        ? normalizeGhsaIdentifier(trimmed)
        : trimmed.toUpperCase()
    const config = vdbR2PathConfigs[source]

    if (!config) {
        logger?.warn(`Unknown source '${source}' for R2 storage, using default path`)
        // Fallback to source-based path
        const path = `${source}/${normalizedId}.json`
        await r2adapter.put(path, JSON.stringify(jsonData, null, 2), {
            httpMetadata: { contentType: `application/json` }
        })
        logger?.info(`Stored ${normalizedId} JSON to R2: ${path}`)
        return
    }

    const path = config.getPath(normalizedId)
    await r2adapter.put(path, JSON.stringify(jsonData, null, 2), {
        httpMetadata: { contentType: `application/json` }
    })
    logger?.info(`Stored ${normalizedId} JSON to R2: ${path}`)
}

/**
 * Retrieve raw JSON data from R2 by identifier
 * Tries all possible R2 paths for the identifier
 * @param r2adapter R2 bucket adapter
 * @param identifier Vulnerability identifier
 * @param logger Optional logger
 * @returns JSON data or null if not found
 */
export const retrieveVulnJsonFromR2 = async (
    r2adapter: any,
    identifier: string,
    logger?: {
        info: (message: string, data?: any) => void
        warn: (message: string, data?: any) => void
        error: (message: string, data?: any) => void
    }
): Promise<{ data: any; source: string; path: string } | null> => {
    const paths = getR2PathsForIdentifier(identifier)

    for (const path of paths) {
        try {
            const object = await r2adapter.get(path)
            if (object) {
                const text = await object.text()
                const data = JSON.parse(text)

                // Extract source from path
                const source = path.split(`/`)[0]

                logger?.info(`Retrieved ${identifier} JSON from R2: ${path}`)
                return { data, source, path }
            }
        } catch (error: any) {
            // Continue to next path (expected when checking multiple possible locations)
            continue
        }
    }

    logger?.warn(`No JSON found in R2 for identifier: ${identifier}`)
    return null
}

/**
 * Store external reference file to R2 (e.g., exploit-db raw files, GitHub files)
 * These are NOT vulnerability JSON files but external reference content
 * @param r2adapter R2 bucket adapter
 * @param path R2 path (e.g., "exploit-db/raw/12345.txt")
 * @param content File content (string or object)
 * @param contentType Content type (e.g., "text/plain", "application/json")
 * @param logger Optional logger
 */
export const storeExternalFileToR2 = async (
    r2adapter: any,
    path: string,
    content: string | any,
    contentType: string = 'text/plain',
    logger?: {
        info: (message: string, data?: any) => void
        warn: (message: string, data?: any) => void
        error: (message: string, data?: any) => void
    }
): Promise<void> => {
    try {
        const data = typeof content === 'string' ? content : JSON.stringify(content, null, 2)
        await r2adapter.put(path, data, {
            httpMetadata: { contentType }
        })
        logger?.info(`Stored external file to R2: ${path}`)
    } catch (error: any) {
        logger?.error(`Failed to store external file to R2 (${path}): ${error.message}`)
        throw error
    }
}

/**
 * Retrieve external reference file from R2
 * @param r2adapter R2 bucket adapter
 * @param path R2 path (e.g., "exploit-db/raw/12345.txt")
 * @param logger Optional logger
 * @returns File content as string or null if not found
 */
export const retrieveExternalFileFromR2 = async (
    r2adapter: any,
    path: string,
    logger?: {
        info: (message: string, data?: any) => void
        warn: (message: string, data?: any) => void
        error: (message: string, data?: any) => void
    }
): Promise<string | null> => {
    try {
        const object = await r2adapter.get(path)
        if (object) {
            const content = await object.text()
            logger?.info(`Retrieved external file from R2: ${path}`)
            return content
        }
        // File not found in R2 (expected when checking cache)
        return null
    } catch (error: any) {
        logger?.warn(`Failed to retrieve external file from R2 (${path}): ${error.message}`)
        return null
    }
}

/**
 * Get R2 path for exploit-db raw file
 * @param exploitId ExploitDB exploit ID (e.g., "12345")
 * @returns R2 path
 */
export const getExploitDBRawPath = (exploitId: string): string => {
    return `exploit-db/raw/${exploitId}.txt`
}

/**
 * Get R2 path for GitHub raw file (blob, raw content, etc.)
 * @param owner Repository owner
 * @param repo Repository name
 * @param path File path or identifier
 * @returns R2 path
 */
export const getGitHubRawPath = (owner: string, repo: string, path: string): string => {
    // Sanitize path to create valid R2 key
    const sanitizedPath = path.replace(/^\/+/, '').replace(/\/+/g, '/')
    return `github/raw/${owner}/${repo}/${sanitizedPath}`
}

/**
 * Get R2 path for Metasploit framework module file
 * @param modulePath Module path (e.g., "/modules/exploits/windows/browser/ie_execcommand_uaf.rb")
 * @returns R2 path
 */
export const getMetasploitModulePath = (modulePath: string): string => {
    // Remove leading slash if present
    const sanitizedPath = modulePath.replace(/^\/+/, '')
    return `metasploit-framework/${sanitizedPath}`
}
