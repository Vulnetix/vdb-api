import type { PrismaClient } from '@prisma/client'

export interface VulnIdResolverResult {
    success: boolean
    table: string // Model name: CVEMetadata, Finding, etc.
    field: string // Field name where the ID was found
    matchType: 'exact' | 'list' // exact = primary key, list = found in aliases/related
    value: string // The normalized value
    record?: any // The actual record(s) found
    error?: string
}

export interface VulnIdSearchMatch {
    table: string
    field: string
    matchType: 'exact' | 'list'
    value: string
    record: any
}

/**
 * VulnId Resolver - Universal vulnerability ID resolver
 * 
 * Takes any vulnerability ID and resolves it across all vulnerability tables:
 * - CVEMetadata (cveId)
 * - Finding (findingId, aliases, related)
 * - Triage (via Finding relationship)
 * - SARIFInfo (ruleId via SarifResults)
 * - CycloneDXInfo (via Finding relationship)
 * - SPDXInfo (via Finding relationship)
 * - EPSSScore (cve field)
 * 
 * @param prisma Prisma client instance
 * @param vulnId The vulnerability ID to resolve (CVE-XXXX-XXXXX, GHSA-xxx, etc.)
 * @param orgId Optional organization ID for scoped searches
 */
export class VulnIdResolver {
    constructor(private prisma: PrismaClient) { }

    /**
     * Resolve a vulnerability ID to its source table and record
     * Normalizes all vulnerability IDs to uppercase for case-insensitive matching
     */
    async resolve(vulnId: string, orgId?: string): Promise<VulnIdResolverResult> {
        if (!vulnId || vulnId.trim() === '') {
            return {
                success: false,
                table: '',
                field: '',
                matchType: 'exact',
                value: '',
                error: 'Vulnerability ID is required'
            }
        }

        // Normalize to uppercase for case-insensitive matching
        const normalizedId = vulnId.trim().toUpperCase()

        // Try GCVE format first (for Vulnetix GCVE IDs)
        if (normalizedId.startsWith('GCVE-')) {
            return await this.resolveGCVE(normalizedId)
        }

        // Try CVE format (most common)
        if (normalizedId.startsWith('CVE-')) {
            return await this.resolveCVE(normalizedId)
        }

        // Try other vulnerability ID formats (all normalized to uppercase)
        if (normalizedId.startsWith('GHSA-')) {
            return await this.resolveGHSA(normalizedId, orgId)
        }

        // Try as a Finding ID or search aliases (normalized to uppercase)
        return await this.resolveFinding(normalizedId, orgId)
    }

    /**
     * Search for CVE IDs in public vulnerability data (CVEMetadata and GcveIssuance)
     * This is for admin editing of global vulnerability data, not customer-specific data
     * Returns all matches found
     */
    async search(query: string, orgId?: string, limit: number = 50): Promise<VulnIdSearchMatch[]> {
        const matches: VulnIdSearchMatch[] = []
        const normalizedQuery = query.trim().toUpperCase()

        // Search GcveIssuance for GCVE IDs first
        try {
            if (normalizedQuery.startsWith('GCVE-')) {
                const gcveRecords = await this.prisma.gcveIssuance.findMany({
                    where: {
                        gcveId: normalizedQuery // exact match
                    },
                    take: limit,
                    orderBy: {
                        datePublished: 'desc'
                    }
                })

                for (const gcve of gcveRecords) {
                    matches.push({
                        table: 'GcveIssuance',
                        field: 'gcveId',
                        matchType: 'exact',
                        value: gcve.gcveId,
                        record: gcve
                    })
                }

                // If GCVE found, also fetch the corresponding CVEMetadata
                if (gcveRecords.length > 0) {
                    for (const gcve of gcveRecords) {
                        const cveRecords = await this.prisma.cVEMetadata.findMany({
                            where: {
                                cveId: gcve.cveId
                            }
                        })

                        for (const cve of cveRecords) {
                            matches.push({
                                table: 'CVEMetadata',
                                field: 'cveId',
                                matchType: 'exact',
                                value: cve.cveId,
                                record: cve
                            })
                        }
                    }
                }
            }
        } catch (error) {
            console.error('Error searching GcveIssuance:', error)
        }

        // Search CVEMetadata - this is the primary table for public VDB data
        try {
            // For CVE IDs, use contains for partial matching anywhere in string (SQL injection safe via Prisma parameterization)
            if (normalizedQuery.startsWith('CVE-')) {
                const cves = await this.prisma.cVEMetadata.findMany({
                    where: {
                        cveId: normalizedQuery // exact match
                    },
                    take: limit,
                    orderBy: {
                        datePublished: 'desc'
                    }
                })

                for (const cve of cves) {
                    matches.push({
                        table: 'CVEMetadata',
                        field: 'cveId',
                        matchType: 'exact',
                        value: cve.cveId,
                        record: cve
                    })
                }
            }
        } catch (error) {
            console.error('Error searching CVEMetadata:', error)
        }

        // Don't search customer-specific tables (Finding, Triage, SARIF, SPDX, CycloneDX)
        // This admin interface is for editing global/public vulnerability data only

        return matches.slice(0, limit)
    }

    /**
     * Resolve a GCVE ID (Global CVE issued by Vulnetix)
     * Looks up in GcveIssuance table and returns the corresponding CVEMetadata
     */
    private async resolveGCVE(gcveId: string): Promise<VulnIdResolverResult> {
        try {
            // Look up in GcveIssuance table
            const gcveRecord = await this.prisma.gcveIssuance.findUnique({
                where: {
                    gcveId: gcveId.toUpperCase()
                }
            })

            if (!gcveRecord) {
                return {
                    success: false,
                    table: 'GcveIssuance',
                    field: 'gcveId',
                    matchType: 'exact',
                    value: gcveId,
                    error: `GCVE ${gcveId} not found in GcveIssuance table`
                }
            }

            // Get ALL corresponding CVEMetadata records (from all sources)
            // The gcveRecord.source tells us which source issued the GCVE, but we want
            // to return all available CVE data sources (just like resolveCVE does)
            const cveRecords = await this.prisma.cVEMetadata.findMany({
                where: {
                    cveId: gcveRecord.cveId
                },
                include: {
                    cna: true,
                    fileLink: true,
                    adp: {
                        include: {
                            adp: true
                        }
                    }
                }
            })

            if (cveRecords.length > 0) {
                return {
                    success: true,
                    table: 'CVEMetadata',
                    field: 'cveId',
                    matchType: 'exact',
                    value: gcveRecord.cveId,
                    record: cveRecords
                }
            }

            // GCVE found but no CVEMetadata - this shouldn't happen but handle it
            return {
                success: false,
                table: 'CVEMetadata',
                field: 'cveId',
                matchType: 'exact',
                value: gcveRecord.cveId,
                error: `GCVE ${gcveId} found but corresponding CVEMetadata ${gcveRecord.cveId} not found`
            }
        } catch (error) {
            return {
                success: false,
                table: 'GcveIssuance',
                field: 'gcveId',
                matchType: 'exact',
                value: gcveId,
                error: error instanceof Error ? error.message : 'Unknown error'
            }
        }
    }

    /**
     * Resolve a CVE ID
     * First tries CVEMetadata directly, then checks CVEAlias relations, then falls back to Finding.aliases
     */
    private async resolveCVE(cveId: string): Promise<VulnIdResolverResult> {
        try {
            // First try CVEMetadata direct match
            const cveRecords = await this.prisma.cVEMetadata.findMany({
                where: { cveId: cveId.toUpperCase() },
                include: {
                    cna: true,
                    fileLink: true,
                    adp: {
                        include: {
                            adp: true
                        }
                    }
                }
            })

            if (cveRecords.length > 0) {
                return {
                    success: true,
                    table: 'CVEMetadata',
                    field: 'cveId',
                    matchType: 'exact',
                    value: cveId,
                    record: cveRecords
                }
            }

            // Check CVEAlias table - search as both primary and alias
            const aliasRecords = await this.prisma.cVEAlias.findMany({
                where: {
                    OR: [
                        { primaryCveId: cveId.toUpperCase() },
                        { aliasCveId: cveId.toUpperCase() }
                    ]
                },
                take: 1
            })

            if (aliasRecords.length > 0) {
                // Found in alias relations, get the primary CVE
                const primaryCveId = aliasRecords[0].aliasCveId === cveId
                    ? aliasRecords[0].primaryCveId
                    : aliasRecords[0].aliasCveId

                // Fetch the CVEMetadata for the primary CVE
                const primaryCveRecords = await this.prisma.cVEMetadata.findMany({
                    where: { cveId: primaryCveId.toUpperCase() },
                    include: {
                        cna: true,
                        fileLink: true,
                        adp: {
                            include: {
                                adp: true
                            }
                        }
                    }
                })

                if (primaryCveRecords.length > 0) {
                    return {
                        success: true,
                        table: 'CVEMetadata',
                        field: 'aliases',
                        matchType: 'list',
                        value: primaryCveId,
                        record: primaryCveRecords
                    }
                }
            }

            // CVE not in CVEMetadata or CVEAlias, try Finding.aliases
            const findings = await this.prisma.finding.findMany({
                where: {
                    aliases: {
                        contains: cveId
                    }
                },
                include: {
                    triage: {
                        take: 1,
                        orderBy: {
                            lastObserved: 'desc'
                        }
                    }
                }
            })

            if (findings.length > 0) {
                return {
                    success: true,
                    table: 'Finding',
                    field: 'aliases',
                    matchType: 'list',
                    value: cveId,
                    record: findings
                }
            }

            // Not found anywhere
            return {
                success: false,
                table: 'CVEMetadata',
                field: 'cveId',
                matchType: 'exact',
                value: cveId,
                error: `CVE ${cveId} not found in CVEMetadata, CVEAlias, or Finding records`
            }
        } catch (error) {
            return {
                success: false,
                table: 'CVEMetadata',
                field: 'cveId',
                matchType: 'exact',
                value: cveId,
                error: error instanceof Error ? error.message : 'Unknown error'
            }
        }
    }

    /**
     * Resolve a GHSA (GitHub Security Advisory) ID
     * VulnProcessor stores GHSA IDs directly in CVEMetadata with cveId = 'GHSA-*'
     * Also checks CVEAlias relations and Finding aliases for GHSA IDs linked to CVEs
     */
    private async resolveGHSA(ghsaId: string, orgId?: string): Promise<VulnIdResolverResult> {
        try {
            // First try CVEMetadata.cveId for direct GHSA storage
            const ghsaRecords = await this.prisma.cVEMetadata.findMany({
                where: { cveId: ghsaId.toUpperCase(), },
                include: {
                    cna: true,
                    fileLink: true,
                    adp: {
                        include: {
                            adp: true
                        }
                    }
                }
            })

            if (ghsaRecords.length > 0) {
                return {
                    success: true,
                    table: 'CVEMetadata',
                    field: 'cveId',
                    matchType: 'exact',
                    value: ghsaId,
                    record: ghsaRecords
                }
            }

            // Check CVEAlias table - search as both primary and alias
            const aliasRecords = await this.prisma.cVEAlias.findMany({
                where: {
                    OR: [
                        { primaryCveId: ghsaId },
                        { aliasCveId: ghsaId }
                    ]
                },
                take: 1
            })

            if (aliasRecords.length > 0) {
                // Found in alias relations, get the related CVE
                const relatedCveId = aliasRecords[0].aliasCveId === ghsaId
                    ? aliasRecords[0].primaryCveId
                    : aliasRecords[0].aliasCveId

                // Fetch the CVEMetadata for the related CVE
                const relatedCveRecords = await this.prisma.cVEMetadata.findMany({
                    where: { cveId: relatedCveId },
                    include: {
                        cna: true,
                        fileLink: true,
                        adp: {
                            include: {
                                adp: true
                            }
                        }
                    }
                })

                if (relatedCveRecords.length > 0) {
                    return {
                        success: true,
                        table: 'CVEMetadata',
                        field: 'aliases',
                        matchType: 'list',
                        value: relatedCveId,
                        record: relatedCveRecords
                    }
                }
            }

            // Try Finding.aliases
            const where: any = {
                aliases: {
                    contains: ghsaId
                }
            }

            if (orgId) {
                where.orgId = orgId
            }

            const findings = await this.prisma.finding.findMany({
                where,
                include: {
                    repo: true,
                    triage: {
                        take: 1,
                        orderBy: {
                            lastObserved: 'desc'
                        }
                    }
                }
            })

            if (findings.length > 0) {
                // Found in Finding.aliases, check if any have a CVE alias
                for (const finding of findings) {
                    if (finding.aliases) {
                        try {
                            const aliases = JSON.parse(finding.aliases)
                            const cveId = aliases.find((alias: string) => alias.startsWith('CVE-'))

                            if (cveId) {
                                // Check if this CVE exists in CVEMetadata
                                const cveRecords = await this.prisma.cVEMetadata.findMany({
                                    where: { cveId },
                                    include: {
                                        cna: true,
                                        fileLink: true,
                                        adp: {
                                            include: {
                                                adp: true
                                            }
                                        }
                                    }
                                })

                                if (cveRecords.length > 0) {
                                    // Return CVEMetadata record instead of Finding
                                    // This provides the most comprehensive data
                                    return {
                                        success: true,
                                        table: 'CVEMetadata',
                                        field: 'aliases',
                                        matchType: 'list',
                                        value: cveId,
                                        record: cveRecords
                                    }
                                }
                            }
                        } catch (e) {
                            // Continue to next finding if alias parsing fails
                        }
                    }
                }

                // No CVE found in CVEMetadata, return Finding records
                return {
                    success: true,
                    table: 'Finding',
                    field: 'aliases',
                    matchType: 'list',
                    value: ghsaId,
                    record: findings
                }
            }

            // Not found anywhere
            return {
                success: false,
                table: 'CVEMetadata',
                field: 'cveId',
                matchType: 'exact',
                value: ghsaId,
                error: `GHSA ${ghsaId} not found in CVEMetadata, CVEAlias, or Finding records`
            }
        } catch (error) {
            return {
                success: false,
                table: 'CVEMetadata',
                field: 'cveId',
                matchType: 'exact',
                value: ghsaId,
                error: error instanceof Error ? error.message : 'Unknown error'
            }
        }
    }

    /**
     * Resolve a Finding by findingId or search aliases
     * Also checks CVEMetadata directly for vulnerability IDs (PYSEC-*, RUSTSEC-*, GO-*, etc.)
     * and CVEAlias relations
     */
    private async resolveFinding(findingId: string, orgId?: string): Promise<VulnIdResolverResult> {
        try {
            // First try CVEMetadata.cveId for direct storage of non-CVE IDs
            // VulnProcessor stores PYSEC-*, RUSTSEC-*, GO-*, etc. directly in CVEMetadata
            const vulnRecords = await this.prisma.cVEMetadata.findMany({
                where: { cveId: findingId },
                include: {
                    cna: true,
                    fileLink: true,
                    adp: {
                        include: {
                            adp: true
                        }
                    }
                }
            })

            if (vulnRecords.length > 0) {
                return {
                    success: true,
                    table: 'CVEMetadata',
                    field: 'cveId',
                    matchType: 'exact',
                    value: findingId,
                    record: vulnRecords
                }
            }

            // Check CVEAlias table - search as both primary and alias
            const aliasRecords = await this.prisma.cVEAlias.findMany({
                where: {
                    OR: [
                        { primaryCveId: findingId },
                        { aliasCveId: findingId }
                    ]
                },
                take: 1
            })

            if (aliasRecords.length > 0) {
                // Found in alias relations, get the related CVE
                const relatedCveId = aliasRecords[0].aliasCveId === findingId
                    ? aliasRecords[0].primaryCveId
                    : aliasRecords[0].aliasCveId

                // Fetch the CVEMetadata for the related CVE
                const relatedCveRecords = await this.prisma.cVEMetadata.findMany({
                    where: { cveId: relatedCveId },
                    include: {
                        cna: true,
                        fileLink: true,
                        adp: {
                            include: {
                                adp: true
                            }
                        }
                    }
                })

                if (relatedCveRecords.length > 0) {
                    return {
                        success: true,
                        table: 'CVEMetadata',
                        field: 'aliases',
                        matchType: 'list',
                        value: relatedCveId,
                        record: relatedCveRecords
                    }
                }
            }

            // Try Finding table
            const where: any = {
                OR: [
                    { findingId: findingId },
                    { aliases: { contains: findingId } },
                    { related: { contains: findingId } }
                ]
            }

            if (orgId) {
                where.orgId = orgId
            }

            const findings = await this.prisma.finding.findMany({
                where,
                include: {
                    repo: true,
                    triage: {
                        take: 1,
                        orderBy: {
                            lastObserved: 'desc'
                        }
                    },
                    spdx: true,
                    cdx: true
                }
            })

            if (findings.length === 0) {
                return {
                    success: false,
                    table: 'Finding',
                    field: 'findingId',
                    matchType: 'exact',
                    value: findingId,
                    error: `Finding ${findingId} not found`
                }
            }

            // Check if any findings have a CVE alias that exists in CVEMetadata
            for (const finding of findings) {
                if (finding.aliases) {
                    try {
                        const aliases = JSON.parse(finding.aliases)
                        const cveId = aliases.find((alias: string) => alias.startsWith('CVE-'))

                        if (cveId) {
                            // Check if this CVE exists in CVEMetadata
                            const cveRecords = await this.prisma.cVEMetadata.findMany({
                                where: { cveId },
                                include: {
                                    cna: true,
                                    fileLink: true,
                                    adp: {
                                        include: {
                                            adp: true
                                        }
                                    }
                                }
                            })

                            if (cveRecords.length > 0) {
                                // Return CVEMetadata record for comprehensive data
                                return {
                                    success: true,
                                    table: 'CVEMetadata',
                                    field: 'aliases',
                                    matchType: 'list',
                                    value: cveId,
                                    record: cveRecords
                                }
                            }
                        }
                    } catch (e) {
                        // Continue to next finding if alias parsing fails
                    }
                }
            }

            // Determine match type
            const exactMatch = findings.find(f => f.findingId === findingId)
            const matchType = exactMatch ? 'exact' : 'list'
            const field = exactMatch ? 'findingId' : 'aliases'

            return {
                success: true,
                table: 'Finding',
                field,
                matchType,
                value: findingId,
                record: findings
            }
        } catch (error) {
            return {
                success: false,
                table: 'Finding',
                field: 'findingId',
                matchType: 'exact',
                value: findingId,
                error: error instanceof Error ? error.message : 'Unknown error'
            }
        }
    }

    /**
     * Get full vulnerability data for a resolved ID
     * Returns comprehensive data similar to the public VDB page
     */
    async getFullVulnerabilityData(vulnId: string, orgId?: string): Promise<any> {
        const resolved = await this.resolve(vulnId, orgId)

        if (!resolved.success) {
            return {
                success: false,
                error: resolved.error
            }
        }

        // For CVE, return the existing VDB API format
        if (resolved.table === 'CVEMetadata') {
            return {
                success: true,
                source: 'CVEMetadata',
                data: resolved.record
            }
        }

        // For Finding, return finding data with relationships
        if (resolved.table === 'Finding') {
            return {
                success: true,
                source: 'Finding',
                data: resolved.record
            }
        }

        return {
            success: true,
            source: resolved.table,
            data: resolved.record
        }
    }
}

/**
 * Helper function to create a resolver instance
 */
export function createVulnIdResolver(prisma: PrismaClient): VulnIdResolver {
    return new VulnIdResolver(prisma)
}
