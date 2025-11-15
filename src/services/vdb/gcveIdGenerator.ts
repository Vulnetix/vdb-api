/**
 * GCVE ID Generator Service
 *
 * Generates GCVE (Global CVE) identifiers for Vulnetix-sourced vulnerabilities
 * following the GCVE BCP-04 specification: https://gcve.eu/bcp/gcve-bcp-04/
 *
 * Format: GCVE-VVD-YYYY-NNNN
 * - VVD: Vulnetix Vulnerability Database (our GNA identifier)
 * - YYYY: Publication year
 * - NNNN: Sequential number (zero-padded to 4 digits minimum)
 */

import type { PrismaClient } from '@prisma/client'

const GNA_ID = 'VVD'
const GCVE_PREFIX = 'GCVE'
const R2_BUCKET_NAME = 'r2artifacts'
const R2_PATH_PREFIX = 'gcve/cvelistv5'

export interface GcveGenerationResult {
    success: boolean
    gcveId?: string
    cveId?: string
    source?: string
    r2Key?: string
    error?: string
}

export interface GcveIdGeneratorOptions {
    year?: number // Override year (default: current year)
    forceRegenerate?: boolean // Force regeneration even if GCVE ID exists
}

/**
 * Generate or retrieve a GCVE identifier for a CVE
 */
export async function generateGcveId(
    prisma: PrismaClient,
    r2adapter: any,
    cveId: string,
    source: string,
    options: GcveIdGeneratorOptions = {}
): Promise<GcveGenerationResult> {
    const { year = new Date().getFullYear(), forceRegenerate = false } = options
    const normalizedCveId = cveId.trim().toUpperCase()

    try {
        // Check if GCVE ID already exists for this CVE
        if (!forceRegenerate) {
            const existing = await prisma.gcveIssuance.findFirst({
                where: {
                    cveId: normalizedCveId,
                    source: source
                }
            })

            if (existing) {
                return {
                    success: true,
                    gcveId: existing.gcveId,
                    cveId: existing.cveId,
                    source: existing.source,
                    r2Key: existing.r2Key || undefined
                }
            }
        }

        // Get the next sequence number for this year
        // Use both database and R2 as sources of truth to handle race conditions
        const r2PathPrefix = `${R2_PATH_PREFIX}/${year}/`

        // Get existing sequence numbers from database
        const dbIssuances = await prisma.gcveIssuance.findMany({
            where: { year },
            select: { sequenceNumber: true, gcveId: true }
        })

        const dbSequenceNumbers = new Set(dbIssuances.map(i => i.sequenceNumber))
        const existingGcveIds = new Set(dbIssuances.map(i => i.gcveId))

        // Also check R2 for any files that might exist
        const listResult = await r2adapter.list({ prefix: r2PathPrefix })
        const gcvePattern = new RegExp(`^${R2_PATH_PREFIX}/${year}/GCVE-${GNA_ID}-${year}-(\\d+)\\.json$`)

        for (const obj of listResult.objects) {
            const match = obj.key.match(gcvePattern)
            if (match && match[1]) {
                dbSequenceNumbers.add(parseInt(match[1], 10))
            }
        }

        // Determine next available sequence number
        let nextSequence = 1
        while (dbSequenceNumbers.has(nextSequence)) {
            nextSequence++
        }

        // Retry logic for race conditions
        const MAX_RETRIES = 5
        let retryCount = 0
        let gcveIssuance: any = null

        while (retryCount < MAX_RETRIES) {
            // Format GCVE ID
            const sequenceStr = nextSequence.toString().padStart(4, '0')
            const gcveId = `${GCVE_PREFIX}-${GNA_ID}-${year}-${sequenceStr}`

            // Check if this gcveId already exists (race condition check)
            if (existingGcveIds.has(gcveId)) {
                nextSequence++
                retryCount++
                continue
            }

            try {
                // Fetch aliases for this CVE from ANY source (not just the Vulnetix source)
                // since Vulnetix is a virtual/computed source that aggregates all other sources
                const aliases = await prisma.cVEAlias.findMany({
                    where: {
                        OR: [
                            { primaryCveId: normalizedCveId },
                            { aliasCveId: normalizedCveId }
                        ]
                    }
                })

                // Create GCVE issuance record
                const datePublished = Math.floor(Date.now() / 1000)
                const r2Key = `${R2_PATH_PREFIX}/${year}/${gcveId}.json`

                gcveIssuance = await prisma.gcveIssuance.create({
                    data: {
                        gcveId,
                        cveId: normalizedCveId,
                        source,
                        datePublished,
                        year,
                        sequenceNumber: nextSequence,
                        r2Bucket: R2_BUCKET_NAME,
                        r2Key,
                        createdAt: datePublished
                    }
                })

                // Collect all unique aliases (both directions) into a format for GcveAlias
                const aliasRecords: Array<{ aliasCveId: string; aliasSource: string }> = []

                // Process aliases where this CVE is the primary
                for (const rel of aliases) {
                    if (rel.primaryCveId === normalizedCveId && rel.aliasCveId !== normalizedCveId) {
                        aliasRecords.push({
                            aliasCveId: rel.aliasCveId,
                            aliasSource: rel.aliasSource
                        })
                    }
                    // Process aliases where this CVE is the alias
                    if (rel.aliasCveId === normalizedCveId && rel.primaryCveId !== normalizedCveId) {
                        aliasRecords.push({
                            aliasCveId: rel.primaryCveId,
                            aliasSource: rel.primarySource
                        })
                    }
                }

                // Create GcveAlias records for all aliases
                if (aliasRecords.length > 0) {
                    await prisma.gcveAlias.createMany({
                        data: aliasRecords.map(alias => ({
                            gcveId,
                            aliasCveId: alias.aliasCveId,
                            aliasSource: alias.aliasSource,
                            createdAt: datePublished
                        })),
                        skipDuplicates: true
                    } as any)
                }

                // Success! Break out of retry loop
                break
            } catch (error: any) {
                // Check if it's a unique constraint error on gcveId
                if (error.message?.includes('UNIQUE constraint failed') &&
                    error.message?.includes('gcveId')) {
                    // Race condition detected - try next sequence number
                    retryCount++
                    nextSequence++
                    existingGcveIds.add(gcveId) // Remember this ID is taken

                    if (retryCount >= MAX_RETRIES) {
                        throw new Error(`Failed to generate unique GCVE ID after ${MAX_RETRIES} attempts`)
                    }
                    continue
                }
                // Different error - rethrow
                throw error
            }
        }

        if (!gcveIssuance) {
            throw new Error('Failed to create GCVE issuance record')
        }

        return {
            success: true,
            gcveId: gcveIssuance.gcveId,
            cveId: gcveIssuance.cveId,
            source: gcveIssuance.source,
            r2Key: gcveIssuance.r2Key || undefined
        }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error generating GCVE ID'
        }
    }
}

/**
 * Store CVE data in CVE List v5 format to R2
 */
export async function storeGcveCveListV5(
    r2adapter: any,
    gcveId: string,
    cveData: any
): Promise<{ success: boolean; r2Key?: string; error?: string }> {
    try {
        // Extract year from GCVE ID
        const yearMatch = gcveId.match(/GCVE-[A-Z]+-(\d{4})-\d+/)
        if (!yearMatch) {
            return {
                success: false,
                error: `Invalid GCVE ID format: ${gcveId}`
            }
        }

        const year = yearMatch[1]
        const r2Key = `${R2_PATH_PREFIX}/${year}/${gcveId}.json`

        // Ensure the CVE data has proper GCVE metadata
        const enhancedData = {
            ...cveData,
            dataType: 'CVE_RECORD',
            dataVersion: '5.1',
            cveMetadata: {
                ...cveData.cveMetadata,
                // Add GCVE as an alias in the metadata
                gcveId: gcveId
            }
        }

        // Store to R2
        await r2adapter.put(r2Key, JSON.stringify(enhancedData, null, 2), {
            httpMetadata: {
                contentType: 'application/json',
                contentDisposition: `attachment; filename="${gcveId}.json"`
            }
        })

        return {
            success: true,
            r2Key
        }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error storing to R2'
        }
    }
}

/**
 * Lookup existing GCVE ID for a CVE
 * IMPORTANT: For GCVE IDs, gcveId should ALWAYS equal cveId (GCVE IDs ARE the CVE IDs)
 */
export async function lookupGcveId(
    prisma: PrismaClient,
    cveId: string,
    source?: string
): Promise<{ gcveId: string; source: string } | null> {
    const normalizedCveId = cveId.trim().toUpperCase()

    // CRITICAL FIX: For GCVE IDs, only return when gcveId === cveId
    // This prevents returning corrupted records where cveId points to the wrong CVE
    if (normalizedCveId.startsWith('GCVE-')) {
        const gcveIssuance = await prisma.gcveIssuance.findFirst({
            where: {
                gcveId: normalizedCveId, // For GCVE IDs, look up by gcveId (NOT cveId)
                ...(source && { source })
            }
        })

        return gcveIssuance
            ? { gcveId: gcveIssuance.gcveId, source: gcveIssuance.source }
            : null
    }

    // For regular CVE IDs, look up by cveId as before
    const where = source
        ? { cveId: normalizedCveId, source }
        : { cveId: normalizedCveId }

    const gcveIssuance = await prisma.gcveIssuance.findFirst({
        where,
        orderBy: { createdAt: 'desc' }
    })

    return gcveIssuance
        ? { gcveId: gcveIssuance.gcveId, source: gcveIssuance.source }
        : null
}
