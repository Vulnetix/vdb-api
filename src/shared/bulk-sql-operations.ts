/**
 * Bulk SQL Operations for PostgreSQL
 *
 * This module provides utilities for efficient bulk INSERT/UPSERT operations
 * using PostgreSQL transactions via Prisma.
 *
 * All operations use PostgreSQL-compatible syntax:
 * - INSERT ... ON CONFLICT DO NOTHING - Skip duplicates silently
 * - INSERT ... ON CONFLICT DO UPDATE - True upsert behavior
 *
 * Strategy:
 * - Use Prisma's transaction API for atomic operations
 * - Build parameterized SQL statements to prevent SQL injection
 * - All operations execute within a single transaction for consistency
 *
 * See: https://www.postgresql.org/docs/current/tutorial-transactions.html
 */

import { Prisma, type PrismaClient } from '@prisma/client'

interface Logger {
    warn: (message: string, data?: any) => void
    debug: (message: string, data?: any) => void
    error: (message: string, data?: any) => void
    info: (message: string, data?: any) => void
}

/**
 * Escape a string value for SQL by replacing single quotes with two single quotes
 */
export function escapeSqlString(value: string | null | undefined): string {
    if (value === null || value === undefined) {
        return 'NULL'
    }
    return `'${String(value).replace(/'/g, "''")}'`
}

/**
 * Format a value for SQL (handles null, numbers, strings, dates)
 */
function formatSqlValue(value: any): string {
    if (value === null || value === undefined) {
        return 'NULL'
    }
    if (typeof value === 'number') {
        return String(value)
    }
    if (value instanceof Date) {
        return String(Math.floor(value.getTime() / 1000))
    }
    // String
    return escapeSqlString(value)
}

/**
 * Result from bulk operation
 */
export type BulkOperationResult = {
    success: boolean
    recordsProcessed: number
    recordsFailed: number
    batches: number
    errors: string[]
}

/**
 * Check if an error is a transient PostgreSQL error that should be retried
 */
function isTransientError(error: any): boolean {
    const errorMessage = error?.message || String(error)
    const errorCode = error?.code

    // PostgreSQL error codes that indicate transient errors:
    // 40001 = serialization_failure (deadlock)
    // 40P01 = deadlock_detected
    // 55P03 = lock_not_available
    // 57014 = query_canceled
    const transientCodes = ['40001', '40P01', '55P03', '57014']

    if (errorCode && transientCodes.includes(errorCode)) {
        return true
    }

    // Check error message for common transient error patterns
    const transientPatterns = [
        'deadlock detected',
        'lock timeout',
        'could not serialize access',
        'connection refused',
        'connection terminated',
        'server closed the connection',
        'timeout exceeded'
    ]

    return transientPatterns.some(pattern =>
        errorMessage.toLowerCase().includes(pattern)
    )
}

/**
 * Split an array into chunks of specified size
 */
export function chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = []
    for (let i = 0; i < array.length; i += chunkSize) {
        chunks.push(array.slice(i, i + chunkSize))
    }
    return chunks
}

/**
 * Execute a batch of SQL statements using PostgreSQL transaction
 * Combines multiple INSERT statements into multi-row INSERTs to reduce timeout usage
 *
 * For very large datasets, splits into multiple transactions to avoid timeout issues
 *
 * RELIABILITY OPTIMIZATIONS:
 * - Reduced batch sizes for faster, more predictable transactions
 * - Shorter transaction timeouts (30s instead of 120s)
 * - Smaller multi-row INSERTs for better error isolation
 *
 * @param prisma - The PrismaClient instance
 * @param statements - Array of SQL statements to execute
 * @param batchSize - Number of statements to combine per multi-row INSERT (default: 100, reduced from 500)
 * @returns Array of results from each statement execution
 */
async function executeBatch(
    prisma: PrismaClient,
    statements: string[],
    batchSize: number = 100,
    retryCount: number = 0,
    logger?: Logger
): Promise<any[]> {
    if (statements.length === 0) return []

    const MAX_RETRIES = 3

    // Combine statements into multi-row INSERTs to minimize timeout usage
    const combinedStatements = combineInsertStatements(statements, batchSize, logger)

    // Increased from 30 to 100 for better throughput with bulk operations
    // This reduces the number of transactions needed per batch
    const MAX_STATEMENTS_PER_TRANSACTION = 100
    const allResults: any[] = []

    if (combinedStatements.length <= MAX_STATEMENTS_PER_TRANSACTION) {
        // Small enough to fit in a single transaction
        try {
            if (logger) {
                logger.debug(`[executeBatch] Executing ${combinedStatements.length} combined statements in single transaction`)
            }
            return await prisma.$transaction(async (tx) => {
                const results: any[] = []
                for (let i = 0; i < combinedStatements.length; i++) {
                    const sql = combinedStatements[i]
                    if (combinedStatements.length > 5 && i % Math.ceil(combinedStatements.length / 5) === 0) {
                        if (logger) {
                            logger.debug(`[executeBatch] Progress: ${i}/${combinedStatements.length} statements executed`)
                        }
                    }
                    const result = await (tx as any).$executeRawUnsafe(sql)
                    results.push(result)
                }
                if (logger) {
                    logger.debug(`[executeBatch] Transaction complete: ${combinedStatements.length} statements executed`)
                }
                return results
            }, {
                maxWait: 60000, // 60 seconds to acquire connection
                timeout: 300000 // 5 minutes for transaction to complete
            })
        } catch (error: any) {
            // Retry transient errors
            if (isTransientError(error) && retryCount < MAX_RETRIES) {
                const waitMs = 1000 * Math.pow(2, retryCount) // Exponential backoff
                if (logger) {
                    logger.warn(`[executeBatch] Transient error detected (attempt ${retryCount + 1}/${MAX_RETRIES}), retrying in ${waitMs}ms...`, {
                        error: error.message,
                        code: error.code
                    })
                }
                await new Promise(resolve => setTimeout(resolve, waitMs))
                return executeBatch(prisma, statements, batchSize, retryCount + 1, logger)
            }
            // Non-transient error or max retries reached
            throw error
        }
    }

    // Split into multiple transactions for large datasets
    if (logger) {
        logger.debug(`[executeBatch] Splitting ${combinedStatements.length} statements into multiple transactions (max ${MAX_STATEMENTS_PER_TRANSACTION} per transaction)`)
    }

    for (let i = 0; i < combinedStatements.length; i += MAX_STATEMENTS_PER_TRANSACTION) {
        const chunk = combinedStatements.slice(i, i + MAX_STATEMENTS_PER_TRANSACTION)
        const chunkNum = Math.floor(i / MAX_STATEMENTS_PER_TRANSACTION) + 1
        const totalChunks = Math.ceil(combinedStatements.length / MAX_STATEMENTS_PER_TRANSACTION)

        if (logger) {
            logger.debug(`[executeBatch] Processing transaction chunk ${chunkNum}/${totalChunks} (${chunk.length} statements)`)
        }

        let chunkRetryCount = 0
        const MAX_RETRIES = 3
        let chunkSuccess = false

        while (!chunkSuccess && chunkRetryCount <= MAX_RETRIES) {
            try {
                const chunkResults = await prisma.$transaction(async (tx) => {
                    const results: any[] = []
                    for (let i = 0; i < chunk.length; i++) {
                        const sql = chunk[i]
                        if (chunk.length > 5 && i % Math.ceil(chunk.length / 5) === 0) {
                            if (logger) {
                                logger.debug(`[executeBatch] Chunk ${chunkNum}/${totalChunks} progress: ${i}/${chunk.length} statements executed`)
                            }
                        }
                        const result = await (tx as any).$executeRawUnsafe(sql)
                        results.push(result)
                    }
                    if (logger) {
                        logger.debug(`[executeBatch] Chunk ${chunkNum}/${totalChunks} complete: ${chunk.length} statements executed`)
                    }
                    return results
                }, {
                    maxWait: 60000, // 60 seconds to acquire connection
                    timeout: 300000 // 5 minutes for transaction to complete
                })

                allResults.push(...chunkResults)
                chunkSuccess = true
            } catch (error: any) {
                // Retry transient errors
                if (isTransientError(error) && chunkRetryCount < MAX_RETRIES) {
                    chunkRetryCount++
                    const waitMs = 1000 * Math.pow(2, chunkRetryCount - 1) // Exponential backoff
                    if (logger) {
                        logger.warn(`[executeBatch] Chunk ${chunkNum}/${totalChunks} failed (attempt ${chunkRetryCount}/${MAX_RETRIES}), retrying in ${waitMs}ms...`, {
                            error: error.message,
                            code: error.code
                        })
                    }
                    await new Promise(resolve => setTimeout(resolve, waitMs))
                } else {
                    // Non-transient error or max retries reached
                    throw error
                }
            }
        }
    }

    return allResults
}

/**
 * Combine multiple INSERT statements into multi-row INSERTs
 * Reduces the number of $executeRawUnsafe calls dramatically
 *
 * @deprecated This function uses fragile string-based SQL parsing and should not be used for new code.
 * Use Prisma.join() with Prisma.sql template literals instead for reliable multi-row INSERTs.
 * See bulkUpsertCVEMetadata() for the recommended pattern.
 *
 * Example:
 *   Input: ["INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (2)"]
 *   Output: ["INSERT INTO t VALUES (1), (2)"]
 */
function combineInsertStatements(statements: string[], batchSize: number, logger?: Logger): string[] {
    if (statements.length === 0) return []

    // Filter out undefined, null, or non-string statements
    const validStatements = statements.filter((stmt): stmt is string => {
        if (typeof stmt !== 'string' || !stmt) {
            if (logger) {
                logger.warn('[combineInsertStatements] Skipping invalid statement', { type: typeof stmt, value: stmt })
            }
            return false
        }
        return true
    })

    if (validStatements.length === 0) {
        if (logger) {
            logger.warn('[combineInsertStatements] No valid statements to process')
        }
        return []
    }

    const combined: string[] = []
    const chunks = chunkArray(validStatements, batchSize)

    for (const chunk of chunks) {
        if (chunk.length === 0) continue

        // Normalize whitespace in the first statement for parsing
        const firstStmt = chunk[0].replace(/\s+/g, ' ').trim()
        const valuesIndex = firstStmt.toUpperCase().indexOf(' VALUES ')

        if (valuesIndex === -1) {
            // Not an INSERT statement, execute as-is
            combined.push(...chunk)
            continue
        }

        // Extract the base INSERT part (before VALUES keyword)
        const baseInsert = firstStmt.substring(0, valuesIndex + 7).trim() // Include "VALUES"

        // Extract ON CONFLICT clause from the first statement
        // Use a more robust regex that handles the full clause including DO UPDATE
        // [\s\S]+ matches any character including newlines (since . doesn't match newlines by default)
        // Support both: ON CONFLICT (...) DO ... and ON CONFLICT DO ... (without conflict target)
        const onConflictMatch = firstStmt.match(/\s+ON\s+CONFLICT\s*(?:\([^)]+\)\s+)?DO\s+(?:NOTHING|UPDATE\s+SET\s+[\s\S]+)$/i)
        const onConflictClause = onConflictMatch ? ' ' + onConflictMatch[0].trim() : ''

        // Extract VALUES clauses from all statements
        const valuesClauses: string[] = []
        for (const stmt of chunk) {
            // Additional safety check
            if (typeof stmt !== 'string' || !stmt) {
                if (logger) {
                    logger.warn('[combineInsertStatements] Skipping invalid statement in chunk', { type: typeof stmt })
                }
                continue
            }

            // Normalize whitespace
            const normalizedStmt = stmt.replace(/\s+/g, ' ').trim()
            const stmtValuesIndex = normalizedStmt.toUpperCase().indexOf(' VALUES ')
            if (stmtValuesIndex === -1) continue

            // Extract everything after "VALUES "
            let afterValues = normalizedStmt.substring(stmtValuesIndex + 8)

            // Remove ON CONFLICT clause if present
            // Look for the pattern: ON CONFLICT(...) DO ... or ON CONFLICT DO ... (without conflict target)
            // [\s\S]+ matches any character including newlines
            const conflictPattern = /\s+ON\s+CONFLICT\s*(?:\([^)]+\)\s+)?DO\s+(?:NOTHING|UPDATE\s+SET\s+[\s\S]+)$/i
            afterValues = afterValues.replace(conflictPattern, '').trim()

            if (afterValues) {
                valuesClauses.push(afterValues)
            }
        }

        if (valuesClauses.length === 0) {
            if (logger) {
                logger.warn('[combineInsertStatements] No valid VALUES clauses extracted, using original statements')
            }
            combined.push(...chunk)
            continue
        }

        // Combine into single multi-row INSERT
        const combinedValues = valuesClauses.join(', ')
        const combinedStmt = `${baseInsert} ${combinedValues} ${onConflictClause}`.trim()

        // Validate the combined statement has basic structure
        if (!combinedStmt.includes('INSERT INTO') || !combinedStmt.includes('VALUES')) {
            if (logger) {
                logger.error('[combineInsertStatements] Invalid combined statement generated, using original statements')
            }
            combined.push(...chunk)
            continue
        }

        combined.push(combinedStmt)
    }

    return combined
}

/**
 * Generate an array of UUIDs
 */
export function generateUUIDs(count: number): string[] {
    return Array.from({ length: count }, () => crypto.randomUUID())
}

/**
 * Bulk upsert CVENumberingAuthority (CNA) records using PostgreSQL transactions
 *
 * Uses INSERT ... ON CONFLICT DO UPDATE for true upsert behavior
 * Primary key: orgId
 */
export async function bulkUpsertCNA(
    prisma: PrismaClient,
    records: Array<{
        orgId: string
        shortName: string
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (records.length === 0) {
        return result
    }

    if (logger) {
        logger.info(`[bulkUpsertCNA] Processing ${records.length} records using PostgreSQL transactions`)
    }

    // Build SQL statements
    const statements: string[] = []
    for (const record of records) {
        const sql = `
            INSERT INTO "CVENumberingAuthority" (
                "orgId", "shortName"
            ) VALUES (
                ${escapeSqlString(record.orgId)},
                ${escapeSqlString(record.shortName)}
            )
            ON CONFLICT("orgId") DO UPDATE SET
                "shortName" = excluded."shortName"
        `
        statements.push(sql)
    }

    const batchSize = 500
    const expectedBatches = Math.ceil(statements.length / batchSize)
    if (logger) {
        logger.info(`[bulkUpsertCNA] Processing ${statements.length} records using ${expectedBatches} multi-row INSERT(s)`)
    }

    try {
        await executeBatch(prisma, statements, batchSize, 0, logger)
        result.recordsProcessed = statements.length
        result.batches = expectedBatches
    } catch (error) {
        result.success = false
        result.recordsFailed += statements.length
        result.errors.push(`Transaction failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    if (logger) {
        logger.info(`[bulkUpsertCNA] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    return result
}

/**
 * Bulk upsert CVEMetadata records using PostgreSQL transactions
 *
 * Uses INSERT ... ON CONFLICT DO UPDATE for true upsert behavior
 * Composite key: (cveId, source) allows multiple sources per CVE
 */
export async function bulkUpsertCVEMetadata(
    prisma: PrismaClient,
    records: Array<{
        cveId: string
        source: string
        dataVersion: string
        state: string
        datePublished: number | Date
        dateUpdated?: number | Date | null
        dateReserved?: number | Date | null
        vectorString?: string | null
        title?: string | null
        sourceAdvisoryRef?: string | null
        affectedVendor?: string | null
        affectedProduct?: string | null
        affectedVersionsJSON?: string | null
        cpesJSON?: string | null
        cnaOrgId?: string | null
        rawFilePath?: string | null
        lastFetchedAt: number | Date
        lastEnriched?: number | Date | null
        fetchCount?: number | null
        rawDataJSON?: string | null
        scorecardUuid?: string | null
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (records.length === 0) {
        return result
    }

    if (logger) {
        logger.info(`[bulkUpsertCVEMetadata] Processing ${records.length} records using Prisma.join()`)
    }

    // Process in batches optimized for Cloudflare Workers CPU limits
    // Reduced from 100 to 25 to avoid timeout issues
    // 25 records = ~525 parameters vs 100 records = 2,100 parameters
    const batchSize = 25
    const batches = chunkArray(records, batchSize)

    if (logger) {
        logger.info(`[bulkUpsertCVEMetadata] Processing ${records.length} records in ${batches.length} batches`)
    }

    for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]
        if (logger) {
            logger.debug(`[bulkUpsertCVEMetadata] Processing batch ${i + 1}/${batches.length} (${batch.length} records)`)
        }

        try {
            // Build value tuples using Prisma.sql for safe parameterization
            const values = batch.map(record => {
                // Convert Date to Unix timestamp and ensure integers (floor all numbers)
                const datePublished = typeof record.datePublished === 'number'
                    ? Math.floor(record.datePublished)
                    : Math.floor(record.datePublished.getTime() / 1000)
                const dateUpdated = record.dateUpdated
                    ? (typeof record.dateUpdated === 'number' ? Math.floor(record.dateUpdated) : Math.floor(record.dateUpdated.getTime() / 1000))
                    : null
                const dateReserved = record.dateReserved
                    ? (typeof record.dateReserved === 'number' ? Math.floor(record.dateReserved) : Math.floor(record.dateReserved.getTime() / 1000))
                    : null
                const lastFetchedAt = typeof record.lastFetchedAt === 'number'
                    ? Math.floor(record.lastFetchedAt)
                    : Math.floor(record.lastFetchedAt.getTime() / 1000)
                const lastEnriched = record.lastEnriched
                    ? (typeof record.lastEnriched === 'number' ? Math.floor(record.lastEnriched) : Math.floor(record.lastEnriched.getTime() / 1000))
                    : null

                return Prisma.sql`(
                    ${record.cveId}, ${record.source}, ${record.dataVersion}, ${record.state},
                    ${datePublished}, ${dateUpdated}, ${dateReserved},
                    ${record.vectorString}, ${record.title}, ${record.sourceAdvisoryRef},
                    ${record.affectedVendor}, ${record.affectedProduct}, ${record.affectedVersionsJSON},
                    ${record.cpesJSON}, ${record.cnaOrgId}, ${record.rawFilePath},
                    ${lastFetchedAt}, ${lastEnriched}, ${record.fetchCount ?? 1},
                    ${record.rawDataJSON}, ${record.scorecardUuid}
                )`
            })

            // Execute multi-row INSERT with ON CONFLICT using Prisma.join()
            // Add timeout protection to prevent hanging on Cloudflare Workers
            const BATCH_TIMEOUT = 10000 // 10 seconds max per batch

            await Promise.race([
                prisma.$executeRaw`
                    INSERT INTO "CVEMetadata" (
                        "cveId", "source", "dataVersion", "state", "datePublished", "dateUpdated", "dateReserved",
                        "vectorString", "title", "sourceAdvisoryRef", "affectedVendor", "affectedProduct",
                        "affectedVersionsJSON", "cpesJSON", "cnaOrgId", "rawFilePath", "lastFetchedAt", "lastEnriched",
                        "fetchCount", "rawDataJSON", "scorecardUuid"
                    ) VALUES ${Prisma.join(values)}
                    ON CONFLICT("cveId", "source") DO UPDATE SET
                        "dataVersion" = excluded."dataVersion",
                        "state" = excluded."state",
                        "datePublished" = excluded."datePublished",
                        "dateUpdated" = excluded."dateUpdated",
                        "dateReserved" = excluded."dateReserved",
                        "vectorString" = excluded."vectorString",
                        "title" = excluded."title",
                        "sourceAdvisoryRef" = excluded."sourceAdvisoryRef",
                        "affectedVendor" = excluded."affectedVendor",
                        "affectedProduct" = excluded."affectedProduct",
                        "affectedVersionsJSON" = excluded."affectedVersionsJSON",
                        "cpesJSON" = excluded."cpesJSON",
                        "cnaOrgId" = excluded."cnaOrgId",
                        "rawFilePath" = excluded."rawFilePath",
                        "lastFetchedAt" = excluded."lastFetchedAt",
                        "lastEnriched" = excluded."lastEnriched",
                        "fetchCount" = "CVEMetadata"."fetchCount" + 1,
                        "rawDataJSON" = excluded."rawDataJSON",
                        "scorecardUuid" = excluded."scorecardUuid"
                `,
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error(`Batch ${i + 1} timed out after ${BATCH_TIMEOUT}ms`)), BATCH_TIMEOUT)
                )
            ])

            result.recordsProcessed += batch.length
            result.batches++
        } catch (error) {
            result.success = false
            result.recordsFailed += batch.length
            const errorMessage = error instanceof Error ? error.message : String(error)
            if (logger) {
                logger.error(`[bulkUpsertCVEMetadata] Batch ${i + 1} failed:`, errorMessage)
            }
            result.errors.push(`Batch ${i + 1} failed: ${errorMessage}`)

            // Continue with next batch rather than failing completely
            continue
        }
    }

    if (logger) {
        logger.info(`[bulkUpsertCVEMetadata] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    return result
}

/**
 * Bulk insert CVEDescription records using Prisma createMany with batching
 * Uses skipDuplicates to handle conflicts (INSERT ... ON CONFLICT DO NOTHING)
 *
 * Batches operations to avoid Cloudflare Workers timeout/memory limits
 */
export async function bulkInsertCVEDescriptions(
    prisma: PrismaClient,
    records: Array<{
        uuid?: string
        cveId: string
        source: string
        containerType: string
        adpOrgId?: string | null
        lang: string
        value: string
        supportingMedia?: string | null
        createdAt?: number
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (records.length === 0) {
        return result
    }

    // Pre-generate UUIDs and timestamps for records that don't have them
    const now = Math.floor(Date.now() / 1000)
    const recordsWithUUIDs = records.map(r => ({
        uuid: r.uuid || crypto.randomUUID(),
        cveId: r.cveId,
        source: r.source,
        containerType: r.containerType,
        adpOrgId: r.adpOrgId || null,
        lang: r.lang,
        value: r.value,
        supportingMedia: r.supportingMedia || null,
        createdAt: r.createdAt ? Math.floor(r.createdAt) : now
    }))

    // Batch the operations to avoid Workers timeout/memory limits
    const BATCH_SIZE = 500
    const batches = chunkArray(recordsWithUUIDs, BATCH_SIZE)

    if (logger) {
        logger.info(`[bulkInsertCVEDescriptions] Processing ${recordsWithUUIDs.length} records in ${batches.length} batches using createMany`)
    }

    for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]
        if (logger) {
            logger.debug(`[bulkInsertCVEDescriptions] Processing batch ${i + 1}/${batches.length} (${batch.length} records)`)
        }

        try {
            const createResult = await prisma.cVEDescription.createMany({
                data: batch,
                skipDuplicates: true // ON CONFLICT DO NOTHING
            })

            result.recordsProcessed += createResult.count
            result.batches++

            const duplicatesSkipped = batch.length - createResult.count
            if (duplicatesSkipped > 0 && logger) {
                logger.debug(`[bulkInsertCVEDescriptions] Batch ${i + 1} inserted ${createResult.count} records (${duplicatesSkipped} duplicates skipped)`)
            }
        } catch (error) {
            result.success = false
            result.recordsFailed += batch.length
            const errorMessage = error instanceof Error ? error.message : String(error)
            if (logger) {
                logger.error(`[bulkInsertCVEDescriptions] Batch ${i + 1} failed:`, errorMessage)
            }
            result.errors.push(`Batch ${i + 1} failed: ${errorMessage}`)

            // Continue with next batch rather than failing completely
            continue
        }
    }

    if (logger) {
        logger.info(`[bulkInsertCVEDescriptions] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    return result
}

/**
 * Bulk insert CVEMetadataReferences records using Prisma createMany with batching
 * Uses skipDuplicates to handle conflicts (INSERT ... ON CONFLICT DO NOTHING)
 *
 * Batches operations to avoid Cloudflare Workers timeout/memory limits
 */
export async function bulkInsertCVEReferences(
    prisma: PrismaClient,
    records: Array<{
        uuid?: string
        cveId: string
        source: string
        url: string
        type?: string | null
        referenceSource?: string | null
        title?: string | null
        createdAt?: number | null
        httpStatus?: number | null
        deadLinkCheckedAt?: number | null
        deadLink?: number | null
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (records.length === 0) {
        return result
    }

    const now = Math.floor(Date.now() / 1000)

    // Pre-generate UUIDs and set defaults
    const recordsWithDefaults = records.map(r => ({
        uuid: r.uuid || crypto.randomUUID(),
        cveId: r.cveId,
        source: r.source,
        url: r.url,
        type: r.type || 'reference',
        referenceSource: r.referenceSource || 'unknown',
        title: r.title || null,
        createdAt: r.createdAt ? Math.floor(r.createdAt) : now,
        httpStatus: r.httpStatus || null,
        deadLinkCheckedAt: r.deadLinkCheckedAt ? Math.floor(r.deadLinkCheckedAt) : null,
        deadLink: r.deadLink ?? 0
    }))

    // Batch the operations to avoid Workers timeout/memory limits
    const BATCH_SIZE = 500 // Cloudflare Workers-friendly batch size
    const batches = chunkArray(recordsWithDefaults, BATCH_SIZE)

    if (logger) {
        logger.info(`[bulkInsertCVEReferences] Processing ${recordsWithDefaults.length} records in ${batches.length} batches using createMany`)
    }

    for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]
        if (logger) {
            logger.debug(`[bulkInsertCVEReferences] Processing batch ${i + 1}/${batches.length} (${batch.length} records)`)
        }

        try {
            const createResult = await prisma.cVEMetadataReferences.createMany({
                data: batch,
                skipDuplicates: true // ON CONFLICT DO NOTHING
            })

            result.recordsProcessed += createResult.count
            result.batches++

            const duplicatesSkipped = batch.length - createResult.count
            if (duplicatesSkipped > 0 && logger) {
                logger.debug(`[bulkInsertCVEReferences] Batch ${i + 1} inserted ${createResult.count} records (${duplicatesSkipped} duplicates skipped)`)
            }
        } catch (error) {
            result.success = false
            result.recordsFailed += batch.length
            const errorMessage = error instanceof Error ? error.message : String(error)
            if (logger) {
                logger.error(`[bulkInsertCVEReferences] Batch ${i + 1} failed:`, errorMessage)
            }
            result.errors.push(`Batch ${i + 1} failed: ${errorMessage}`)

            // Continue with next batch rather than failing completely
            continue
        }
    }

    if (logger) {
        logger.info(`[bulkInsertCVEReferences] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    return result
}

/**
 * Bulk insert CVEProblemType records using Prisma createMany with batching
 * Uses skipDuplicates to handle conflicts (INSERT ... ON CONFLICT DO NOTHING)
 *
 * Batches operations to avoid Cloudflare Workers timeout/memory limits
 */
export async function bulkInsertCVEProblemTypes(
    prisma: PrismaClient,
    records: Array<{
        uuid?: string
        cveId: string
        source: string
        containerType: string
        adpOrgId?: string | null
        cweId?: string | null
        description?: string | null
        descriptionType?: string
        lang?: string
        createdAt?: number
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (records.length === 0) {
        return result
    }

    // Pre-generate UUIDs and timestamps
    const now = Math.floor(Date.now() / 1000)
    const recordsWithDefaults = records.map(r => ({
        uuid: r.uuid || crypto.randomUUID(),
        cveId: r.cveId,
        source: r.source,
        containerType: r.containerType,
        adpOrgId: r.adpOrgId || null,
        cweId: r.cweId || null,
        description: r.description || null,
        descriptionType: r.descriptionType || 'text',
        lang: r.lang || 'en',
        createdAt: r.createdAt ? Math.floor(r.createdAt) : now
    }))

    // Batch the operations to avoid Workers timeout/memory limits
    const BATCH_SIZE = 500
    const batches = chunkArray(recordsWithDefaults, BATCH_SIZE)

    if (logger) {
        logger.info(`[bulkInsertCVEProblemTypes] Processing ${recordsWithDefaults.length} records in ${batches.length} batches using createMany`)
    }

    for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]
        if (logger) {
            logger.info(`[bulkInsertCVEProblemTypes] Processing batch ${i + 1}/${batches.length} (${batch.length} records)`)
        }

        try {
            const createResult = await prisma.cVEProblemType.createMany({
                data: batch,
                skipDuplicates: true // ON CONFLICT DO NOTHING
            })

            result.recordsProcessed += createResult.count
            result.batches++

            const duplicatesSkipped = batch.length - createResult.count
            if (duplicatesSkipped > 0) {
                if (logger) {
                    logger.info(`[bulkInsertCVEProblemTypes] Batch ${i + 1} inserted ${createResult.count} records (${duplicatesSkipped} duplicates skipped)`)
                }
            }
        } catch (error) {
            result.success = false
            result.recordsFailed += batch.length
            const errorMessage = error instanceof Error ? error.message : String(error)
            if (logger) {
                logger.error(`[bulkInsertCVEProblemTypes] Batch ${i + 1} failed:`, errorMessage)
            }
            result.errors.push(`Batch ${i + 1} failed: ${errorMessage}`)

            // Continue with next batch rather than failing completely
            continue
        }
    }

    if (logger) {
        logger.info(`[bulkInsertCVEProblemTypes] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    return result
}

/**
 * Bulk insert VulnCheckKEV base records using PostgreSQL transactions with RETURNING clause
 * Returns a map of unique keys to actual UUIDs in the database for reliable child record insertion
 *
 * Approach: Execute individual INSERTs with RETURNING to ensure we get back the actual UUIDs
 * that ended up in the database (whether new or existing from ON CONFLICT).
 * This is more reliable than trying to query back and match by potentially inconsistent keys.
 */
export async function bulkInsertVulnCheckKEV(
    prisma: PrismaClient,
    records: Array<{
        uuid: string
        vendorProject?: string | null
        product?: string | null
        shortDescription?: string | null
        vulnerabilityName?: string | null
        requiredAction?: string | null
        knownRansomwareCampaignUse?: string | null
        reportedExploitedByVulnCheckCanaries?: number
        dateAdded: number | Date
        createdAt: number
        r2Bucket?: string | null
        r2Key?: string | null
    }>,
    logger?: Logger
): Promise<BulkOperationResult & { uuidMap: Map<string, string> }> {
    const result: BulkOperationResult & { uuidMap: Map<string, string> } = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: [],
        uuidMap: new Map()
    }

    if (logger) {
        logger.info(`[bulkInsertVulnCheckKEV] Processing ${records.length} records individually with RETURNING for reliability`)
    }

    // Execute individual INSERTs with RETURNING to get back actual UUIDs
    // This is the most reliable approach - database tells us exactly what UUIDs it used
    for (const record of records) {
        try {
            const dateAdded = record.dateAdded instanceof Date
                ? Math.floor(record.dateAdded.getTime() / 1000)
                : record.dateAdded

            const sql = `
                INSERT INTO "VulnCheckKEV" (
                    "uuid", "vendorProject", "product", "shortDescription", "vulnerabilityName",
                    "requiredAction", "knownRansomwareCampaignUse", "reportedExploitedByVulnCheckCanaries",
                    "dateAdded", "createdAt", "r2Bucket", "r2Key"
                ) VALUES (
                    ${escapeSqlString(record.uuid)},
                    ${escapeSqlString(record.vendorProject)},
                    ${escapeSqlString(record.product)},
                    ${escapeSqlString(record.shortDescription)},
                    ${escapeSqlString(record.vulnerabilityName)},
                    ${escapeSqlString(record.requiredAction)},
                    ${escapeSqlString(record.knownRansomwareCampaignUse)},
                    ${formatSqlValue(record.reportedExploitedByVulnCheckCanaries ?? 0)},
                    ${formatSqlValue(dateAdded)},
                    ${formatSqlValue(record.createdAt)},
                    ${escapeSqlString(record.r2Bucket)},
                    ${escapeSqlString(record.r2Key)}
                )
                ON CONFLICT ("vendorProject", "product", "vulnerabilityName") DO UPDATE SET
                    "shortDescription" = excluded."shortDescription",
                    "requiredAction" = excluded."requiredAction",
                    "knownRansomwareCampaignUse" = excluded."knownRansomwareCampaignUse",
                    "reportedExploitedByVulnCheckCanaries" = excluded."reportedExploitedByVulnCheckCanaries",
                    "dateAdded" = excluded."dateAdded",
                    "r2Bucket" = excluded."r2Bucket",
                    "r2Key" = excluded."r2Key"
                RETURNING "uuid", "vendorProject", "product", "vulnerabilityName"
            `

            // Use $queryRawUnsafe to get RETURNING results
            const rows = await (prisma as any).$queryRawUnsafe(sql) as Array<{
                uuid: string
                vendorProject: string | null
                product: string | null
                vulnerabilityName: string | null
            }>

            if (rows.length > 0) {
                const row = rows[0]
                // Build unique key using same normalization logic as caller
                const vendorProject = row.vendorProject?.trim() || ''
                const product = row.product?.trim() || ''
                const vulnerabilityName = row.vulnerabilityName?.trim() || ''
                const uniqueKey = `${vendorProject}|||${product}|||${vulnerabilityName}`

                result.uuidMap.set(uniqueKey, row.uuid)
                result.recordsProcessed++
            } else {
                result.recordsFailed++
                result.errors.push(`No RETURNING result for record with vendorProject="${record.vendorProject}"`)
            }
        } catch (error) {
            result.success = false
            result.recordsFailed++
            const errorMsg = error instanceof Error ? error.message : String(error)
            result.errors.push(`Failed to insert record: ${errorMsg}`)
        }
    }

    if (logger) {
        logger.info(`[bulkInsertVulnCheckKEV] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed, ${result.uuidMap.size} UUIDs mapped`)
    }
    if (result.errors.length > 0) {
        if (logger) {
            logger.error(`[bulkInsertVulnCheckKEV] Errors (showing first 3):`, result.errors.slice(0, 3))
        }
    }
    return result
}

/**
 * Bulk insert VulnCheckKEVCVE link records using PostgreSQL transactions
 * Uses INSERT ... ON CONFLICT DO NOTHING with unique constraint on (kevUuid, cveId, source)
 */
export async function bulkInsertVulnCheckKEVCVE(
    prisma: PrismaClient,
    records: Array<{
        kevUuid: string
        cveId: string
        source: string
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (logger) {
        logger.info(`[bulkInsertVulnCheckKEVCVE] Processing ${records.length} records using PostgreSQL transactions`)
    }

    // Import uuid function
    const { v4: uuidv4 } = await import('uuid')

    // Build SQL statements
    const statements: string[] = []
    for (const record of records) {
        const uuid = uuidv4()
        const sql = `
            INSERT INTO "VulnCheckKEVCVE" (
                "uuid", "kevUuid", "cveId", "source"
            ) VALUES (
                ${escapeSqlString(uuid)}, ${escapeSqlString(record.kevUuid)}, ${escapeSqlString(record.cveId)}, ${escapeSqlString(record.source)}
            )
            ON CONFLICT ("kevUuid", "cveId", "source") DO NOTHING
        `
        statements.push(sql)
    }
    const batchSize = 500
    const expectedBatches = Math.ceil(statements.length / batchSize)
    if (logger) {
        logger.info(`[bulkInsertVulnCheckKEVCVE] Processing ${statements.length} records using ${expectedBatches} multi-row INSERT(s)`)
    }
    try {
        await executeBatch(prisma, statements, batchSize)
        result.recordsProcessed = statements.length
        result.batches = expectedBatches
    } catch (error) {
        result.success = false
        result.recordsFailed += statements.length
        result.errors.push(`Transaction failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    if (logger) {
        logger.info(`[bulkInsertVulnCheckKEVCVE] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    if (result.errors.length > 0) {
        if (logger) {
            logger.error(`[bulkInsertVulnCheckKEVCVE] Errors (showing first 3):`, result.errors.slice(0, 3))
        }
    }
    return result
}

/**
 * Bulk insert VulnCheckKEVCWE records using PostgreSQL transactions
 * Uses INSERT ... ON CONFLICT DO NOTHING with unique constraint on (kevUuid, cweId)
 */
export async function bulkInsertVulnCheckKEVCWE(
    prisma: PrismaClient,
    records: Array<{
        kevUuid: string
        cweId: string
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (logger) {
        logger.info(`[bulkInsertVulnCheckKEVCWE] Processing ${records.length} records using PostgreSQL transactions`)
    }

    // Import uuid function
    const { v4: uuidv4 } = await import('uuid')

    // Build SQL statements
    const statements: string[] = []
    for (const record of records) {
        const uuid = uuidv4()
        const sql = `
            INSERT INTO "VulnCheckKEVCWE" (
                "uuid", "kevUuid", "cweId"
            ) VALUES (
                ${escapeSqlString(uuid)}, ${escapeSqlString(record.kevUuid)}, ${escapeSqlString(record.cweId)}
            )
            ON CONFLICT DO NOTHING
        `
        statements.push(sql)
    }
    const batchSize = 500
    const expectedBatches = Math.ceil(statements.length / batchSize)
    if (logger) {
        logger.info(`[bulkInsertVulnCheckKEVCWE] Processing ${statements.length} records using ${expectedBatches} multi-row INSERT(s)`)
    }
    try {
        await executeBatch(prisma, statements, batchSize)
        result.recordsProcessed = statements.length
        result.batches = expectedBatches
    } catch (error) {
        result.success = false
        result.recordsFailed += statements.length
        result.errors.push(`Transaction failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    if (logger) {
        logger.info(`[bulkInsertVulnCheckKEVCWE] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    if (result.errors.length > 0) {
        if (logger) {
            logger.error(`[bulkInsertVulnCheckKEVCWE] Errors (showing first 3):`, result.errors.slice(0, 3))
        }
    }
    return result
}

/**
 * Bulk insert VulnCheckXDB records using PostgreSQL transactions
 * Uses INSERT ... ON CONFLICT DO NOTHING (uuid is primary key)
 */
export async function bulkInsertVulnCheckXDB(
    prisma: PrismaClient,
    records: Array<{
        uuid?: string
        kevUuid: string
        xdbId: string
        xdbUrl: string
        dateAdded: Date
        exploitType?: string | null
        cloneSshUrl: string
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    const now = Math.floor(Date.now() / 1000)

    // Pre-generate UUIDs
    const recordsWithUUIDs = records.map(r => ({
        ...r,
        uuid: r.uuid || crypto.randomUUID()
    }))

    if (logger) {
        logger.info(`[bulkInsertVulnCheckXDB] Processing ${recordsWithUUIDs.length} records using PostgreSQL transactions`)
    }

    // Build SQL statements
    const statements: string[] = []
    const skippedRecords: any[] = []

    for (const record of recordsWithUUIDs) {
        // Validate and convert dateAdded to Unix timestamp
        let dateAddedTimestamp: number

        if (record.dateAdded instanceof Date) {
            const timestamp = record.dateAdded.getTime()

            // Check if date is valid
            if (isNaN(timestamp)) {
                if (logger) {
                    logger.warn(`[bulkInsertVulnCheckXDB] Skipping record with invalid date`, {
                        xdbId: record.xdbId,
                        dateAdded: record.dateAdded
                    })
                }
                skippedRecords.push(record)
                continue
            }

            // Convert to seconds and validate range (INT in PostgreSQL: -2147483648 to 2147483647)
            dateAddedTimestamp = Math.floor(timestamp / 1000)

            if (dateAddedTimestamp < -2147483648 || dateAddedTimestamp > 2147483647) {
                if (logger) {
                    logger.warn(`[bulkInsertVulnCheckXDB] Skipping record with out-of-range timestamp`, {
                        xdbId: record.xdbId,
                        dateAdded: record.dateAdded,
                        timestamp: dateAddedTimestamp
                    })
                }
                skippedRecords.push(record)
                continue
            }
        } else if (typeof record.dateAdded === 'number') {
            dateAddedTimestamp = record.dateAdded
        } else {
            if (logger) {
                logger.warn(`[bulkInsertVulnCheckXDB] Skipping record with invalid dateAdded type`, {
                    xdbId: record.xdbId,
                    dateAddedType: typeof record.dateAdded
                })
            }
            skippedRecords.push(record)
            continue
        }

        const sql = `
            INSERT INTO "VulnCheckXDB" (
                "uuid", "kevUuid", "xdbId", "xdbUrl", "dateAdded", "exploitType", "cloneSshUrl", "createdAt"
            ) VALUES (
                ${escapeSqlString(record.uuid)}, ${escapeSqlString(record.kevUuid)},
                ${escapeSqlString(record.xdbId)}, ${escapeSqlString(record.xdbUrl)},
                ${dateAddedTimestamp}, ${formatSqlValue(record.exploitType)},
                ${escapeSqlString(record.cloneSshUrl)}, ${now}
            )
            ON CONFLICT ("kevUuid", "xdbId") DO NOTHING
        `
        statements.push(sql)
    }

    if (skippedRecords.length > 0) {
        if (logger) {
            logger.warn(`[bulkInsertVulnCheckXDB] Skipped ${skippedRecords.length} records due to date validation failures`)
        }
    }
    const batchSize = 500
    const expectedBatches = Math.ceil(statements.length / batchSize)
    if (logger) {
        logger.info(`[bulkInsertVulnCheckXDB] Processing ${statements.length} records using ${expectedBatches} multi-row INSERT(s)`)
    }
    try {
        await executeBatch(prisma, statements, batchSize)
        result.recordsProcessed = statements.length
        result.batches = expectedBatches
    } catch (error) {
        result.success = false
        result.recordsFailed += statements.length
        result.errors.push(`Transaction failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    if (logger) {
        logger.info(`[bulkInsertVulnCheckXDB] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    if (result.errors.length > 0) {
        if (logger) {
            logger.error(`[bulkInsertVulnCheckXDB] Errors (showing first 3):`, result.errors.slice(0, 3))
        }
    }
    return result
}

/**
 * Bulk insert VulnCheckReportedExploitation records using PostgreSQL transactions
 * Uses INSERT ... ON CONFLICT DO NOTHING (uuid is primary key)
 */
export async function bulkInsertVulnCheckReportedExploitation(
    prisma: PrismaClient,
    records: Array<{
        uuid?: string
        kevUuid: string
        url: string
        dateAdded: Date
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    const now = Math.floor(Date.now() / 1000)

    // Pre-generate UUIDs
    const recordsWithUUIDs = records.map(r => ({
        ...r,
        uuid: r.uuid || crypto.randomUUID()
    }))

    if (logger) {
        logger.info(`[bulkInsertVulnCheckReportedExploitation] Processing ${recordsWithUUIDs.length} records using PostgreSQL transactions`)
    }

    // Build SQL statements
    const statements: string[] = []
    const skippedRecords: any[] = []

    for (const record of recordsWithUUIDs) {
        // Validate and convert dateAdded to Unix timestamp
        let dateAddedTimestamp: number

        if (record.dateAdded instanceof Date) {
            const timestamp = record.dateAdded.getTime()

            // Check if date is valid
            if (isNaN(timestamp)) {
                if (logger) {
                    logger.warn(`[bulkInsertVulnCheckReportedExploitation] Skipping record with invalid date`, {
                        url: record.url,
                        dateAdded: record.dateAdded
                    })
                }
                skippedRecords.push(record)
                continue
            }

            // Convert to seconds and validate range (INT in PostgreSQL: -2147483648 to 2147483647)
            dateAddedTimestamp = Math.floor(timestamp / 1000)

            if (dateAddedTimestamp < -2147483648 || dateAddedTimestamp > 2147483647) {
                if (logger) {
                    logger.warn(`[bulkInsertVulnCheckReportedExploitation] Skipping record with out-of-range timestamp`, {
                        url: record.url,
                        dateAdded: record.dateAdded,
                        timestamp: dateAddedTimestamp
                    })
                }
                skippedRecords.push(record)
                continue
            }
        } else if (typeof record.dateAdded === 'number') {
            dateAddedTimestamp = record.dateAdded
        } else {
            if (logger) {
                logger.warn(`[bulkInsertVulnCheckReportedExploitation] Skipping record with invalid dateAdded type`, {
                    url: record.url,
                    dateAddedType: typeof record.dateAdded
                })
            }
            skippedRecords.push(record)
            continue
        }

        const sql = `
            INSERT INTO "VulnCheckReportedExploitation" (
                "uuid", "kevUuid", "url", "dateAdded", "createdAt"
            ) VALUES (
                ${escapeSqlString(record.uuid)}, ${escapeSqlString(record.kevUuid)},
                ${escapeSqlString(record.url)}, ${dateAddedTimestamp},
                ${now}
            )
            ON CONFLICT ("kevUuid", "url") DO NOTHING
        `
        statements.push(sql)
    }

    if (skippedRecords.length > 0) {
        if (logger) {
            logger.warn(`[bulkInsertVulnCheckReportedExploitation] Skipped ${skippedRecords.length} records due to date validation failures`)
        }
    }
    const batchSize = 500
    const expectedBatches = Math.ceil(statements.length / batchSize)
    if (logger) {
        logger.info(`[bulkInsertVulnCheckReportedExploitation] Processing ${statements.length} records using ${expectedBatches} multi-row INSERT(s)`)
    }
    try {
        await executeBatch(prisma, statements, batchSize)
        result.recordsProcessed = statements.length
        result.batches = expectedBatches
    } catch (error) {
        result.success = false
        result.recordsFailed += statements.length
        result.errors.push(`Transaction failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    if (logger) {
        logger.info(`[bulkInsertVulnCheckReportedExploitation] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    if (result.errors.length > 0) {
        if (logger) {
            logger.error(`[bulkInsertVulnCheckReportedExploitation] Errors (showing first 3):`, result.errors.slice(0, 3))
        }
    }
    return result
}

/**
 * Bulk insert CrowdSecSighting records using PostgreSQL transactions
 * Simple INSERT (no unique constraints)
 */
export async function bulkInsertCrowdSecSightings(
    prisma: PrismaClient,
    records: Array<{
        crowdSecLogUuid?: string
        cveId: string
        source: string
        ip?: string | null
        reputation?: string | null
        confidence?: string | null
        backgroundNoiseScore?: number | null
        asName?: string | null
        asNum?: number | null
        ipRange24?: string | null
        ipRange24Reputation?: string | null
        ipRange24Score?: number | null
        locationCountry?: string | null
        locationCity?: string | null
        locationLat?: number | null
        locationLon?: number | null
        reverseDns?: string | null
        behaviorsCsv?: string | null
        attackDetailsCsv?: string | null
        classificationsCsv?: string | null
        mitreTechniquesCsv?: string | null
        targetCountriesJSON?: string | null
        firstSeen?: number | null
        lastSeen?: number | null
        falsePositivesCount?: number | null
        scoreLastDayAggressiveness?: number | null
        scoreLastDayThreat?: number | null
        scoreLastDayTrust?: number | null
        scoreLastWeekAggressiveness?: number | null
        scoreLastWeekThreat?: number | null
        scoreLastWeekTrust?: number | null
        scoreLastMonthAggressiveness?: number | null
        scoreLastMonthThreat?: number | null
        scoreLastMonthTrust?: number | null
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    const now = Math.floor(Date.now() / 1000)

    if (logger) {
        logger.info(`[bulkInsertCrowdSecSightings] Processing ${records.length} records using PostgreSQL transactions`)
    }

    // Build SQL statements
    const statements: string[] = []
    for (const record of records) {
        const uuid = crypto.randomUUID()
        const sql = `
            INSERT INTO "CrowdSecSighting" (
                "uuid", "crowdSecLogUuid", "cveId", "source", "ip", "reputation", "confidence",
                "backgroundNoiseScore", "asName", "asNum", "ipRange24", "ipRange24Reputation",
                "ipRange24Score", "locationCountry", "locationCity", "locationLat", "locationLon",
                "reverseDns", "behaviorsCsv", "attackDetailsCsv", "classificationsCsv",
                "mitreTechniquesCsv", "targetCountriesJSON", "firstSeen", "lastSeen",
                "falsePositivesCount", "scoreLastDayAggressiveness", "scoreLastDayThreat",
                "scoreLastDayTrust", "scoreLastWeekAggressiveness", "scoreLastWeekThreat",
                "scoreLastWeekTrust", "scoreLastMonthAggressiveness", "scoreLastMonthThreat",
                "scoreLastMonthTrust", "createdAt", "updatedAt"
            ) VALUES (
                ${escapeSqlString(uuid)}, ${formatSqlValue(record.crowdSecLogUuid)},
                ${escapeSqlString(record.cveId)}, ${escapeSqlString(record.source)},
                ${formatSqlValue(record.ip)}, ${formatSqlValue(record.reputation)},
                ${formatSqlValue(record.confidence)}, ${formatSqlValue(record.backgroundNoiseScore)},
                ${formatSqlValue(record.asName)}, ${formatSqlValue(record.asNum)},
                ${formatSqlValue(record.ipRange24)}, ${formatSqlValue(record.ipRange24Reputation)},
                ${formatSqlValue(record.ipRange24Score)}, ${formatSqlValue(record.locationCountry)},
                ${formatSqlValue(record.locationCity)}, ${formatSqlValue(record.locationLat)},
                ${formatSqlValue(record.locationLon)}, ${formatSqlValue(record.reverseDns)},
                ${formatSqlValue(record.behaviorsCsv)}, ${formatSqlValue(record.attackDetailsCsv)},
                ${formatSqlValue(record.classificationsCsv)}, ${formatSqlValue(record.mitreTechniquesCsv)},
                ${formatSqlValue(record.targetCountriesJSON)}, ${formatSqlValue(record.firstSeen)},
                ${formatSqlValue(record.lastSeen)}, ${record.falsePositivesCount ?? 0},
                ${formatSqlValue(record.scoreLastDayAggressiveness)}, ${formatSqlValue(record.scoreLastDayThreat)},
                ${formatSqlValue(record.scoreLastDayTrust)}, ${formatSqlValue(record.scoreLastWeekAggressiveness)},
                ${formatSqlValue(record.scoreLastWeekThreat)}, ${formatSqlValue(record.scoreLastWeekTrust)},
                ${formatSqlValue(record.scoreLastMonthAggressiveness)}, ${formatSqlValue(record.scoreLastMonthThreat)},
                ${formatSqlValue(record.scoreLastMonthTrust)}, ${now}, ${now}
            )
        `
        statements.push(sql)
    }
    const batchSize = 500
    const expectedBatches = Math.ceil(statements.length / batchSize)
    if (logger) {
        logger.info(`[bulkInsertCrowdSecSightings] Processing ${statements.length} records using ${expectedBatches} multi-row INSERT(s)`)
    }
    try {
        await executeBatch(prisma, statements, batchSize)
        result.recordsProcessed = statements.length
        result.batches = expectedBatches
    } catch (error) {
        result.success = false
        result.recordsFailed += statements.length
        result.errors.push(`Transaction failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    if (logger) {
        logger.info(`[bulkInsertCrowdSecSightings] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    return result
}

/**
 * Bulk upsert CVEMetric records using Prisma.join()
 * Uses INSERT ... ON CONFLICT DO UPDATE for true upsert behavior
 *
 * Composite unique key: (cveId, source, containerType, adpOrgId, metricType, vectorString)
 */
export async function bulkUpsertCVEMetrics(
    prisma: PrismaClient,
    records: Array<{
        uuid?: string
        cveId: string
        source: string
        containerType: 'cna' | 'adp'
        adpOrgId?: string | null
        metricType: string
        vectorString?: string | null
        baseScore?: number | null
        baseSeverity?: string | null
        metricFormat?: string | null
        scenariosJSON?: string | null
        otherType?: string | null
        otherContent?: string | null
        createdAt?: number
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (records.length === 0) {
        return result
    }

    const now = Math.floor(Date.now() / 1000)

    if (logger) {
        logger.info(`[bulkUpsertCVEMetrics] Processing ${records.length} records using Prisma.join()`)
    }

    // Process in batches optimized for Cloudflare Workers CPU limits
    // Reduced from 100 to 25 to avoid timeout issues with complex ON CONFLICT UPDATE
    // 25 records = ~350 parameters (14 fields) vs 100 records = 1,400 parameters
    // This reduces PostgreSQL query planning overhead and fits within Workers CPU limits
    const batchSize = 25
    const batches = chunkArray(records, batchSize)

    if (logger) {
        logger.info(`[bulkUpsertCVEMetrics] Processing ${records.length} records in ${batches.length} batches`)
    }

    for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]
        if (logger) {
            logger.info(`[bulkUpsertCVEMetrics] Processing batch ${i + 1}/${batches.length} (${batch.length} records)`)
        }

        try {
            // Build value tuples using Prisma.sql for safe parameterization
            const values = batch.map(record => {
                const uuid = record.uuid || crypto.randomUUID()
                const createdAt = record.createdAt ? Math.floor(record.createdAt) : now

                return Prisma.sql`(
                    ${uuid}, ${record.cveId}, ${record.source}, ${record.containerType},
                    ${record.adpOrgId}, ${record.metricType}, ${record.vectorString},
                    ${record.baseScore}, ${record.baseSeverity}, ${record.metricFormat},
                    ${record.scenariosJSON}, ${record.otherType}, ${record.otherContent}, ${createdAt}
                )`
            })

            // Execute multi-row INSERT with ON CONFLICT using Prisma.join()
            // Add timeout protection to prevent hanging on Cloudflare Workers
            // With reduced batch size (25 records), expected execution time is 1-2 seconds
            // 10-second timeout provides safety margin while failing fast if something goes wrong
            const BATCH_TIMEOUT = 10000 // 10 seconds max per batch

            await Promise.race([
                prisma.$executeRaw`
                    INSERT INTO "CVEMetric" (
                        "uuid", "cveId", "source", "containerType", "adpOrgId", "metricType", "vectorString",
                        "baseScore", "baseSeverity", "metricFormat", "scenariosJSON", "otherType", "otherContent", "createdAt"
                    ) VALUES ${Prisma.join(values)}
                    ON CONFLICT("cveId", "source", "containerType", "adpOrgId", "metricType", "vectorString") DO UPDATE SET
                        "baseScore" = excluded."baseScore",
                        "baseSeverity" = excluded."baseSeverity",
                        "metricFormat" = excluded."metricFormat",
                        "scenariosJSON" = excluded."scenariosJSON",
                        "otherType" = excluded."otherType",
                        "otherContent" = excluded."otherContent"
                `,
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error(`Batch ${i + 1} timed out after ${BATCH_TIMEOUT}ms`)), BATCH_TIMEOUT)
                )
            ])

            result.recordsProcessed += batch.length
            result.batches++
        } catch (error) {
            result.success = false
            result.recordsFailed += batch.length
            const errorMessage = error instanceof Error ? error.message : String(error)
            if (logger) {
                logger.error(`[bulkUpsertCVEMetrics] Batch ${i + 1} failed:`, errorMessage)
            }
            result.errors.push(`Batch ${i + 1} failed: ${errorMessage}`)

            // Continue with next batch rather than failing completely
            continue
        }
    }

    if (logger) {
        logger.info(`[bulkUpsertCVEMetrics] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    return result
}

/**
 * Bulk insert CVEAffected records using PostgreSQL transactions
 * Uses INSERT ... ON CONFLICT DO UPDATE for reliability
 *
 * Unique constraint: (cveId, source, containerType, affectedHash)
 * The affectedHash is an MD5 hash of vendor|product|collectionURL|packageName
 * This ensures each vendor/product combination per CVE is stored exactly once
 */
import { calculateAffectedHash } from '@/shared/utils/cve-affected-hash'

export async function bulkInsertCVEAffected(
    prisma: PrismaClient,
    records: Array<{
        cveId: string
        source: string
        containerType: string
        adpOrgId?: string | null
        vendor?: string | null
        product?: string | null
        collectionURL?: string | null
        packageName?: string | null
        cpes?: string | null
        modules?: string | null
        programFiles?: string | null
        programRoutines?: string | null
        platforms?: string | null
        repo?: string | null
        defaultStatus?: string | null
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    const now = Math.floor(Date.now() / 1000)

    if (logger) {
        logger.info(`[bulkInsertCVEAffected] Processing ${records.length} records with validation`)
    }

    // Validate and prepare records
    const validRecords: typeof records = []
    const invalidRecords: Array<{ record: any; reason: string }> = []

    for (const record of records) {
        // Validate: must have cveId, source, and at least vendor or product
        if (!record.cveId || !record.source) {
            invalidRecords.push({ record, reason: 'Missing cveId or source' })
            continue
        }

        if (!record.vendor && !record.product && !record.collectionURL && !record.packageName) {
            invalidRecords.push({ record, reason: 'No vendor, product, collectionURL, or packageName specified' })
            continue
        }

        validRecords.push(record)
    }

    if (invalidRecords.length > 0) {
        if (logger) {
            logger.warn(`[bulkInsertCVEAffected] Skipped ${invalidRecords.length} invalid records`)
        }
        result.recordsFailed = invalidRecords.length
        invalidRecords.slice(0, 3).forEach(({ record, reason }) => {
            result.errors.push(`Invalid record for CVE ${record.cveId}: ${reason}`)
        })
    }

    if (validRecords.length === 0) {
        if (logger) {
            logger.info(`[bulkInsertCVEAffected] No valid records to process`)
        }
        return result
    }

    // Use smaller batches for reliability - easier to debug issues
    const batchSize = 100
    const batches = chunkArray(validRecords, batchSize)

    if (logger) {
        logger.info(`[bulkInsertCVEAffected] Processing ${validRecords.length} valid records in ${batches.length} batches`)
    }

    // Process each batch with individual error handling
    for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]
        if (logger) {
            logger.info(`[bulkInsertCVEAffected] Processing batch ${i + 1}/${batches.length} (${batch.length} records)`)
        }

        try {
            // Use individual upserts in a transaction for better error visibility
            await prisma.$transaction(async (tx) => {
                for (const record of batch) {
                    // Calculate hash for unique constraint
                    const affectedHash = calculateAffectedHash(
                        record.vendor,
                        record.product,
                        record.collectionURL,
                        record.packageName
                    )

                    await (tx as any).cVEAffected.upsert({
                        where: {
                            cveId_source_containerType_affectedHash: {
                                cveId: record.cveId,
                                source: record.source,
                                containerType: record.containerType,
                                affectedHash
                            }
                        },
                        create: {
                            cveId: record.cveId,
                            source: record.source,
                            containerType: record.containerType,
                            adpOrgId: record.adpOrgId,
                            vendor: record.vendor,
                            product: record.product,
                            collectionURL: record.collectionURL,
                            packageName: record.packageName,
                            affectedHash,
                            cpes: record.cpes,
                            modules: record.modules,
                            programFiles: record.programFiles,
                            programRoutines: record.programRoutines,
                            platforms: record.platforms,
                            repo: record.repo,
                            defaultStatus: record.defaultStatus,
                            createdAt: now
                        },
                        update: {
                            adpOrgId: record.adpOrgId,
                            cpes: record.cpes,
                            modules: record.modules,
                            programFiles: record.programFiles,
                            programRoutines: record.programRoutines,
                            platforms: record.platforms,
                            repo: record.repo,
                            defaultStatus: record.defaultStatus
                        }
                    })
                }
            }, {
                maxWait: 60000, // 60 seconds to acquire connection
                timeout: 300000 // 5 minutes for transaction to complete
            })

            result.recordsProcessed += batch.length
            result.batches++
        } catch (error) {
            result.success = false
            result.recordsFailed += batch.length
            const errorMessage = error instanceof Error ? error.message : String(error)
            if (logger) {
                logger.error(`[bulkInsertCVEAffected] Batch ${i + 1} failed:`, errorMessage)
            }
            result.errors.push(`Batch ${i + 1} failed: ${errorMessage}`)

            // Continue with next batch rather than failing completely
            continue
        }
    }

    if (logger) {
        logger.info(`[bulkInsertCVEAffected] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    if (result.errors.length > 0) {
        if (logger) {
            logger.error(`[bulkInsertCVEAffected] Errors encountered:`, result.errors.slice(0, 5))
        }
    }

    return result
}

/**
 * Bulk insert or update CISA KEV records using PostgreSQL transactions
 * Uses INSERT ... ON CONFLICT DO UPDATE for true upsert behavior
 *
 * Composite unique key: (cveID, source)
 */
export async function bulkInsertCisaKEV(
    prisma: PrismaClient,
    records: Array<{
        cveID: string
        source: string
        vendorProject: string
        product: string
        vulnerabilityName: string
        dateAdded: number | Date
        shortDescription: string
        requiredAction: string
        dueDate: number | Date
        knownRansomwareCampaignUse?: string | null
        notes?: string | null
        cwesJSON?: string | null
        fetchedAt: number
        catalogVersion?: string | null
        catalogReleaseDate?: number | null
        createdAt: number
    }>,
    logger?: Logger
): Promise<BulkOperationResult> {
    const result: BulkOperationResult = {
        success: true,
        recordsProcessed: 0,
        recordsFailed: 0,
        batches: 0,
        errors: []
    }

    if (logger) {
        logger.info(`[bulkInsertCisaKEV] Processing ${records.length} records using PostgreSQL transactions`)
    }

    // Build SQL statements
    const statements: string[] = []
    for (const record of records) {
        const dateAdded = record.dateAdded instanceof Date
            ? Math.floor(record.dateAdded.getTime() / 1000)
            : record.dateAdded

        const dueDate = record.dueDate instanceof Date
            ? Math.floor(record.dueDate.getTime() / 1000)
            : record.dueDate

        const sql = `
            INSERT INTO "Kev" (
                "cveID", "source", "vendorProject", "product", "vulnerabilityName",
                "dateAdded", "shortDescription", "requiredAction", "dueDate",
                "knownRansomwareCampaignUse", "notes", "cwesJSON", "fetchedAt",
                "catalogVersion", "catalogReleaseDate", "createdAt", "updatedAt"
            ) VALUES (
                ${escapeSqlString(record.cveID)},
                ${escapeSqlString(record.source)},
                ${escapeSqlString(record.vendorProject)},
                ${escapeSqlString(record.product)},
                ${escapeSqlString(record.vulnerabilityName)},
                ${formatSqlValue(dateAdded)},
                ${escapeSqlString(record.shortDescription)},
                ${escapeSqlString(record.requiredAction)},
                ${formatSqlValue(dueDate)},
                ${formatSqlValue(record.knownRansomwareCampaignUse)},
                ${formatSqlValue(record.notes)},
                ${formatSqlValue(record.cwesJSON)},
                ${formatSqlValue(record.fetchedAt)},
                ${formatSqlValue(record.catalogVersion)},
                ${formatSqlValue(record.catalogReleaseDate)},
                ${formatSqlValue(record.createdAt)},
                ${formatSqlValue(record.createdAt)}
            )
            ON CONFLICT("cveID", "source") DO UPDATE SET
                "vendorProject" = excluded."vendorProject",
                "product" = excluded."product",
                "vulnerabilityName" = excluded."vulnerabilityName",
                "dateAdded" = excluded."dateAdded",
                "shortDescription" = excluded."shortDescription",
                "requiredAction" = excluded."requiredAction",
                "dueDate" = excluded."dueDate",
                "knownRansomwareCampaignUse" = excluded."knownRansomwareCampaignUse",
                "notes" = excluded."notes",
                "cwesJSON" = excluded."cwesJSON",
                "fetchedAt" = excluded."fetchedAt",
                "catalogVersion" = excluded."catalogVersion",
                "catalogReleaseDate" = excluded."catalogReleaseDate",
                "updatedAt" = ${formatSqlValue(record.createdAt)}
        `
        statements.push(sql)
    }
    const batchSize = 500
    const expectedBatches = Math.ceil(statements.length / batchSize)
    if (logger) {
        logger.info(`[bulkInsertCisaKEV] Processing ${statements.length} records using ${expectedBatches} multi-row INSERT(s)`)
    }
    try {
        await executeBatch(prisma, statements, batchSize)
        result.recordsProcessed = statements.length
        result.batches = expectedBatches
    } catch (error) {
        result.success = false
        result.recordsFailed += statements.length
        result.errors.push(`Transaction failed: ${error instanceof Error ? error.message : String(error)}`)
    }

    if (logger) {
        logger.info(`[bulkInsertCisaKEV] Complete: ${result.recordsProcessed} processed, ${result.recordsFailed} failed`)
    }
    return result
}
