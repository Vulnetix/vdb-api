import { default as axios } from 'axios';
import { ApiCache } from './api-cache';
import { timeAgo as momentTimeAgo } from './datetime';
import { FetchResponse } from './interfaces';
import { normalizeGhsaIdentifier, getExploitDBRawPath, getMetasploitModulePath, retrieveExternalFileFromR2, storeExternalFileToR2 } from './vdb-identifier';
import { getExistingCvssVector, generateCvssVectorForCVE } from './cwe-to-cvss-mapper';

// User-Agent constant for all HTTP requests
export const VULNETIX_USER_AGENT = "Vulnetix-Client/1.0"

/**
 * Calculate SHA256 hash of a buffer using Web Crypto API
 * This works in both Cloudflare Workers and Node.js environments
 *
 * @param buffer - Buffer or Uint8Array to hash
 * @returns Hex-encoded SHA256 hash string
 *
 * @example
 * ```typescript
 * const fileBuffer = await file.arrayBuffer()
 * const hash = await calculateSHA256(Buffer.from(fileBuffer))
 * console.log(hash) // "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
 * ```
 */
export async function calculateSHA256(buffer: Buffer | Uint8Array): Promise<string> {
    // Use Web Crypto API (available in both Workers and modern Node.js)
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)

    // Convert ArrayBuffer to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    return hashHex
}

/**
 * Calculate SHA256 hash of a file in R2 using chunked range requests
 * This avoids loading the entire file into memory, making it suitable for large files
 *
 * @param r2Bucket - R2 bucket containing the file
 * @param r2Path - Path to the file in R2
 * @param options - Optional configuration
 * @param options.chunkSize - Size of each chunk to read (default: 50MB)
 * @param options.logger - Optional logger for progress tracking
 * @returns Hex-encoded SHA256 hash string
 *
 * @example
 * ```typescript
 * const sha256 = await calculateSHA256FromR2(
 *   env.r2artifacts,
 *   'vulncheck-nvd/archive.zip',
 *   { logger }
 * )
 * console.log(sha256) // "599a32f73b076bd1d10478eb74f69e7c..."
 * ```
 */
export async function calculateSHA256FromR2(
    r2Bucket: R2Bucket,
    r2Path: string,
    options?: {
        chunkSize?: number
        logger?: { debug: (msg: string) => void; info: (msg: string) => void }
    }
): Promise<string> {
    const chunkSize = options?.chunkSize || 50 * 1024 * 1024 // Default 50MB chunks
    const logger = options?.logger

    // Get file size
    const head = await r2Bucket.head(r2Path)
    if (!head) {
        throw new Error(`File not found in R2: ${r2Path}`)
    }

    const totalBytes = head.size
    logger?.info?.(`Calculating SHA256 for ${r2Path} (${(totalBytes / (1024 * 1024)).toFixed(2)}MB)`)

    // Read file in chunks using R2 range requests
    let offset = 0
    const chunks: Uint8Array[] = []

    while (offset < totalBytes) {
        const bytesToRead = Math.min(chunkSize, totalBytes - offset)
        const r2Obj = await r2Bucket.get(r2Path, {
            range: {
                offset,
                length: bytesToRead
            }
        })

        if (!r2Obj) {
            throw new Error(`Failed to read file from R2 at offset ${offset}: ${r2Path}`)
        }

        const chunk = new Uint8Array(await r2Obj.arrayBuffer())
        chunks.push(chunk)
        offset += bytesToRead

        logger?.debug?.(`SHA256 progress: ${((offset / totalBytes) * 100).toFixed(1)}%`)
    }

    // Concatenate chunks and calculate SHA256
    const fullData = new Uint8Array(totalBytes)
    let writeOffset = 0
    for (const chunk of chunks) {
        fullData.set(chunk, writeOffset)
        writeOffset += chunk.length
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', fullData)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const sha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    logger?.info?.(`SHA256 calculated: ${sha256}`)

    return sha256
}

/**
 * PostgreSQL INT type range constants
 * INT: -2,147,483,648 to 2,147,483,647
 */
const PG_INT_MIN = -2147483648
const PG_INT_MAX = 2147483647

/**
 * Validates and converts a timestamp to PostgreSQL-safe INT format (seconds since epoch)
 *
 * @param timestamp - Timestamp in milliseconds or seconds (number) or Date string
 * @param fieldName - Optional field name for error messages
 * @returns Validated timestamp in seconds, or null if invalid
 *
 * @example
 * ```typescript
 * // Convert milliseconds to seconds
 * const ts1 = validateTimestamp(Date.now()) // Returns seconds
 *
 * // Handle Date string
 * const ts2 = validateTimestamp(new Date().toISOString()) // Returns seconds
 *
 * // Already in seconds
 * const ts3 = validateTimestamp(1700000000) // Returns as-is
 *
 * // Invalid or out of range
 * const ts4 = validateTimestamp(999999999999999) // Returns null and logs error
 * ```
 */
interface Logger {
    warn: (message: string, data?: any) => void
    debug: (message: string, data?: any) => void
    error: (message: string, data?: any) => void
    info: (message: string, data?: any) => void
}

export function validateTimestamp(timestamp: number | string | Date | null | undefined, fieldName: string = 'timestamp', logger?: Logger): number | null {
    if (timestamp === null || timestamp === undefined) {
        return null
    }

    let timestampMs: number

    // Convert to milliseconds first
    if (timestamp instanceof Date) {
        timestampMs = timestamp.getTime()
    } else if (typeof timestamp === 'string') {
        timestampMs = new Date(timestamp).getTime()
    } else if (typeof timestamp === 'number') {
        // Auto-detect if timestamp is in milliseconds or seconds
        // Timestamps > 10 billion are definitely in milliseconds (corresponds to year 2286 in seconds)
        timestampMs = timestamp > 10000000000 ? timestamp : timestamp * 1000
    } else {
        if (logger) {
            logger.error(`[validateTimestamp] Invalid ${fieldName} type: ${typeof timestamp}`)
        }
        return null
    }

    // Check if conversion resulted in valid number
    if (isNaN(timestampMs)) {
        if (logger) {
            logger.error(`[validateTimestamp] Invalid ${fieldName} value (NaN)`)
        }
        return null
    }

    // Convert to seconds
    const timestampSeconds = Math.floor(timestampMs / 1000)

    // Validate PostgreSQL INT range
    if (timestampSeconds < PG_INT_MIN || timestampSeconds > PG_INT_MAX) {
        if (logger) {
            logger.error(`[validateTimestamp] ${fieldName} out of PostgreSQL INT range: ${timestampSeconds} (original: ${timestamp})`)
        }
        return null
    }

    return timestampSeconds
}

export class OSV {
    headers: { 'Accept': string, 'User-Agent': string }
    baseUrl: string
    logger?: Logger

    constructor(baseUrl?: string, logger?: Logger) {
        this.headers = {
            'Accept': 'application/json',
            'User-Agent': VULNETIX_USER_AGENT,
        }
        // Use provided baseUrl, or default to OSV API v1
        this.baseUrl = baseUrl || "https://api.osv.dev/v1"
        this.logger = logger
    }
    async fetchJSON(url, body = null, method = 'POST') {
        try {
            if (method === 'POST' && typeof body !== "string") {
                body = JSON.stringify(body)
            }
            const response = await axios({
                url,
                method,
                headers: this.headers,
                data: body,
                validateStatus: () => true // Accept all status codes
            })
            const respText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
            const ok = response.status >= 200 && response.status < 300
            if (!ok) {
                // Log based on severity - not all non-2xx responses are errors
                const logMessage = `OSV API response: ${method} ${url} - ${response.status} ${response.statusText}`

                if (response.status === 404) {
                    // 404 is expected when a CVE/vulnerability isn't in OSV's database
                    if (this.logger) {
                        this.logger.debug(`[OSV] ${logMessage}`)
                        this.logger.debug(`[OSV] Response: ${respText}`)
                    }
                } else if (response.status >= 400 && response.status < 500) {
                    // Other 4xx are client errors - log as warnings
                    if (this.logger) {
                        this.logger.warn(`[OSV] ${logMessage}`)
                        this.logger.warn(`[OSV] Request headers: ${JSON.stringify(this.headers, null, 2)}`)
                        this.logger.warn(`[OSV] Response: ${respText}`)
                    }
                } else {
                    // 5xx server errors are actual problems
                    if (this.logger) {
                        this.logger.error(`[OSV] ${logMessage}`)
                        this.logger.error(`[OSV] Request headers: ${JSON.stringify(this.headers, null, 2)}`)
                        this.logger.error(`[OSV] Response headers: ${JSON.stringify(response.headers, null, 2)}`)
                        this.logger.error(`[OSV] Response: ${respText}`)
                    }
                }
            }
            if (!isJSON(respText)) {
                return { ok, status: response.status, statusText: response.statusText, error: { message: `Response not JSON format` }, content: respText, url } as FetchResponse
            }
            const content = JSON.parse(respText)
            return { ok, status: response.status, statusText: response.statusText, content, url } as FetchResponse
        } catch (e) {
            const match = e.stack?.match(/(\d+):(\d+)/)
            const lineno = match?.[1] || 'unknown'
            const colno = match?.[2] || 'unknown'
            if (this.logger) {
                this.logger.error(`[OSV] Network/API error: ${e.message}`)
                if (lineno !== 'unknown') {
                    this.logger.error(`[OSV] Error location: line ${lineno}, col ${colno}`)
                }
            }

            return { url, status: 500, ok: false, statusText: 'Network Error', error: { message: e.message, lineno, colno } } as FetchResponse
        }
    }
    async queryBatch(prisma, orgId, memberUuid, queryArr) {
        // https://google.github.io/osv.dev/post-v1-querybatch/
        const url = `${this.baseUrl}/querybatch`
        const results = []
        for (const queries of chunkArray(queryArr, 1000)) {
            const resp = await this.fetchJSON(url, { queries }) as FetchResponse
            if (resp?.content?.results) {
                results.push(...resp.content.results)
            }
        }
        return results
    }

    async queryBatchByEcosystem(prisma, orgId, memberUuid, queryArr, ecosystem?: string) {
        // Group queries by ecosystem for better error handling
        const url = `${this.baseUrl}/querybatch`
        const results = []

        // Add debugging for ecosystem
        if (ecosystem && this.logger) {
            this.logger.debug(`[OSV] Querying ${queryArr.length} packages for ecosystem: ${ecosystem}`)
        }

        for (const queries of chunkArray(queryArr, 1000)) {
            try {
                // Log sample queries for debugging
                if (queries.length > 0 && this.logger) {
                    this.logger.debug(`[OSV] Sample query for ecosystem ${ecosystem}:`, JSON.stringify(queries[0], null, 2))
                }

                const resp = await this.fetchJSON(url, { queries }) as FetchResponse
                if (resp?.content?.results) {
                    results.push(...resp.content.results)
                } else if (!resp?.ok) {
                    // Enhanced error logging with ecosystem context
                    if (this.logger) {
                        this.logger.error(`[OSV] Batch query failed for ecosystem: ${ecosystem}`)
                        this.logger.error(`[OSV] OSV message: ${resp.content?.message}`)
                        this.logger.error(`[OSV] Failed queries sample:`, JSON.stringify(queries.slice(0, 3), null, 2))
                        this.logger.error(`[OSV] Response:`, resp)
                    }
                    throw new Error(`OSV API error for ecosystem ${ecosystem}: ${resp?.status} ${resp?.statusText} - ${resp.content?.message}`)
                }
            } catch (error) {
                if (this.logger) {
                    this.logger.error(`[OSV] Error querying ecosystem ${ecosystem}:`, error)
                    this.logger.error(`[OSV] Problematic queries:`, JSON.stringify(queries.slice(0, 5), null, 2))
                }
                throw error
            }
        }
        return results
    }
    async query(prisma, orgId, memberUuid, vulnId, r2cache = null) {
        // Check R2 cache first if available
        if (r2cache) {
            const cache = new ApiCache({ r2bucket: r2cache });

            return await cache.withCache('osv', vulnId, async () => {
                return await this._performQuery(prisma, orgId, memberUuid, vulnId);
            });
        }

        // Fallback to direct query if no cache
        return await this._performQuery(prisma, orgId, memberUuid, vulnId);
    }

    private async _performQuery(prisma, orgId, memberUuid, vulnId) {
        // https://google.github.io/osv.dev/get-v1-vulns/
        // Normalize GHSA identifiers to correct case format (GHSA-xxxx-xxxx-xxxx)
        // OSV API is case-sensitive and requires uppercase prefix + lowercase identifier
        const normalizedVulnId = normalizeGhsaIdentifier(vulnId)
        const url = `${this.baseUrl}/vulns/${normalizedVulnId}`
        const resp = await this.fetchJSON(url, null, "GET") as FetchResponse

        if (resp?.ok && resp?.content) {
            // Success - found the vulnerability
            return resp.content
        } else if (resp?.status === 404) {
            // 404 is a valid response - the CVE/vulnerability simply isn't in OSV's database
            if (this.logger) {
                this.logger.debug(`[OSV] Vulnerability ${normalizedVulnId} not found in OSV database`)
            }
            return null
        } else {
            // Other errors (5xx, network errors, etc.)
            if (this.logger) {
                this.logger.error(`[OSV] Failed to query ${normalizedVulnId}: ${resp.status} ${resp.statusText}`)
            }
            return null
        }
    }
}

export class CESS {
    headers: { 'User-Agent': string }
    baseUrl: string

    constructor(baseUrl?: string) {
        this.headers = {
            'User-Agent': VULNETIX_USER_AGENT,
        }
        // Use provided baseUrl, or default to correct Coalition ESS API endpoint
        this.baseUrl = baseUrl || "https://ess-api.coalitioninc.com/cess"
    }

    /**
     * Helper function to delay execution
     */
    private async sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms))
    }

    async fetchJSON(url, method = 'GET', maxRetries = 3) {
        let lastError = null

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                const response = await axios({
                    url,
                    method,
                    headers: this.headers,
                    validateStatus: () => true // Accept all status codes
                })
                const respText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
                const ok = response.status >= 200 && response.status < 300
                if (!ok) {
                    console.error(`${method} ${url}`)
                    console.error(`req headers=${JSON.stringify(this.headers, null, 2)}`)
                    console.error(`resp headers=${JSON.stringify(response.headers, null, 2)}`)
                    console.error(respText)
                    console.error(`CESS error! status: ${response.status} ${response.statusText}`)
                }
                if (!isJSON(respText)) {
                    return { ok, status: response.status, statusText: response.statusText, error: { message: `Response not JSON format` }, content: respText, url } as FetchResponse
                }
                const content = JSON.parse(respText)
                return { ok, status: response.status, statusText: response.statusText, content, url } as FetchResponse
            } catch (e) {
                lastError = e
                const isNetworkError = e.code === 'ENOTFOUND' || e.code === 'ETIMEDOUT' || e.code === 'ECONNREFUSED' || e.code === 'ECONNRESET'

                // Only retry on network errors, not on other errors
                if (isNetworkError && attempt < maxRetries) {
                    const delay = Math.pow(2, attempt) * 1000 // Exponential backoff: 1s, 2s, 4s
                    console.warn(`[CESS] Network error on attempt ${attempt + 1}/${maxRetries + 1} for ${url}: ${e.message}. Retrying in ${delay}ms...`)
                    await this.sleep(delay)
                    continue
                }

                // No more retries or non-network error
                const match = e.stack?.match(/(\d+):(\d+)/)
                const lineno = match?.[1] || 'unknown'
                const colno = match?.[2] || 'unknown'
                console.error(`[CESS] Network/API error after ${attempt + 1} attempt(s): ${e.message}`)
                if (lineno !== 'unknown') {
                    console.error(`line ${lineno}, col ${colno}`)
                }

                return { url, status: 500, ok: false, statusText: 'Network Error', error: { message: e.message, lineno, colno, attempts: attempt + 1 } } as FetchResponse
            }
        }

        // Should never reach here, but just in case
        return { url, status: 500, ok: false, statusText: 'Network Error', error: { message: lastError?.message || 'Unknown error', attempts: maxRetries + 1 } } as FetchResponse
    }
    async query(prisma, orgId, memberUuid, cve, r2cache = null) {
        // Check R2 cache first if available
        if (r2cache) {
            const cache = new ApiCache({ r2bucket: r2cache });

            return await cache.withCache('cess', cve, async () => {
                return await this._performQuery(prisma, orgId, memberUuid, cve);
            });
        }

        // Fallback to direct query if no cache
        return await this._performQuery(prisma, orgId, memberUuid, cve);
    }

    private async _performQuery(prisma, orgId, memberUuid, cve) {
        // https://ess-api.coalitioninc.com/docs#/default/cve_details_cve__cve_id__get
        const url = `${this.baseUrl}/cve/${cve}`
        const resp = await this.fetchJSON(url) as FetchResponse
        if (resp?.content) {
            return resp.content
        }
    }

    /**
     * Converts a Date object to YYYY-MM-DD format in UTC
     */
    private toDateString(date: Date): string {
        const year = date.getUTCFullYear()
        const month = String(date.getUTCMonth() + 1).padStart(2, '0')
        const day = String(date.getUTCDate()).padStart(2, '0')
        return `${year}-${month}-${day}`
    }

    /**
     * Store CESS score in database
     */
    async storeInCache(prisma, cve: string, timelineEntry: any): Promise<void> {
        const currentTime = Math.floor(Date.now() / 1000) // Unix timestamp in seconds

        // Extract timeline_date and convert to Unix timestamp and dateString
        const timelineDateString = timelineEntry.timeline_date
        const dateObj = new Date(timelineDateString)
        const timelineDate = Math.floor(dateObj.getTime() / 1000) // Convert to Unix timestamp (seconds)
        const dateString = this.toDateString(dateObj)

        const probability = timelineEntry.cess?.probability_exploit_usage || 0
        const probabilityVariation = timelineEntry.cess?.probability_exploit_usage_variation || null
        const score = probability * 10 // Scale to 0-10
        const latestEntry = timelineEntry.latest_entry ? 1 : 0

        try {
            // Check if record exists for this exact timeline date
            const existing = await prisma.cessScore.findFirst({
                where: {
                    cve,
                    timelineDate
                }
            })

            if (existing) {
                // Update existing record
                await prisma.cessScore.update({
                    where: {
                        id: existing.id
                    },
                    data: {
                        score,
                        probabilityExploitUsage: probability,
                        probabilityExploitUsageVariation: probabilityVariation,
                        fetchedAt: currentTime,
                        latestEntry,
                        modelVersion: '1.0'
                    }
                })
            } else {
                // Create new record
                await prisma.cessScore.create({
                    data: {
                        cve,
                        dateString,
                        timelineDate,
                        score,
                        probabilityExploitUsage: probability,
                        probabilityExploitUsageVariation: probabilityVariation,
                        fetchedAt: currentTime,
                        modelVersion: '1.0',
                        createdAt: currentTime,
                        latestEntry
                    }
                })
            }
        } catch (error) {
            console.error(`[CESS] Failed to cache score for ${cve} on ${timelineDateString}:`, error)
        }
    }

    /**
     * Fetch and store historical CESS scores with pagination support
     * Also extracts and stores CVSS data from the latest timeline entry
     * @param prisma - Prisma client
     * @param orgId - Organization ID
     * @param memberUuid - Member UUID
     * @param cve - CVE identifier
     * @param pageSize - Number of results per page (default 100)
     */
    async fetchHistory(prisma, orgId: string, memberUuid: string, cve: string, pageSize: number = 100): Promise<void> {
        let currentPage = 1
        let totalStored = 0
        let hasMorePages = true
        let latestCvssData = null

        try {
            while (hasMorePages) {
                const url = `${this.baseUrl}/cve/${cve}/history?page=${currentPage}&page_size=${pageSize}`
                const resp = await this.fetchJSON(url) as FetchResponse

                if (!resp?.ok || !resp?.content?.results) {
                    console.error(`[CESS] History fetch failed for ${cve} at page ${currentPage}`)
                    console.error(`[CESS] Response status: ${resp?.status} ${resp?.statusText}`)
                    if (resp?.error) {
                        console.error(`[CESS] Error details:`, JSON.stringify(resp.error, null, 2))
                    }
                    break
                }

                const results = resp.content.results || []
                const total = resp.content.total || 0
                const page = resp.content.page || currentPage

                // Store all historical scores from this page
                for (const timelineEntry of results) {
                    if (timelineEntry.cess && timelineEntry.cess.probability_exploit_usage !== undefined) {
                        await this.storeInCache(prisma, cve, timelineEntry)
                        totalStored++
                    }

                    // Extract CVSS - prefer latest_entry, but capture any CVSS data
                    if (timelineEntry.cvss && timelineEntry.cvss.vector_string) {
                        if (timelineEntry.latest_entry) {
                            // Always use latest_entry if available (overrides any previous value)
                            latestCvssData = timelineEntry.cvss
                        } else if (!latestCvssData) {
                            // Use first available CVSS data as fallback
                            latestCvssData = timelineEntry.cvss
                        }
                    }
                }

                console.log(`[CESS] Page ${page}: Stored ${results.length} records for ${cve} (total so far: ${totalStored}/${total})`)

                // Check if there are more pages
                const recordsSoFar = page * pageSize
                if (recordsSoFar >= total || results.length === 0) {
                    hasMorePages = false
                } else {
                    currentPage++
                }
            }

            console.log(`[CESS] Completed: Stored ${totalStored} total historical scores for ${cve}`)

            // Store CVSS data as CVEMetadata if found
            if (latestCvssData && latestCvssData.vector_string) {
                console.log(`[CESS] Found CVSS data for ${cve}, storing as CVEMetadata with source='cess'`)
                await this.storeCVSSFromCESS(prisma, cve, latestCvssData)
            } else {
                // 3-TIER FALLBACK STRATEGY for CVEs without CVSS from CESS
                const now = Math.floor(Date.now() / 1000)
                let vectorString: string | null = null
                let vectorSource = 'cess'

                // TIER 1: Check for existing CVSS from other sources (NVD, OSV, CVE.org, GitHub, EUVD)
                console.log(`[CESS] No CVSS from CESS for ${cve}, checking other sources...`)
                const existingCvss = await getExistingCvssVector(prisma, cve)
                if (existingCvss) {
                    vectorString = existingCvss.vectorString
                    vectorSource = existingCvss.source
                    console.log(`[CESS] Found existing CVSS from ${existingCvss.source} for ${cve}: ${vectorString}`)
                }

                // TIER 2: Generate CVSS v4.0 from CWE + description
                if (!vectorString) {
                    console.log(`[CESS] No existing CVSS found for ${cve}, generating from CWE...`)
                    const generatedVector = await generateCvssVectorForCVE(prisma, cve)
                    if (generatedVector) {
                        vectorString = generatedVector
                        vectorSource = 'cess-generated'
                        console.log(`[CESS] Generated CVSS v4.0 from CWE for ${cve}: ${vectorString}`)
                    }
                }

                // TIER 3: Conservative default as last resort
                if (!vectorString) {
                    vectorString = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N'
                    console.log(`[CESS] Using conservative default CVSS for ${cve}: ${vectorString}`)
                }

                // Store CVEMetadata with the determined vector string
                await prisma.cVEMetadata.upsert({
                    where: {
                        cveId_source: {
                            cveId: cve,
                            source: 'cess'
                        }
                    },
                    create: {
                        cveId: cve,
                        source: 'cess',
                        dataVersion: vectorSource === 'cess-generated' ? 'cess-history-with-generated-cvss' : 'cess-history-only',
                        state: 'PUBLISHED',
                        datePublished: now,
                        dateUpdated: now,
                        dateReserved: null,
                        vectorString: vectorString,
                        title: null,
                        sourceAdvisoryRef: null,
                        affectedVendor: null,
                        affectedProduct: null,
                        affectedVersionsJSON: null,
                        cpesJSON: null,
                        lastFetchedAt: now,
                        fetchCount: 1,
                        rawDataJSON: null
                    },
                    update: {
                        // Update timestamp and vectorString if we have a better one
                        lastFetchedAt: now,
                        dateUpdated: now,
                        vectorString: vectorString,
                        fetchCount: {
                            increment: 1
                        }
                    }
                })

                console.log(`[CESS] Stored CVEMetadata for ${cve} with CVSS: ${vectorString} (source: ${vectorSource})`)
            }
        } catch (error) {
            console.error(`[CESS] History fetch failed for ${cve}:`, error)
            console.error(`[CESS] Error type: ${error?.constructor?.name}, Code: ${error?.code}`)
            if (error?.response) {
                console.error(`[CESS] Response status: ${error.response.status}`)
            }
        }
    }

    /**
     * Fetch and store exploit data from ExploitDB and Metasploit via CESS API
     * @param prisma - Prisma client
     * @param orgId - Organization ID
     * @param memberUuid - Member UUID
     * @param cve - CVE identifier
     * @param r2adapter - Optional R2 adapter for caching external files
     */
    async fetchExploits(prisma, orgId: string, memberUuid: string, cve: string, r2adapter: any = null): Promise<void> {
        try {
            const now = Math.floor(Date.now() / 1000)

            // CRITICAL: Ensure CVEMetadata (source='cess') exists BEFORE storing any references
            // This prevents foreign key constraint violations when creating CVEMetadataReferences
            await prisma.cVEMetadata.upsert({
                where: {
                    cveId_source: {
                        cveId: cve,
                        source: 'cess'
                    }
                },
                create: {
                    cveId: cve,
                    source: 'cess',
                    dataVersion: 'references-only',
                    state: 'PUBLISHED',
                    datePublished: now,
                    dateUpdated: now,
                    dateReserved: null,
                    vectorString: null, // No CVSS from references-only path
                    title: null,
                    sourceAdvisoryRef: null,
                    affectedVendor: null,
                    affectedProduct: null,
                    affectedVersionsJSON: null,
                    cpesJSON: null,
                    lastFetchedAt: now,
                    fetchCount: 1,
                    rawDataJSON: null
                },
                update: {
                    // Do not overwrite vectorString or other fields if already set by CVSS path
                    lastFetchedAt: now,
                    dateUpdated: now,
                    fetchCount: {
                        increment: 1
                    }
                }
            })

            // Fetch ExploitDB exploits
            const exploitDbStored = await this.fetchExploitDB(prisma, orgId, memberUuid, cve, r2adapter)

            // Fetch Metasploit modules (with R2 caching)
            const metasploitStored = await this.fetchMetasploit(prisma, orgId, memberUuid, cve, r2adapter)

            const storedThisRun = (exploitDbStored || 0) + (metasploitStored || 0)

            if (storedThisRun > 0) {
                console.log(`[CESS] Stored ${storedThisRun} exploit reference(s) for ${cve}`)
            } else {
                console.log(`[CESS] No new exploit references found for ${cve}`)
            }
        } catch (error) {
            console.error(`[CESS] Failed to fetch exploits for ${cve}:`, error)
        }
    }

    /**
     * Fetch and parse ExploitDB raw exploit data to extract metadata
     * Checks R2 cache first, then fetches from exploit-db.com/raw/{id} and caches the result
     * @param exploitId - ExploitDB exploit ID
     * @param r2adapter - Optional R2 adapter for caching external files
     */
    private async parseExploitDBRaw(exploitId: string, r2adapter: any = null): Promise<{ title: string; datePublished: string; author: string }> {
        try {
            let rawText: string | null = null

            // Step 1: Check R2 cache first (no TTL - permanent cache)
            if (r2adapter) {
                const r2Path = getExploitDBRawPath(exploitId)
                rawText = await retrieveExternalFileFromR2(r2adapter, r2Path, {
                    info: (msg) => console.log(msg),
                    warn: (msg) => console.warn(msg),
                    error: (msg) => console.error(msg)
                })

                if (rawText) {
                    console.log(`[CESS] ✅ Using cached ExploitDB raw data for ${exploitId} from R2`)
                }
            }

            // Step 2: Fetch from remote if not in cache
            if (!rawText) {
                const url = `https://www.exploit-db.com/raw/${exploitId}`
                console.log(`[CESS] 🔄 Fetching ExploitDB raw data for ${exploitId} from ${url}`)
                const response = await fetch(url, {
                    headers: {
                        'User-Agent': VULNETIX_USER_AGENT
                    }
                })

                if (!response.ok) {
                    console.warn(`[CESS] Failed to fetch ExploitDB raw data for ${exploitId}: ${response.status}`)
                    return { title: '', datePublished: '', author: '' }
                }

                rawText = await response.text()

                // Step 3: Store to R2 cache (no expiry)
                if (r2adapter && rawText) {
                    try {
                        const r2Path = getExploitDBRawPath(exploitId)
                        await storeExternalFileToR2(r2adapter, r2Path, rawText, 'text/plain', {
                            info: (msg) => console.log(msg),
                            warn: (msg) => console.warn(msg),
                            error: (msg) => console.error(msg)
                        })
                        console.log(`[CESS] 💾 Stored ExploitDB raw data for ${exploitId} to R2`)
                    } catch (r2Error: any) {
                        console.warn(`[CESS] Failed to cache ExploitDB raw data to R2: ${r2Error.message}`)
                    }
                }
            }

            // Parse the header comments for metadata
            let title = ''
            let datePublished = ''
            let author = ''

            // Split into lines and look for headers (both commented and plain text)
            const lines = rawText.split('\n')
            let nonCommentLines = 0

            for (const line of lines) {
                const trimmedLine = line.trim()

                // Count non-comment, non-empty lines
                if (!trimmedLine.startsWith('#') && !trimmedLine.startsWith('//') && trimmedLine.length > 0) {
                    nonCommentLines++
                    // Stop after 10 non-comment lines to handle exploits without # headers
                    if (nonCommentLines > 10) {
                        break
                    }
                }

                // Extract Exploit Title (supports #, ##, //, and plain text format)
                if (trimmedLine.match(/^#{1,2}\s*Exploit Title:/i) || trimmedLine.match(/^\/\/\s*Exploit Title:/i)) {
                    title = trimmedLine.replace(/^#{1,2}\s*Exploit Title:\s*/i, '').replace(/^\/\/\s*Exploit Title:\s*/i, '').trim()
                } else if (!title && trimmedLine.match(/^#{1,2}\s*Title:/i)) {
                    title = trimmedLine.replace(/^#{1,2}\s*Title:\s*/i, '').trim()
                } else if (!title && trimmedLine.match(/^Exploit Title:/i)) {
                    title = trimmedLine.replace(/^Exploit Title:\s*/i, '').trim()
                } else if (!title && trimmedLine.match(/^Title:/i)) {
                    title = trimmedLine.replace(/^Title:\s*/i, '').trim()
                }

                // Extract Date (various formats: Date, Date Published, etc.)
                if (trimmedLine.match(/^#{1,2}\s*Date.*:/i) || trimmedLine.match(/^\/\/\s*Date.*:/i)) {
                    datePublished = trimmedLine.replace(/^#{1,2}\s*Date.*:\s*/i, '').replace(/^\/\/\s*Date.*:\s*/i, '').trim()
                } else if (!datePublished && trimmedLine.match(/^Date.*:/i)) {
                    datePublished = trimmedLine.replace(/^Date.*:\s*/i, '').trim()
                }

                // Extract Author/Exploit Author
                if (trimmedLine.match(/^#{1,2}\s*(Exploit )?Author:/i) || trimmedLine.match(/^\/\/\s*(Exploit )?Author:/i)) {
                    author = trimmedLine.replace(/^#{1,2}\s*(Exploit )?Author:\s*/i, '').replace(/^\/\/\s*(Exploit )?Author:\s*/i, '').trim()
                } else if (!author && trimmedLine.match(/^(Exploit )?Author:/i)) {
                    author = trimmedLine.replace(/^(Exploit )?Author:\s*/i, '').trim()
                }

                // If first line is not a comment and looks like a title, use it
                if (!title && nonCommentLines === 1 && trimmedLine.length > 10 && !trimmedLine.includes(':')) {
                    title = trimmedLine
                }
            }

            return { title, datePublished, author }
        } catch (error) {
            console.error(`[CESS] Error parsing ExploitDB raw data for ${exploitId}:`, error)
            return { title: '', datePublished: '', author: '' }
        }
    }

    /**
     * Fetch ExploitDB exploits with pagination
     * @param r2adapter - Optional R2 adapter for caching external files
     */
    private async fetchExploitDB(prisma, orgId: string, memberUuid: string, cve: string, r2adapter: any = null): Promise<number> {
        let currentPage = 1
        let totalStored = 0
        let hasMorePages = true
        const pageSize = 50

        try {
            while (hasMorePages) {
                const url = `${this.baseUrl}/cve/${cve}/exploits/exploitdb?page=${currentPage}&page_size=${pageSize}`
                const resp = await this.fetchJSON(url) as FetchResponse

                if (!resp?.ok || !resp?.content?.results) {
                    if (currentPage === 1) {
                        console.log(`[CESS] No ExploitDB data for ${cve}`)
                    }
                    break
                }

                const results = resp.content.results || []
                const total = resp.content.total || 0

                // Store each exploit as a reference
                for (const exploit of results) {
                    const exploitUrl = `https://www.exploit-db.com/exploits/${exploit.exploit_id}`

                    // Fetch and parse the raw exploit data for metadata (with R2 caching)
                    const { title: extractedTitle, datePublished, author: extractedAuthor } = await this.parseExploitDBRaw(exploit.exploit_id, r2adapter)

                    const title = extractedTitle || `ExploitDB #${exploit.exploit_id}`
                    const author = extractedAuthor ? ` by ${extractedAuthor}` : ''

                    await this.storeExploitReference(prisma, cve, {
                        url: exploitUrl,
                        type: 'exploit',
                        title: `${title} (${exploit.type}${exploit.verified ? ' - Verified' : ''})${author}`.trim(),
                        referenceSource: 'ExploitDB',
                        createdAt: datePublished ? Math.floor(new Date(datePublished).getTime() / 1000) : Math.floor(Date.now() / 1000),
                    })
                    totalStored++
                }

                console.log(`[CESS] ExploitDB Page ${currentPage}: Stored ${results.length} exploits for ${cve}`)

                // Check if there are more pages
                const recordsSoFar = currentPage * pageSize
                if (recordsSoFar >= total || results.length === 0) {
                    hasMorePages = false
                } else {
                    currentPage++
                }
            }

            if (totalStored > 0) {
                console.log(`[CESS] Completed: Stored ${totalStored} ExploitDB references for ${cve}`)
            }
        } catch (error) {
            console.error(`[CESS] ExploitDB fetch failed for ${cve}:`, error)
        }

        return totalStored
    }

    /**
     * Fetch and parse Metasploit module raw file from GitHub
     * Checks R2 cache first, then fetches from GitHub and caches the result
     * @param modulePath - Module path (e.g., "/modules/exploits/windows/browser/ie_execcommand_uaf.rb")
     * @param r2adapter - Optional R2 adapter for caching external files
     */
    private async parseMetasploitRaw(modulePath: string, r2adapter: any = null): Promise<{ content: string; metadata: any }> {
        try {
            let rawContent: string | null = null

            // Step 1: Check R2 cache first (no TTL - permanent cache)
            if (r2adapter) {
                const r2Path = getMetasploitModulePath(modulePath)
                rawContent = await retrieveExternalFileFromR2(r2adapter, r2Path, {
                    info: (msg) => console.log(msg),
                    warn: (msg) => console.warn(msg),
                    error: (msg) => console.error(msg)
                })

                if (rawContent) {
                    console.log(`[CESS] ✅ Using cached Metasploit module for ${modulePath} from R2`)
                    return { content: rawContent, metadata: {} }
                }
            }

            // Step 2: Fetch from GitHub if not in cache
            // GitHub raw URL format: https://raw.githubusercontent.com/rapid7/metasploit-framework/master{modulePath}
            const rawUrl = `https://raw.githubusercontent.com/rapid7/metasploit-framework/master${modulePath}`
            console.log(`[CESS] 🔄 Fetching Metasploit module ${modulePath} from GitHub`)

            const response = await fetch(rawUrl, {
                headers: {
                    'User-Agent': VULNETIX_USER_AGENT
                }
            })

            if (!response.ok) {
                console.warn(`[CESS] Failed to fetch Metasploit module ${modulePath}: ${response.status}`)
                return { content: '', metadata: {} }
            }

            rawContent = await response.text()

            // Step 3: Store to R2 cache (no expiry)
            if (r2adapter && rawContent) {
                try {
                    const r2Path = getMetasploitModulePath(modulePath)
                    // Determine content type based on file extension
                    const contentType = modulePath.endsWith('.rb') ? 'text/x-ruby' : 'text/plain'
                    await storeExternalFileToR2(r2adapter, r2Path, rawContent, contentType, {
                        info: (msg) => console.log(msg),
                        warn: (msg) => console.warn(msg),
                        error: (msg) => console.error(msg)
                    })
                    console.log(`[CESS] 💾 Stored Metasploit module ${modulePath} to R2`)
                } catch (r2Error: any) {
                    console.warn(`[CESS] Failed to cache Metasploit module to R2: ${r2Error.message}`)
                }
            }

            return { content: rawContent || '', metadata: {} }
        } catch (error) {
            console.error(`[CESS] Error parsing Metasploit module ${modulePath}:`, error)
            return { content: '', metadata: {} }
        }
    }

    /**
     * Fetch Metasploit modules with pagination
     * @param r2adapter - Optional R2 adapter for caching external files
     */
    private async fetchMetasploit(prisma, orgId: string, memberUuid: string, cve: string, r2adapter: any = null): Promise<number> {
        let currentPage = 1
        let totalStored = 0
        let hasMorePages = true
        const pageSize = 50

        try {
            while (hasMorePages) {
                const url = `${this.baseUrl}/cve/${cve}/exploits/metasploit?page=${currentPage}&page_size=${pageSize}`
                const resp = await this.fetchJSON(url) as FetchResponse

                if (!resp?.ok || !resp?.content?.results) {
                    if (currentPage === 1) {
                        console.log(`[CESS] No Metasploit data for ${cve}`)
                    }
                    break
                }

                const results = resp.content.results || []
                const total = resp.content.total || 0

                // Store each module as a reference and cache raw file
                for (const module of results) {
                    // Metasploit modules don't have direct web URLs, but we can link to the GitHub source
                    const moduleUrl = `https://github.com/rapid7/metasploit-framework/blob/master${module.path}`
                    const title = `${module.name} (${module.type})`

                    // Fetch and cache the raw module file (with R2 caching)
                    if (module.path) {
                        await this.parseMetasploitRaw(module.path, r2adapter)
                    }

                    await this.storeExploitReference(prisma, cve, {
                        url: moduleUrl,
                        type: 'exploit',
                        title,
                        referenceSource: 'Metasploit',
                        createdAt: module?.disclosure_date ? Math.floor(new Date(module.disclosure_date).getTime() / 1000) : Math.floor(Date.now() / 1000),
                    })
                    totalStored++
                }

                console.log(`[CESS] Metasploit Page ${currentPage}: Stored ${results.length} modules for ${cve}`)

                // Check if there are more pages
                const recordsSoFar = currentPage * pageSize
                if (recordsSoFar >= total || results.length === 0) {
                    hasMorePages = false
                } else {
                    currentPage++
                }
            }

            if (totalStored > 0) {
                console.log(`[CESS] Completed: Stored ${totalStored} Metasploit references for ${cve}`)
            }
        } catch (error) {
            console.error(`[CESS] Metasploit fetch failed for ${cve}:`, error)
        }

        return totalStored
    }

    /**
     * Store exploit reference in CVEMetadataReferences
     */
    private async storeExploitReference(prisma, cveId: string, refData: {
        url: string
        type: string
        title: string
        createdAt: number
        referenceSource: string
    }): Promise<void> {
        try {
            // Check if reference already exists
            const existing = await prisma.cVEMetadataReferences.findFirst({
                where: {
                    cveId,
                    source: 'cess',
                    url: refData.url
                }
            })

            if (existing) {
                // Update existing reference
                await prisma.cVEMetadataReferences.update({
                    where: { uuid: existing.uuid },
                    data: {
                        title: refData.title,
                        type: refData.type,
                        referenceSource: refData.referenceSource,
                        createdAt: refData.createdAt,
                    }
                })
            } else {
                // Create new reference
                await prisma.cVEMetadataReferences.create({
                    data: {
                        cveId,
                        source: 'cess',
                        url: refData.url,
                        type: refData.type,
                        title: refData.title,
                        referenceSource: refData.referenceSource,
                        createdAt: refData.createdAt,
                        httpStatus: null,
                        deadLinkCheckedAt: null,
                        deadLink: 0
                    }
                })
            }
        } catch (error) {
            console.error(`[CESS] Failed to store exploit reference for ${cveId}:`, error)
        }
    }

    /**
     * Store CVSS data from CESS API as CVEMetadata
     */
    private async storeCVSSFromCESS(prisma, cveId: string, cvssData: any): Promise<void> {
        try {
            const now = Math.floor(Date.now() / 1000)

            // Build CVSS vector string (CESS provides it in standard format)
            const vectorString = cvssData.vector_string

            if (!vectorString) {
                console.warn(`[CESS] No vector string found in CVSS data for ${cveId}`)
                return
            }

            // Upsert CVEMetadata with CESS as source
            await prisma.cVEMetadata.upsert({
                where: {
                    cveId_source: {
                        cveId,
                        source: 'cess'
                    }
                },
                create: {
                    cveId,
                    source: 'cess',
                    dataVersion: cvssData.version || 'unknown',
                    state: 'PUBLISHED',
                    datePublished: now,
                    dateUpdated: now,
                    dateReserved: null,
                    vectorString,
                    title: null,
                    sourceAdvisoryRef: null,
                    affectedVendor: null,
                    affectedProduct: null,
                    affectedVersionsJSON: null,
                    cpesJSON: null,
                    lastFetchedAt: now,
                    fetchCount: 1,
                    rawDataJSON: JSON.stringify(cvssData)
                },
                update: {
                    vectorString,
                    dataVersion: cvssData.version || 'unknown',
                    dateUpdated: now,
                    lastFetchedAt: now,
                    fetchCount: {
                        increment: 1
                    },
                    rawDataJSON: JSON.stringify(cvssData)
                }
            })

            console.log(`[CESS] Stored CVSS vector ${vectorString} for ${cveId} (version ${cvssData.version})`)
        } catch (error) {
            console.error(`[CESS] Failed to store CVSS for ${cveId}:`, error)
        }
    }
}

export class EPSS {
    headers: { 'User-Agent': string }
    baseUrl: string

    constructor(baseUrl?: string) {
        this.headers = {
            'User-Agent': VULNETIX_USER_AGENT,
        }
        // Use provided baseUrl, or default to FIRST.org EPSS API v1
        this.baseUrl = baseUrl || "https://api.first.org/data/v1"
    }

    /**
     * Retry wrapper for transient database errors with exponential backoff
     */
    private async retryOnTransientError<T>(
        operation: () => Promise<T>,
        context: string,
        maxRetries: number = 3
    ): Promise<T> {
        let lastError: any

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                return await operation()
            } catch (error: any) {
                lastError = error

                // Check if this is a transient error that should be retried
                const isTransient =
                    error?.code === 'P2024' || // Prisma timeout
                    error?.message?.includes('Response from the Engine was empty') ||
                    error?.message?.includes('connection') ||
                    error?.message?.includes('timeout')

                // Don't retry on constraint violations or other non-transient errors
                if (!isTransient || attempt === maxRetries) {
                    throw error
                }

                // Exponential backoff: 100ms, 200ms, 400ms
                const backoffMs = 100 * Math.pow(2, attempt - 1)
                console.warn(`[EPSS] ${context} failed (attempt ${attempt}/${maxRetries}), retrying in ${backoffMs}ms...`)
                await new Promise(resolve => setTimeout(resolve, backoffMs))
            }
        }

        throw lastError
    }

    /**
     * Gets the current UTC date in YYYY-MM-DD format
     */
    private getCurrentDateString(): string {
        const now = new Date()
        const year = now.getUTCFullYear()
        const month = String(now.getUTCMonth() + 1).padStart(2, '0')
        const day = String(now.getUTCDate()).padStart(2, '0')
        return `${year}-${month}-${day}`
    }

    /**
     * Converts a Date object to YYYY-MM-DD format in UTC
     */
    private toDateString(date: Date): string {
        const year = date.getUTCFullYear()
        const month = String(date.getUTCMonth() + 1).padStart(2, '0')
        const day = String(date.getUTCDate()).padStart(2, '0')
        return `${year}-${month}-${day}`
    }

    async fetchJSON(url, body = null, method = 'POST') {
        try {
            if (method === 'POST' && typeof body !== "string") {
                body = JSON.stringify(body)
            }
            const response = await axios({
                url,
                method,
                headers: this.headers,
                data: body,
                validateStatus: () => true // Accept all status codes
            })
            const respText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
            const ok = response.status >= 200 && response.status < 300
            if (!ok) {
                console.error(`${method} ${url}`)
                console.error(`req headers=${JSON.stringify(this.headers, null, 2)}`)
                console.error(`resp headers=${JSON.stringify(response.headers, null, 2)}`)
                console.error(respText)
                console.error(`EPSS error! status: ${response.status} ${response.statusText}`)
            }
            if (!isJSON(respText)) {
                return { ok, status: response.status, statusText: response.statusText, error: { message: `Response not JSON format` }, content: respText, url } as FetchResponse
            }
            const content = JSON.parse(respText)
            return { ok, status: response.status, statusText: response.statusText, content, url } as FetchResponse
        } catch (e) {
            const match = e.stack?.match(/(\d+):(\d+)/)
            const lineno = match?.[1] || 'unknown'
            const colno = match?.[2] || 'unknown'
            console.error(`Network/API error: ${e.message}`)
            if (lineno !== 'unknown') {
                console.error(`line ${lineno}, col ${colno}`)
            }

            return { url, status: 500, ok: false, statusText: 'Network Error', error: { message: e.message, lineno, colno } } as FetchResponse
        }
    }

    /**
     * Check if EPSS score exists in database cache for today
     */
    async checkCache(prisma, cve: string): Promise<any | null> {
        const dateString = this.getCurrentDateString()

        try {
            const cached = await prisma.epssScore.findFirst({
                where: {
                    cve,
                    dateString
                }
            })

            if (cached) {
                return {
                    cve: cached.cve,
                    epss: cached.score.toString(),
                    percentile: cached.percentile.toString(),
                    date: cached.dateString,
                    model_version: cached.modelVersion
                }
            }

            return null
        } catch (error) {
            console.error(`[EPSS] Cache check failed for ${cve}:`, error)
            return null
        }
    }

    /**
     * Store EPSS score in database cache with retry logic
     */
    async storeInCache(prisma, cve: string, epssData: any): Promise<void> {
        const dateString = epssData.date || this.getCurrentDateString()
        const currentTime = Math.floor(Date.now() / 1000) // Unix timestamp in seconds

        try {
            await this.retryOnTransientError(
                async () => {
                    // Check if record exists for this CVE and date
                    // Using findFirst + conditional update/create instead of upsert
                    // This is more resilient with database constraints
                    const existing = await prisma.epssScore.findFirst({
                        where: {
                            cve,
                            dateString
                        }
                    })

                    if (existing) {
                        // Update existing record
                        await prisma.epssScore.update({
                            where: {
                                id: existing.id
                            },
                            data: {
                                score: parseFloat(epssData.epss),
                                percentile: parseFloat(epssData.percentile),
                                fetchedAt: currentTime,
                                modelVersion: epssData.model_version || null
                            }
                        })
                    } else {
                        // Create new record
                        await prisma.epssScore.create({
                            data: {
                                cve,
                                dateString,
                                score: parseFloat(epssData.epss),
                                percentile: parseFloat(epssData.percentile),
                                fetchedAt: currentTime,
                                modelVersion: epssData.model_version || null,
                                createdAt: currentTime
                            }
                        })
                    }
                },
                `Store cache for ${cve} on ${dateString}`
            )
        } catch (error: any) {
            // Enhanced error handling with specific Prisma error codes
            if (error?.code === 'P2002' || error?.message?.includes('UNIQUE constraint failed')) {
                // Race condition: another process inserted the record between our check and insert
                console.debug(`[EPSS] Record already exists for ${cve} on ${dateString}, skipping`)
            } else if (error?.code === 'P2024') {
                // Prisma timeout error
                console.error(`[EPSS] Database timeout for ${cve} on ${dateString}:`, error.message)
            } else if (error?.message?.includes('Response from the Engine was empty')) {
                // Connection pool exhaustion or Prisma engine error
                console.error(`[EPSS] Database connection error for ${cve} on ${dateString}:`, error.message)
            } else {
                // Other unexpected errors
                console.error(`[EPSS] Failed to cache score for ${cve} on ${dateString}:`, error)
            }
        }
    }

    /**
     * Fetch and store historical EPSS scores for the past 30 days using batch operations
     */
    async fetchTimeSeries(prisma, orgId: string, memberUuid: string, cve: string): Promise<void> {
        const url = `${this.baseUrl}/epss?cve=${cve}&scope=time-series`
        const startTime = Date.now()

        try {
            const resp = await this.fetchJSON(url, null, "GET") as FetchResponse

            if (!resp?.ok || !resp?.content?.data) {
                console.error(`[EPSS] Time series fetch failed for ${cve}`)
                return
            }

            // Process each historical data point
            const cveData = resp.content.data.find(d => d.cve === cve)

            if (!cveData) {
                console.error(`[EPSS] No data found for ${cve} in API response`)
                return
            }

            const currentTime = Math.floor(Date.now() / 1000)
            const timeSeries = cveData['time-series'] || []

            // Collect all data points (latest + time-series) for batch insert
            const allDataPoints = [
                {
                    cve,
                    dateString: cveData.date,
                    score: parseFloat(cveData.epss),
                    percentile: parseFloat(cveData.percentile),
                    fetchedAt: currentTime,
                    modelVersion: cveData.model_version || null,
                    createdAt: currentTime
                },
                ...timeSeries.map(dp => ({
                    cve,
                    dateString: dp.date,
                    score: parseFloat(dp.epss),
                    percentile: parseFloat(dp.percentile),
                    fetchedAt: currentTime,
                    modelVersion: dp.model_version || null,
                    createdAt: currentTime
                }))
            ]

            // Use retry wrapper for batch insert with skipDuplicates
            await this.retryOnTransientError(
                async () => {
                    await prisma.epssScore.createMany({
                        data: allDataPoints,
                        skipDuplicates: true
                    })
                },
                `Batch insert for ${cve}`
            )

            const duration = Date.now() - startTime
            console.log(
                `[EPSS] Stored ${allDataPoints.length} historical scores for ${cve} ` +
                `(1 latest + ${timeSeries.length} time-series) in ${duration}ms`
            )
        } catch (error: any) {
            // Enhanced error handling with specific error types
            if (error?.code === 'P2002') {
                console.debug(`[EPSS] Duplicate records skipped for ${cve}`)
            } else if (error?.code === 'P2024' || error?.message?.includes('Response from the Engine was empty')) {
                console.error(`[EPSS] Database connection error for ${cve}:`, error.message)
            } else {
                console.error(`[EPSS] Time series fetch failed for ${cve}:`, error)
            }
        }
    }

    async query(prisma, orgId, memberUuid, cve, r2cache = null) {
        // Check database cache first
        const cached = await this.checkCache(prisma, cve)
        if (cached) {
            console.log(`[EPSS] Cache hit for ${cve}`)
            return cached
        }

        console.log(`[EPSS] Cache miss for ${cve}, fetching from API`)

        // Check R2 cache if available
        if (r2cache) {
            const cache = new ApiCache({ r2bucket: r2cache });

            return await cache.withCache('epss', cve, async () => {
                return await this._performQuery(prisma, orgId, memberUuid, cve);
            });
        }

        // Fallback to direct query if no R2 cache
        return await this._performQuery(prisma, orgId, memberUuid, cve);
    }

    private async _performQuery(prisma, orgId, memberUuid, cve) {
        // Check if this is the first time fetching this CVE
        const existingScores = await prisma.epssScore.count({
            where: { cve }
        })

        const isFirstFetch = existingScores === 0

        if (isFirstFetch) {
            console.log(`[EPSS] First fetch for ${cve}, retrieving 30-day time series`)
            // Fetch historical data in the background (don't wait for it)
            this.fetchTimeSeries(prisma, orgId, memberUuid, cve).catch(err => {
                console.error(`[EPSS] Background time series fetch failed:`, err)
            })
        }

        // Fetch current day's score
        const url = `${this.baseUrl}/epss?cve=${cve}`
        const resp = await this.fetchJSON(url, null, "GET") as FetchResponse

        if (resp?.content) {
            const epssData = resp.content.data.filter(d => d.cve === cve).pop()

            if (epssData) {
                // Store in database cache
                await this.storeInCache(prisma, cve, epssData)
            }

            return epssData
        }
    }
}

export class MitreCVE {
    headers: { 'User-Agent': string }
    baseUrl: string
    apiUrl: string
    cveRegex: RegExp

    constructor(baseUrl?: string, apiUrl?: string) {
        this.headers = {
            'User-Agent': VULNETIX_USER_AGENT,
        }
        // Use provided baseUrl, or default to GitHub CVEProject raw files
        this.baseUrl = baseUrl || "https://github.com/CVEProject/cvelistV5/raw/refs/heads/main/cves/"
        // Use provided apiUrl, or default to MITRE CVE AWG API
        this.apiUrl = apiUrl || "https://cveawg.mitre.org/api/cve-id"
        this.cveRegex = new RegExp(`^CVE-\\d{4}-\\d{4,}$`)
    }

    async fetchJSON(url, body = null, method = 'GET') {
        try {
            if (method === 'POST' && typeof body !== "string") {
                body = JSON.stringify(body)
            }
            const response = await axios({
                url,
                method,
                headers: this.headers,
                data: body,
                validateStatus: () => true // Accept all status codes
            })
            const respText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
            const ok = response.status >= 200 && response.status < 300
            if (!ok) {
                console.error(`${method} ${url}`)
                console.error(`req headers=${JSON.stringify(this.headers, null, 2)}`)
                console.error(`resp headers=${JSON.stringify(response.headers, null, 2)}`)
                console.error(respText)
                console.error(`MitreCVE error! status: ${response.status} ${response.statusText}`)
            }
            if (!isJSON(respText)) {
                return { ok, status: response.status, statusText: response.statusText, error: { message: `Response not JSON format` }, content: respText, url } as FetchResponse
            }
            const content = JSON.parse(respText)
            return { ok, status: response.status, statusText: response.statusText, content, url } as FetchResponse
        } catch (e) {
            const match = e.stack?.match(/(\d+):(\d+)/)
            const lineno = match?.[1] || 'unknown'
            const colno = match?.[2] || 'unknown'
            console.error(`Network/API error: ${e.message}`)
            if (lineno !== 'unknown') {
                console.error(`line ${lineno}, col ${colno}`)
            }

            return { url, status: 500, ok: false, statusText: 'Network Error', error: { message: e.message, lineno, colno } } as FetchResponse
        }
    }

    constructURL(cveId) {
        if (!this.cveRegex.test(cveId)) {
            throw new Error("Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN....")
        }
        const [, year, number] = cveId.split('-')
        const subfolder = number.slice(0, -3) + "xxx"
        const path = `${year}/${subfolder}/${cveId}.json`
        return `${this.baseUrl}${path}`
    }

    async query(prisma, orgId, memberUuid, cveId, r2cache = null) {
        // Check R2 cache first if available
        if (r2cache) {
            const cache = new ApiCache({ r2bucket: r2cache });

            return await cache.withCache('mitre-cve', cveId, async () => {
                return await this._performQuery(prisma, orgId, memberUuid, cveId);
            });
        }

        // Fallback to direct query if no cache
        return await this._performQuery(prisma, orgId, memberUuid, cveId);
    }

    private async _performQuery(prisma, orgId, memberUuid, cveId) {
        let url = `${this.apiUrl}/${cveId}`
        const resp = await this.fetchJSON(url) as FetchResponse

        if (resp?.content) {
            return resp.content
        } else {
            url = this.constructURL(cveId)
            const response = await this.fetchJSON(url) as FetchResponse

            if (response?.content) {
                return response.content
            }
        }
    }
}

export class VulnCheck {
    headers: { 'Accept': string, 'Authorization': string, 'User-Agent': string }
    baseUrl: string

    constructor(BearerToken, baseUrl?: string) {
        this.headers = {
            'Accept': 'application/json',
            'Authorization': `Bearer ${BearerToken}`,
            'User-Agent': VULNETIX_USER_AGENT,
        }
        // Use provided baseUrl, or default to VulnCheck API v3
        this.baseUrl = baseUrl || "https://api.vulncheck.com/v3"
    }
    async fetchJSON(url) {
        try {
            const response = await axios.get(url, {
                headers: this.headers,
                validateStatus: () => true // Accept all status codes
            })
            const respText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
            const ok = response.status >= 200 && response.status < 300
            if (!ok) {
                console.error(`GET ${url}`)
                console.error(`req headers=${JSON.stringify(this.headers, null, 2)}`)
                console.error(`resp headers=${JSON.stringify(response.headers, null, 2)}`)
                console.error(respText)
                console.error(`VulnCheck error! status: ${response.status} ${response.statusText}`)
            }
            if (!isJSON(respText)) {
                return { ok, status: response.status, statusText: response.statusText, error: { message: `Response not JSON format` }, content: respText, url } as FetchResponse
            }
            const content = JSON.parse(respText)
            return { ok, status: response.status, statusText: response.statusText, content, url } as FetchResponse
        } catch (e) {
            const match = e.stack?.match(/(\d+):(\d+)/)
            const lineno = match?.[1] || 'unknown'
            const colno = match?.[2] || 'unknown'
            console.error(`Network/API error: ${e.message}`)
            if (lineno !== 'unknown') {
                console.error(`line ${lineno}, col ${colno}`)
            }

            return { url, status: 500, ok: false, statusText: 'Network Error', error: { message: e.message, lineno, colno } } as FetchResponse
        }
    }
    async getPurl(purl) {
        // https://docs.vulncheck.com/api/purl
        // const githubIntegration = await prisma.IntegrationConfig.findFirst({ where: { orgId, AND: { name: `vulncheck` } } })
        // if (!!githubIntegration?.suspend) {
        //     throw new Error('VulnCheck Integration is Disabled')
        // }
        // for (const vulnerability of vc.content?.data?.vulnerabilities) {
        //     fixedVersion: vulnerability?.fixed_version,
        //     maliciousSource: vulnerability?.research_attributes.malicious_source,
        //     abandoned: vulnerability?.research_attributes.abandoned,
        //     squattedPackage: vulnerability?.research_attributes.squatted_package,
        // }
        const url = `${this.baseUrl}/purl?purl=${purl}`
        // console.log(`VulnCheck.getPurl(${purl})`)
        return await this.fetchJSON(url) as FetchResponse
    }
    async getCPE(cpe) {
        // https://docs.vulncheck.com/api/cpe
        // const githubIntegration = await prisma.IntegrationConfig.findFirst({ where: { orgId, AND: { name: `vulncheck` } } })
        // if (!!githubIntegration?.suspend) {
        //     throw new Error('VulnCheck Integration is Disabled')
        // }
        const url = `${this.baseUrl}/cpe?cpe=${cpe}`
        // console.log(`VulnCheck.getCPE(${cpe})`)
        return await this.fetchJSON(url) as FetchResponse
    }
    async getCVE(cve_id) {
        // https://docs.vulncheck.com/community/nist-nvd/nvd-2
        // const githubIntegration = await prisma.IntegrationConfig.findFirst({ where: { orgId, AND: { name: `vulncheck` } } })
        // if (!!githubIntegration?.suspend) {
        //     throw new Error('VulnCheck Integration is Disabled')
        // }
        const url = `${this.baseUrl}/index/nist-nvd2?cve=${cve_id}`
        // console.log(`VulnCheck.getCVE(${cve_id})`)
        return await this.fetchJSON(url) as FetchResponse
    }
    async getNVD() {
        // https://docs.vulncheck.com/community/nist-nvd/nvd-2
        // const githubIntegration = await prisma.IntegrationConfig.findFirst({ where: { orgId, AND: { name: `vulncheck` } } })
        // if (!!githubIntegration?.suspend) {
        //     throw new Error('VulnCheck Integration is Disabled')
        // }
        const url = `${this.baseUrl}/index/nist-nvd2`
        // Check hash before downloading
        return await this.fetchJSON(url) as FetchResponse
    }
    async getKEV() {
        // https://docs.vulncheck.com/community/vulncheck-kev/schema
        // const githubIntegration = await prisma.IntegrationConfig.findFirst({ where: { orgId, AND: { name: `vulncheck` } } })
        // if (!!githubIntegration?.suspend) {
        //     throw new Error('VulnCheck Integration is Disabled')
        // }
        const url = `${this.baseUrl}/index/vulncheck-kev`
        // Check hash before downloading
        return await this.fetchJSON(url) as FetchResponse
    }
}

// Google OAuth utility functions
export const generateGoogleOAuthURL = (clientId: string, redirectUri: string, state?: string, env?: any): string => {
    const authUrl = env?.GOOGLE_OAUTH_AUTH_URL || 'https://accounts.google.com/o/oauth2/v2/auth'

    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        access_type: 'offline',
        prompt: 'consent'
    });

    if (state) {
        params.append('state', state);
    }

    return `${authUrl}?${params.toString()}`;
};

export const exchangeGoogleCodeForTokens = async (
    code: string,
    clientId: string,
    clientSecret: string,
    redirectUri: string,
    env?: any
): Promise<{
    access_token: string;
    id_token: string;
    refresh_token?: string;
}> => {
    const tokenEndpoint = env?.GOOGLE_OAUTH_TOKEN_URL || 'https://oauth2.googleapis.com/token';

    const body = new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
    });

    const response = await axios.post(tokenEndpoint, body.toString(), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
    });

    if (response.status < 200 || response.status >= 300) {
        throw new Error(`Google token exchange failed: ${response.statusText}`);
    }

    return response.data;
};

export const getGoogleUserInfo = async (accessToken: string, env?: any): Promise<{
    id: string;
    email: string;
    verified_email: boolean;
    name: string;
    given_name: string;
    family_name: string;
    avatarUrl: string;
}> => {
    const userInfoEndpoint = env?.GOOGLE_OAUTH_USERINFO_URL || 'https://www.googleapis.com/oauth2/v2/userinfo';

    const response = await axios.get(userInfoEndpoint, {
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    });

    if (response.status < 200 || response.status >= 300) {
        throw new Error(`Google user info request failed: ${response.statusText}`);
    }

    return response.data;
};

export const verifyGoogleIdToken = (idToken: string): {
    sub: string;
    email: string;
    email_verified: boolean;
    name: string;
    given_name: string;
    family_name: string;
    avatarUrl: string;
} => {
    // Simple JWT decode without verification for now
    // In production, you should verify the signature with Google's public keys
    const parts = idToken.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid ID token format');
    }
    
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    
    return {
        sub: payload.sub,
        email: payload.email,
        email_verified: payload.email_verified,
        name: payload.name,
        given_name: payload.given_name,
        family_name: payload.family_name,
        avatarUrl: payload.picture
    };
};
export const parseSearchQuery = query => {
    const inclusive = []  // for AND groups
    const exclude = []    // for NOT groups
    const exclusive = []  // all terms for OR groups
    const terms = []  // Any of these
    const decodedQuery = decodeURIComponent(query)

    // handle quoted terms
    function processQuotes(str) {
        const result = []
        let currentTerm = ''
        let inQuotes = false

        for (let i = 0; i < str.length; i++) {
            if (str[i] === '"') {
                inQuotes = !inQuotes
                if (!inQuotes && currentTerm) {
                    result.push(currentTerm)
                    currentTerm = ''
                }
            } else if (inQuotes) {
                currentTerm += str[i]
            } else if (str[i] !== ' ') {
                currentTerm += str[i]
            } else if (currentTerm) {
                result.push(currentTerm)
                currentTerm = ''
            }
        }

        if (currentTerm) {
            result.push(currentTerm)
        }

        return result
    }

    // Split by spaces while preserving quoted terms
    const tokens = processQuotes(decodedQuery)

    // Process tokens for OR and NOT groups
    for (let i = 0; i < tokens.length; i++) {
        if (tokens[i] === 'AND') {
            if (i > 0 && i < tokens.length - 1) {
                inclusive.push({
                    left: tokens[i - 1],
                    right: tokens[i + 1]
                })
                terms.push(tokens[i - 1])
                terms.push(tokens[i + 1])
                // Skip the next token as it's already processed
                i++
            }
        } else if (tokens[i] === 'NOT') {
            if (i > 0 && i < tokens.length - 1) {
                exclude.push(tokens[i + 1])
                // Skip the next token as it's already processed
                i++
            }
        } else {
            // Check if this term is not part of a previous OR/AND group
            const isPartOfGroup = (i > 0 && (tokens[i - 1] === 'AND' || tokens[i - 1] === 'NOT')) ||
                (i < tokens.length - 1 && (tokens[i + 1] === 'AND'))

            if (!isPartOfGroup) {
                exclusive.push(tokens[i])
                terms.push(tokens[i])
            }
        }
    }

    return { exclusive, inclusive, exclude, terms: terms.filter((value, index, array) => array.indexOf(value) === index) }
}

/**
 * isValidUuid checks if a given string is a valid UUID (version 4).
 * It uses a regular expression to validate the format of the UUID.
 * @param value - The string to validate as a UUID
 * @returns 
 */
export const isValidUuid = (value: string): boolean => {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
};

/**
 * Constructs a version range string from version objects following the CVE schema
 * @param {Array} versions - Array of version objects from CVE data
 * @returns {string|null} Formatted version range string or null if invalid
 */
export const constructVersionRangeString = versions => {
    if (!Array.isArray(versions) || versions.length === 0) {
        return null
    }

    const ranges = versions
        .map(v => {
            // Skip invalid entries
            if (!v?.version) return null

            // Case 1: Single version
            if (!v.lessThan && !v.lessThanOrEqual && !v.changes) {
                return `${v.version}`
            }

            // Case 2: Version range with less than
            if (v.lessThan) {
                return `>=${v.version} <${v.lessThan}`
            }

            // Case 3: Version range with less than or equal
            if (v.lessThanOrEqual) {
                return `>=${v.version} <=${v.lessThanOrEqual}`
            }

            // Case 4: Version range with changes
            if (v.changes) {
                // Note: This is a semver string comparison
                const sortedChanges = [...v.changes].sort((a, b) => {
                    // Split versions into components and pre-release tags
                    const [aBase, aPreRelease] = a.split('-')
                    const [bBase, bPreRelease] = b.split('-')

                    // Split version numbers
                    const [aMajor, aMinor, aPatch] = aBase.split('.').map(Number)
                    const [bMajor, bMinor, bPatch] = bBase.split('.').map(Number)

                    // Compare major versions
                    if (aMajor !== bMajor) return aMajor - bMajor

                    // Compare minor versions
                    if (aMinor !== bMinor) return aMinor - bMinor

                    // Compare patch versions
                    if (aPatch !== bPatch) return aPatch - bPatch

                    // If one has a pre-release tag and the other doesn't,
                    // the one without comes first
                    if (aPreRelease && !bPreRelease) return 1
                    if (!aPreRelease && bPreRelease) return -1

                    // If both have pre-release tags, compare them
                    if (aPreRelease && bPreRelease) {
                        return aPreRelease.localeCompare(bPreRelease)
                    }

                    return 0
                })

                const changePoints = sortedChanges
                    .map(change => `${change.at}(${change.status})`)
                    .join(', ')

                return `${v.version} with changes at ${changePoints}`
            }

            return `${v.version}`
        })
        .filter(Boolean)

    if (ranges.length === 0) {
        return null
    }

    // Combine ranges with ' || ' to indicate multiple ranges
    return ranges.join(' || ')
}

/**
 * ensureStrReqBody reads in the incoming request body
 * Use await ensureStrReqBody(..) in an async function to get the string
 * @param {Request} request the incoming request to read from
 */
export const ensureStrReqBody = async (c: any): Promise<string> => {
    const contentType = c.req.header("content-type") || ''
    
    if (contentType.includes("application/json")) {
        try {
            const jsonData = await c.req.json()
            return JSON.stringify(jsonData)
        } catch (e) {
            // Fallback to text if JSON parsing fails
            const jsonText = await c.req.text()
            return decodeURIComponent(jsonText)
        }
    } else if (contentType.includes("application/text")) {
        return await c.req.text()
    } else if (contentType.includes("text/html")) {
        return await c.req.text()
    } else if (contentType.includes("form")) {
        const formData = await c.req.formData()
        const body: Record<string, any> = {}
        for (const entry of formData.entries()) {
            body[entry[0]] = entry[1]
        }
        return JSON.stringify(body)
    } else {
        // Default to text for unknown content types
        try {
            return await c.req.text()
        } catch (e) {
            throw new Error(`Unhandled content type: ${contentType}`)
        }
    }
}

/**
 * Converts a Buffer or ArrayBuffer to a hexadecimal string.
 *
 * If `Buffer` is not defined (e.g., in a browser environment), it will attempt to convert the input using
 * `ArrayBuffer` and `Uint8Array`.
 *
 * @param {Buffer|ArrayBuffer} input - The input data to convert.
 * @returns {string} The hexadecimal string representation of the input data.
 */
export const bufferToHex = input => {
    if (typeof Buffer !== 'undefined') {
        // Node.js environment or using a Buffer polyfill
        return Buffer.from(input).toString('hex')
    } else {
        // Browser environment without Buffer support
        const arrayBuffer = input instanceof ArrayBuffer ? input : new ArrayBuffer(input.byteLength)
        const view = new Uint8Array(arrayBuffer)
        const hexArray = Array.from(view).map(byte => byte.toString(16).padStart(2, '0'))
        return hexArray.join('')
    }
}

/**
 * Encodes a given string to Base64.
 *
 * This function is designed to be compatible with both Node.js and browsers.
 *
 * @param {string} body - The string to be encoded.
 * @returns {string} The Base64-encoded string.
 */
/**
 * Decodes a Base64-encoded string into its original string.
 *
 * This function is designed to be compatible with both Node.js and browsers.
 *
 * @param {string} base64String - The Base64-encoded string.
 * @returns {string} The decoded original string.
 */
export const decodeFromBase64 = base64String => {
    if (typeof Buffer !== 'undefined') {
        // Node.js environment - decode to binary string (latin1)
        return Buffer.from(base64String, 'base64').toString('binary')
    } else {
        // Browser environment
        return atob(base64String)
    }
}

/**
 * Converts ISO 8601 formatted date strings within an object or array to Unix timestamps (milliseconds since epoch).
 *
 * This function recursively traverses the provided object or array, converting any encountered ISO 8601 date strings
 * to their corresponding Unix timestamps. Other data types (e.g., numbers, strings) are left unchanged.
 *
 * @param {object|array} obj - The object or array to be processed.
 * @returns {object|array} A new object or array with ISO 8601 dates converted to timestamps.
 */
export const convertIsoDatesToTimestamps = (obj: any) => {
    if (Array.isArray(obj)) {
        return obj.map(item => convertIsoDatesToTimestamps(item))
    } else if (typeof obj === 'object' && obj !== null) {
        return Object.fromEntries(
            Object.entries(obj).map(([key, value]) => {
                if (typeof value === 'string' && /(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))/.test(value)) {
                    value = new Date(value).getTime()
                } else if (!!value && typeof value === 'object') {
                    value = convertIsoDatesToTimestamps(value)
                }
                return [key, value]
            })
        )
    } else {
        return obj // Handle other data types (e.g., numbers, strings)
    }
}
/**
 * Parses a SemVer string into its components
 * @param {string} versionString - The version string to parse
 * @returns {Object} Object containing version components and constraints
 */
export function parseSemVer(versionString) {
    // Regular expressions for different parts
    const operatorRegex = /^([<>]=?|={1,2}|\*|~|\^)|^.*(\.x|\.\*)/;
    const versionRegex = /^v?(\d+|[x*])(?:\.(\d+|[x*]))?(?:\.(\d+|[x*]))?(?:-?([0-9A-Za-z-.]+))?(?:\+([0-9A-Za-z-.]+))?$/;

    let operator = '';
    let version = versionString;

    // Extract operator if present
    const operatorMatch = versionString.match(operatorRegex);
    if (operatorMatch && operatorMatch[0]) {
        operator = operatorMatch[1];
        version = versionString.slice(operator.length).trim();
    } else if (operatorMatch && operatorMatch[2]) {
        operator = operatorMatch[2];
        version = versionString.replace(operator, '.0').trim();
    }

    // Handle "*" and "x" as a special case
    if (['*', 'x'].includes(version)) {
        return {
            operator,
            major: '*',
            minor: '*',
            patch: '*',
            prerelease: null,
            buildMetadata: null,
            original: versionString
        };
    }

    // Parse version parts
    const match = version.match(versionRegex);
    if (!match) {
        return {
            operator,
            major: '',
            minor: '',
            patch: '',
            prerelease: null,
            buildMetadata: null,
            original: versionString
        };
    }

    const [, major, minor, patch, prerelease, buildMetadata] = match;

    // Convert version parts to numbers or keep as special characters
    const processVersionPart = (part) => {
        if (!part) return '0';
        if (['*', 'x'].includes(part)) return '*';
        return part;
    };

    return {
        operator,
        major: processVersionPart(major),
        minor: processVersionPart(minor),
        patch: processVersionPart(patch),
        prerelease: prerelease || null,
        buildMetadata: buildMetadata || null,
        original: versionString
    };
}
export function getSemVerWithoutOperator(versionString) {
    if (!versionString) {
        return ''
    }
    // Regular expressions for different parts
    const operatorRegex = /^([<>]=?|={1,2}|\*|~|\^)|^.*(\.x|\.\*)/;
    let operator = '';
    let version = versionString;
    // Extract operator if present
    const operatorMatch = versionString.match(operatorRegex);
    if (operatorMatch && operatorMatch[1]) {
        operator = operatorMatch[1] || '';
        version = versionString.slice(operator.length).trim();
    } else if (operatorMatch && operatorMatch[2]) {
        operator = operatorMatch[2] || '';
        // Replace wildcard suffix (.x or .*) with .0 for comparisons
        version = versionString.replace(/(\.x|\.\*)$/, '.0').trim();
    }

    // If still contains wildcard segments, normalize each to 0
    if (/\.(x|\*)/.test(version)) {
        version = version.split('.').map(p => (p === 'x' || p === '*') ? '0' : p).join('.')
    }

    return version
}
/**
 * Splits a version string into comparison operator and version number
 * @param {string} versionString - The version string to split
 * @returns {[string, string]} Array containing [comparison, version]
 */
export function splitVersionComparison(versionString) {
    const parsed = parseSemVer(versionString)
    if (!parsed) return ['=', versionString]
    const { operator, major, minor, patch } = parsed
    const version = `${major}.${minor}.${patch}`
    return [operator || '=', version]
}

/**
 * Analyzes a response string to determine if it is a JSON string or a simple string.
 * @param input - The input string to analyze, which is expected to be a JSON string or a simple string.
 * @returns {string} - Returns the parsed JSON string if the input is valid JSON, otherwise returns the original input string.
 */
export const analysisResponseJson = (input: string): string => {
    if (isJSON(input)) {
        const respArr = JSON.parse(input)
        return Array.isArray(respArr) ? respArr.join(', ') : respArr;
    }
    return input;
}

/**
 * Validates if a given version string is a valid semantic version (SemVer).
 * @param version - The version string to validate (e.g., "1.0.0", "v2.3.4", "x.y.z")
 * @returns {boolean} True if the version is valid, false otherwise.
 */
export const isValidSemver = version => {
    if (!version) return false;
    // Disallow double dots and ensure proper part content
    if (/\.\./.test(version)) return false;
    const semverRegex = /^v?(\d+|[x*])(?:\.(\d+|[x*]))?(?:\.(\d+|[x*]))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
    return semverRegex.test(version);
}

export function getVersionString(versionString, majorDefault = "0", minorDefault = "0", patchDefault = "0") {
    // Get clean version number for each part
    const cleanVersions = versionString.split('||').map(v => v.trim()).filter(v => !!v).map(v => {
        const [, version = ''] = splitVersionComparison(v)
        return version.trim()
    }).filter(i => !!i)
    if (!cleanVersions.length) return `${majorDefault}.${minorDefault}.${patchDefault}`
    const comp = (v1, v2) => {
        // Use same compare as isVersionVulnerable for consistency
        const cmp = ((a,b)=>{
            // local simple comparator: major/minor/patch numeric, prerelease
            const pa = parseSemVer(a); const pb = parseSemVer(b)
            const toNum = (v:any)=>({
                major: parseInt(String(v.major||'0'),10)||0,
                minor: parseInt(String(v.minor||'0'),10)||0,
                patch: parseInt(String(v.patch||'0'),10)||0,
                prerelease: v.prerelease,
            })
            const A=toNum(pa), B=toNum(pb)
            if (A.major!==B.major) return A.major-B.major
            if (A.minor!==B.minor) return A.minor-B.minor
            if (A.patch!==B.patch) return A.patch-B.patch
            if (A.prerelease===B.prerelease) return 0
            if (!A.prerelease && B.prerelease) return 1
            if (A.prerelease && !B.prerelease) return -1
            const aIds=String(A.prerelease).split('.'); const bIds=String(B.prerelease).split('.')
            const len=Math.max(aIds.length,bIds.length)
            for (let i=0;i<len;i++){
                const ai=aIds[i], bi=bIds[i]
                if (ai===undefined) return -1
                if (bi===undefined) return 1
                const an=/^\d+$/.test(ai)?parseInt(ai,10):NaN
                const bn=/^\d+$/.test(bi)?parseInt(bi,10):NaN
                if (!Number.isNaN(an) && !Number.isNaN(bn)) { if (an!==bn) return an-bn }
                else if (!Number.isNaN(an)) return -1
                else if (!Number.isNaN(bn)) return 1
                else if (ai!==bi) return ai<bi?-1:1
            }
            return 0
        })(v1,v2)
        return cmp >= 0 ? v1 : v2
    }
    const semVer = cleanVersions.reduce((highest, current) => {
        return comp(highest, current)
    })
    if (!semVer) return `${majorDefault}.${minorDefault}.${patchDefault}`
    const { major = majorDefault, minor = minorDefault, patch = patchDefault } = parseSemVer(semVer)
    return `${major}.${minor}.${patch}`
}

export const versionSorter = (v1, v2) => {
    if (!v1 || !v2) return 0
    const pa = parseSemVer(v1); const pb = parseSemVer(v2)
    const toNum = (v:any)=>({
        major: parseInt(String(v.major||'0'),10)||0,
        minor: parseInt(String(v.minor||'0'),10)||0,
        patch: parseInt(String(v.patch||'0'),10)||0,
        prerelease: v.prerelease,
    })
    const A=toNum(pa), B=toNum(pb)
    if (A.major!==B.major) return A.major-B.major
    if (A.minor!==B.minor) return A.minor-B.minor
    if (A.patch!==B.patch) return A.patch-B.patch
    if (A.prerelease===B.prerelease) return 0
    if (!A.prerelease && B.prerelease) return 1
    if (A.prerelease && !B.prerelease) return -1
    const aIds=String(A.prerelease).split('.'); const bIds=String(B.prerelease).split('.')
    const len=Math.max(aIds.length,bIds.length)
    for (let i=0;i<len;i++){
        const ai=aIds[i], bi=bIds[i]
        if (ai===undefined) return -1
        if (bi===undefined) return 1
        const an=/^\d+$/.test(ai)?parseInt(ai,10):NaN
        const bn=/^\d+$/.test(bi)?parseInt(bi,10):NaN
        if (!Number.isNaN(an) && !Number.isNaN(bn)) { if (an!==bn) return an-bn }
        else if (!Number.isNaN(an)) return -1
        else if (!Number.isNaN(bn)) return 1
        else if (ai!==bi) return ai<bi?-1:1
    }
    return 0
}

export function chunkArray(array, chunkSize = 1000) {
    return Array.from(
        { length: Math.ceil(array.length / chunkSize) },
        (_, index) => array.slice(index * chunkSize, (index + 1) * chunkSize)
    )
}
/**
 * Determines if a version is vulnerable based on a set of version ranges
 *
 * @param {string} version - The version to check (e.g., "2.10.6")
 * @param {string} vulnerableRanges - String containing version ranges (e.g., "< 2.11.2 >= 0")
 *                                   Multiple ranges can be separated by "||"
 *                                   Space-separated comparisons within a range are treated as AND conditions
 *                                   "||" separated ranges are treated as OR conditions
 *
 * Examples:
 * "< 2.11.2 >= 0" - Version must be less than 2.11.2 AND greater than or equal to 0
 * "< 2.11.2 || >= 0 < 2.8.7" - Version must either be less than 2.11.2 OR (greater than or equal to 0 AND less than 2.8.7)
 *
 * @returns {boolean} True if the version is vulnerable according to any of the ranges
 */
export const isVersionVulnerable = (version, vulnerableRanges) => {
    // First normalize the version by removing any operators
    const normalizedVersion = getSemVerWithoutOperator(version)

    // CalVer detection (supports multiple shapes):
    // - YYYY.MM.DD (e.g., 2024.09.01)
    // - YYYY.MM (e.g., 2024.09)
    // - YYYYMMDD (e.g., 20240901)
    // - YY.MM.DD (e.g., 24.09.01)
    // - YY.MM (e.g., 24.09)
    // - YYYY.MINOR.PATCH (numeric 3-part, treated as numeric calver-like)
    const calverShapes = [
        { name: 'YYYY.MM.DD', re: /^\d{4}\.\d{1,2}\.\d{1,2}$/ },
        { name: 'YYYY.MM',    re: /^\d{4}\.\d{1,2}$/ },
        { name: 'YYYYMMDD',   re: /^\d{8}$/ },
        { name: 'YY.MM.DD',   re: /^\d{2}\.\d{1,2}\.\d{1,2}$/ },
        { name: 'YY.MM',      re: /^\d{2}\.\d{1,2}$/ },
        { name: 'NUM.NUM.NUM',re: /^\d+\.\d+\.\d+$/ },
    ]

    const detectCalVerShape = (v) => calverShapes.find(s => s.re.test(v))?.name || null

    const toCalTuple = (v, shape) => {
        if (shape === 'YYYYMMDD') {
            const y = parseInt(v.slice(0,4), 10)
            const m = parseInt(v.slice(4,6), 10)
            const d = parseInt(v.slice(6,8), 10)
            return [y, m, d]
        }
        const parts = v.split('.').map(n => parseInt(n, 10))
        if (shape === 'YYYY.MM') return [parts[0], parts[1], 0]
        if (shape === 'YY.MM') return [parts[0], parts[1], 0]
        // For 3-part shapes (YYYY.MM.DD, YY.MM.DD, NUM.NUM.NUM) return as-is
        return [parts[0] || 0, parts[1] || 0, parts[2] || 0]
    }

    const compareCalVer = (v1, v2) => {
        const s1 = detectCalVerShape(v1)
        const s2 = detectCalVerShape(v2)
        if (!s1 || !s2 || s1 !== s2) return NaN
        const p1 = toCalTuple(v1, s1)
        const p2 = toCalTuple(v2, s2)
        const len = Math.max(p1.length, p2.length)
        for (let i = 0; i < len; i++) {
            const a = p1[i] ?? 0
            const b = p2[i] ?? 0
            if (a !== b) return a - b
        }
        return 0
    }

    // Helper: robust comparison with SemVer first, CalVer fallback
    const compareVersions = (version1, version2) => {
        const v1 = getSemVerWithoutOperator(version1)
        const v2 = getSemVerWithoutOperator(version2)
        // If both look like the same CalVer shape, use CalVer compare
        const calCmp = compareCalVer(v1, v2)
        if (!Number.isNaN(calCmp)) return calCmp
        const a = parseSemVer(getSemVerWithoutOperator(version1))
        const b = parseSemVer(getSemVerWithoutOperator(version2))

        const toNum = (v) => ({
            major: parseInt(String(v.major || '0'), 10) || 0,
            minor: parseInt(String(v.minor || '0'), 10) || 0,
            patch: parseInt(String(v.patch || '0'), 10) || 0,
            prerelease: v.prerelease,
        })

        const va = toNum(a)
        const vb = toNum(b)

        if (va.major !== vb.major) return va.major - vb.major
        if (va.minor !== vb.minor) return va.minor - vb.minor
        if (va.patch !== vb.patch) return va.patch - vb.patch

        // Handle prerelease precedence: 1.0.0-alpha < 1.0.0
        if (va.prerelease === vb.prerelease) return 0
        if (!va.prerelease && vb.prerelease) return 1
        if (va.prerelease && !vb.prerelease) return -1

        // Both have prerelease: compare identifiers
        const aIds = String(va.prerelease).split('.')
        const bIds = String(vb.prerelease).split('.')
        const len = Math.max(aIds.length, bIds.length)
        for (let i = 0; i < len; i++) {
            const ai = aIds[i]
            const bi = bIds[i]
            if (ai === undefined) return -1
            if (bi === undefined) return 1
            const an = ai.match(/^\d+$/) ? parseInt(ai, 10) : NaN
            const bn = bi.match(/^\d+$/) ? parseInt(bi, 10) : NaN
            if (!Number.isNaN(an) && !Number.isNaN(bn)) {
                if (an !== bn) return an - bn
            } else if (!Number.isNaN(an)) {
                return -1 // Numeric identifiers have lower precedence
            } else if (!Number.isNaN(bn)) {
                return 1
            } else if (ai !== bi) {
                return ai < bi ? -1 : 1
            }
        }
        return 0
    };

    // Helper function to evaluate a single comparison
    const evaluateComparison = (comparison, targetVersion) => {
        // Split into operator and version
        const [operator, compareVersion] = splitVersionComparison(comparison)

        // First-class CalVer: if both are CalVer and same shape, compare via CalVer immediately
        const s1 = detectCalVerShape(targetVersion)
        const s2 = detectCalVerShape(compareVersion)
        if (s1 && s2) {
            if (s1 !== s2) return false
            const calCmp2 = compareCalVer(targetVersion, compareVersion)
            switch (operator) {
                case '<': return calCmp2 < 0
                case '<=': return calCmp2 <= 0
                case '>': return calCmp2 > 0
                case '>=': return calCmp2 >= 0
                case '=':
                case '==': return calCmp2 === 0
                default: return false
            }
        }

        // Otherwise require valid SemVer to proceed
        const semverOK = isValidSemver(targetVersion) && isValidSemver(compareVersion)
        if (!semverOK) {
            return false
        }

        // Prefer CalVer compare if applicable
        const calCmp = compareCalVer(targetVersion, compareVersion)
        if (!Number.isNaN(calCmp)) {
            switch (operator) {
                case '<': return calCmp < 0
                case '<=': return calCmp <= 0
                case '>': return calCmp > 0
                case '>=': return calCmp >= 0
                case '=':
                case '==': return calCmp === 0
                default: return false
            }
        }

        // Get the difference between versions (SemVer-aware)
        const versionDifference = compareVersions(targetVersion, compareVersion)

        // Evaluate based on operator
        switch (operator) {
            case '<':
                return versionDifference < 0
            case '<=':
                return versionDifference <= 0
            case '>':
                return versionDifference > 0
            case '>=':
                return versionDifference >= 0
            case '=':
            case '==':
                return versionDifference === 0
            default:
                return false
        }
    };

    // Normalize the ranges string:
    // 1. Trim whitespace
    // 2. Replace multiple spaces with single space
    // 3. Remove spaces around comparison operators
    const normalizedRanges = vulnerableRanges
        .trim()
        .replace(/\s+/g, ' ')
        .replace(/\s*(>=|>|<=|<)\s*/g, ' $1')

    // Split into individual range sets (separated by ||)
    const rangeSets = normalizedRanges.split('||').map(range => range.trim())

    // Check each range set (these are OR conditions)
    for (const rangeSet of rangeSets) {
        // Get all comparisons in this range set (these are AND conditions)
        const comparisons = rangeSet.split(' ').filter(i => !!i.trim())

        // Track if all comparisons in this range set are true, meaning the version is within range if all are true
        const rangeResults = []

        // Check each comparison in the current range set
        for (const comparison of comparisons) {
            rangeResults.push(evaluateComparison(comparison, normalizedVersion))
        }

        // If all comparisons in this range set matched, we can return true immediately
        // (because range sets are OR conditions)
        if (rangeResults.every(r => r === true)) {
            return true
        }
    }

    // If we get here, no range set was satisfied
    return false
}

/**
 * Flattens a nested object into a single-level object, optionally converting ISO 8601 date strings to Unix timestamps.
 *
 * This function recursively traverses the object, flattening nested objects and arrays. If a `convertDates` option is provided,
 * it will convert any ISO 8601 date strings encountered to their corresponding Unix timestamps.
 *
 * @param {object} obj - The object to be flattened.
 * @param {string} [prefix=''] - An optional prefix to prepend to the keys of the flattened object.
 * @param {boolean} [convertDates=false] - An optional flag indicating whether to convert ISO 8601 dates to timestamps.
 * @returns {object} A flattened object with all nested properties merged into a single level.
 */
export const flatten = (obj, prefix = '', convertDates = false) =>
    Object.entries(obj).reduce((acc, [key, value]) => {
        const newKey = prefix ? `${prefix}_${key}` : key
        return Array.isArray(value)
            ? { ...acc, [newKey]: value } // Flatten array directly
            : value && typeof value === 'object'
                ? { ...acc, ...flatten(value, newKey, convertDates) } // Handle nested objects
                : convertDates && typeof value === 'string' && /(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))/.test(value)
                    ? { ...acc, [newKey]: new Date(value).getTime() } // Convert date to timestamp
                    : { ...acc, [newKey]: value } // Handle primitives
    }, {})

/**
 * Converts a text string to a hexadecimal hash using the specified hashing algorithm.
 *
 * This function uses the Web Crypto API to perform the hashing operation.
 *
 * @param {string} text - The text string to be hashed.
 * @param {string} [name="SHA-1"] - The name of the hashing algorithm to use (e.g., "SHA-1", "SHA-256", "SHA-384", "SHA-512").
 * @returns {Promise<string>} A promise that resolves to the hexadecimal representation of the hash.
 */
export async function hex(text, name = "SHA-1") {
    return [...new Uint8Array(await crypto.subtle.digest({ name }, new TextEncoder().encode(text)))].map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Rounds a number to a specified number of decimal places.
 *
 * @param {number} n - The number to round.
 * @param {number} [p=10] - The precision factor. Defaults to 10.
 *   - p = 10 results in 1 decimal place
 *   - p = 100 results in 2 decimal places
 *   - p = 1000 results in 3 decimal places, and so on
 *
 * @returns {number} The rounded number.
 *
 * @example
 * round(3.14159, 10)  // Returns 3.1
 * round(3.14159, 100) // Returns 3.14
 * round(3.14159)      // Returns 3.1 (uses default precision)
 */export const round = (n, p = 10) => Math.round((n + Number.EPSILON) * p) / p

export const isJSON = str => {
    if (!str || typeof str !== 'string') {
        return false
    }
    try {
        JSON.parse(str)
        return true
    } catch (e) {
        return false
    }
}

/**
 * Safely gets parsed JSON from Hono context with proper validation and fallback handling
 * @param c - Hono context
 * @param logger - Logger instance for debugging
 * @returns Parsed JSON object or null if not available/invalid
 */
export const getRequestJson = (c: any, logger?: any) => {
    // First try to get the pre-parsed JSON from middleware
    const json = c.get('json')
    if (json && typeof json === 'object') {
        return json
    }
    
    // Fallback to parsing bodyText if json is not available
    const bodyText = c.get('bodyText')
    if (bodyText && isJSON(bodyText)) {
        try {
            const parsed = JSON.parse(bodyText)
            if (logger) {
                logger.debug('Fallback JSON parsing successful', {
                    bodyTextLength: bodyText.length,
                    parsedKeys: Object.keys(parsed)
                })
            }
            return parsed
        } catch (e) {
            if (logger) {
                logger.warn('Fallback JSON parsing failed', {
                    error: e.message,
                    bodyTextLength: bodyText?.length || 0
                })
            }
        }
    }
    
    // Final fallback to raw body text
    const rawBodyText = c.get('rawBodyText')
    if (rawBodyText && isJSON(rawBodyText)) {
        try {
            const parsed = JSON.parse(rawBodyText)
            if (logger) {
                logger.debug('Raw body JSON parsing successful', {
                    rawBodyLength: rawBodyText.length,
                    parsedKeys: Object.keys(parsed)
                })
            }
            return parsed
        } catch (e) {
            if (logger) {
                logger.warn('Raw body JSON parsing failed', {
                    error: e.message,
                    rawBodyLength: rawBodyText?.length || 0
                })
            }
        }
    }
    
    if (logger) {
        logger.warn('No valid JSON found in request', {
            hasJson: !!json,
            hasBodyText: !!bodyText,
            hasRawBodyText: !!rawBodyText,
            contentType: c.req.header('content-type')
        })
    }
    
    return null
}

/**
 * Calculates a human-readable time difference between the current time and a given date.
 *
 * This function returns a string indicating how long ago the date was, such as "2 years ago", "1 month ago", or "just now".
 *
 * @param {Date | string | number} date - The date to calculate the time difference from. Can be a Date object, timestamp number, or ISO string.
 * @returns {string} A human-readable time difference string.
 */
export const timeAgo = (date: Date | string | number) => momentTimeAgo(date)

/**
 * Helper function to convert hex string to Uint8Array
 * @return {Uint8Array<Object>}
 */
export const hexStringToUint8Array = (hexString: string) => {
    const length = hexString.length / 2
    const array = new Uint8Array(length)
    for (let i = 0; i < length; i++) {
        array[i] = parseInt(hexString.substr(i * 2, 2), 16)
    }
    return array
}

export const getPastelColor = () => {
    const red = Math.floor(Math.random() * 75 + 180)
    const green = Math.floor(Math.random() * 75 + 180)
    const blue = Math.floor(Math.random() * 75 + 180)
    return '#' +
        red.toString(16).padStart(2, '0') +
        green.toString(16).padStart(2, '0') +
        blue.toString(16).padStart(2, '0')
}

/**
 * Parsed CVSS vector metrics
 */
export interface CvssVectorMetrics {
    attackVector: 'N' | 'A' | 'L' | 'P' | null // Network, Adjacent, Local, Physical
    attackComplexity: 'L' | 'H' | null // Low, High
    privilegesRequired: 'N' | 'L' | 'H' | null // None, Low, High
    userInteraction: 'N' | 'R' | null // None, Required
    scope: 'U' | 'C' | null // Unchanged, Changed
    confidentiality: 'N' | 'L' | 'H' | null // None, Low, High
    integrity: 'N' | 'L' | 'H' | null // None, Low, High
    availability: 'N' | 'L' | 'H' | null // None, Low, High
    version: string | null // CVSS version (e.g., "3.1", "3.0", "2.0", "4.0")
}

/**
 * Parses a CVSS vector string and extracts key metrics
 * Supports CVSS v2.0, v3.0, v3.1, and v4.0
 *
 * @param vectorString - CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
 * @returns Parsed CVSS metrics object
 *
 * @example
 * const metrics = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
 * console.log(metrics.attackVector) // "N"
 * console.log(metrics.privilegesRequired) // "N"
 */
export const parseCvssVector = (vectorString: string | null): CvssVectorMetrics => {
    const defaultMetrics: CvssVectorMetrics = {
        attackVector: null,
        attackComplexity: null,
        privilegesRequired: null,
        userInteraction: null,
        scope: null,
        confidentiality: null,
        integrity: null,
        availability: null,
        version: null
    }

    if (!vectorString) {
        return defaultMetrics
    }

    // Extract version from vector string
    const versionMatch = vectorString.match(/CVSS:(\d+\.\d+)/)
    const version = versionMatch ? versionMatch[1] : null

    // Split by "/" and extract metrics
    const parts = vectorString.split('/')
    const metrics = { ...defaultMetrics, version }

    for (const part of parts) {
        const [key, value] = part.split(':')
        if (!key || !value) continue

        switch (key) {
            case 'AV':
                metrics.attackVector = value as 'N' | 'A' | 'L' | 'P'
                break
            case 'AC':
                metrics.attackComplexity = value as 'L' | 'H'
                break
            case 'PR':
                metrics.privilegesRequired = value as 'N' | 'L' | 'H'
                break
            case 'UI':
                metrics.userInteraction = value as 'N' | 'R'
                break
            case 'S':
                metrics.scope = value as 'U' | 'C'
                break
            case 'C':
                metrics.confidentiality = value as 'N' | 'L' | 'H'
                break
            case 'I':
                metrics.integrity = value as 'N' | 'L' | 'H'
                break
            case 'A':
                metrics.availability = value as 'N' | 'L' | 'H'
                break
        }
    }

    return metrics
}

/**
 * Checks if a CVSS vector indicates network reachability (Attack Vector: Network)
 * @param vectorString - CVSS vector string
 * @returns true if AV:N (Network)
 */
export const isNetworkReachable = (vectorString: string | null): boolean => {
    const metrics = parseCvssVector(vectorString)
    return metrics.attackVector === 'N'
}

/**
 * Checks if a CVSS vector requires no privileges (Privileges Required: None)
 * @param vectorString - CVSS vector string
 * @returns true if PR:N (None)
 */
export const requiresNoPrivileges = (vectorString: string | null): boolean => {
    const metrics = parseCvssVector(vectorString)
    return metrics.privilegesRequired === 'N'
}
