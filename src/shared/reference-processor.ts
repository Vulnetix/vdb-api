import type { GitHubCommitEnrichment, GitHubPREnrichment, GitHubGistEnrichment, ExploitDBEnrichment, VulnerabilityLabEnrichment } from '@/shared/interfaces'
import { Octokit } from '@octokit/rest'
import type { PrismaClient } from '@prisma/client'
import { VULNETIX_USER_AGENT } from '@shared/utils'
import { default as axios } from 'axios'
import { categorizeURL } from '@/services/utilities/url-categorizer'
import { getExploitDBRawPath, getMetasploitModulePath, retrieveExternalFileFromR2, storeExternalFileToR2 } from '@shared/vdb-identifier'

export interface ReferenceData {
    url: string
    type?: string
    title?: string
}

export interface ProcessedReference {
    url: string
    type: string
    title: string | null
    httpStatus: number | null
    deadLink: number
    prEnrichment?: GitHubPREnrichment
    commitEnrichment?: GitHubCommitEnrichment
    gistEnrichment?: GitHubGistEnrichment
    exploitDbEnrichment?: ExploitDBEnrichment
    vlEnrichment?: VulnerabilityLabEnrichment
    blobCreatedAt?: number | null // GitHub blob file creation timestamp
}

interface Logger {
    warn: (message: string, data?: any) => void
    debug: (message: string, data?: any) => void
    error: (message: string, data?: any) => void
    info: (message: string, data?: any) => void
}

/**
 * Create Octokit client for public GitHub API access
 * Uses unauthenticated access for public repositories
 */
const createOctokitClient = (): Octokit => {
    return new Octokit({
        userAgent: VULNETIX_USER_AGENT
    })
}

/**
 * Fetch GitHub Pull Request data using Octokit
 */
const fetchGitHubPRData = async (
    octokit: Octokit,
    owner: string,
    repo: string,
    prNumber: number
): Promise<GitHubPREnrichment | null> => {
    try {
        const { data: pr } = await octokit.pulls.get({
            owner,
            repo,
            pull_number: prNumber
        })

        return {
            title: pr.title,
            diff_url: pr.diff_url,
            state: pr.state,
            author: pr.user?.login || null,
            labels: pr.labels?.map((label: any) => label.name) || [],
            merged_at: pr.merged_at ? Math.floor(new Date(pr.merged_at).getTime() / 1000) : null,
            merge_commit_sha: pr.merge_commit_sha || null,
            health: {
                additions: pr.additions || 0,
                deletions: pr.deletions || 0,
                changed_files: pr.changed_files || 0,
                comments: pr.comments || 0,
                review_comments: pr.review_comments || 0,
                commits: pr.commits || 0
            }
        }
    } catch (error: any) {
        if (error.status === 404) {
            return null // PR not found
        }
        throw error
    }
}

/**
 * Fetch GitHub Commit data using Octokit
 */
const fetchGitHubCommitData = async (
    octokit: Octokit,
    owner: string,
    repo: string,
    sha: string
): Promise<GitHubCommitEnrichment | null> => {
    try {
        const { data: commit } = await octokit.repos.getCommit({
            owner,
            repo,
            ref: sha
        })

        return {
            author_email: commit.commit.author?.email || null,
            author_login: commit.author?.login || null,
            verified: commit.commit.verification?.verified || false,
            createdAt: commit.commit.author?.date ? Math.floor(new Date(commit.commit.author.date).getTime() / 1000) : null,
            message: commit.commit.message || null,
            commit_health: {
                additions: commit.stats.additions || 0,
                deletions: commit.stats.deletions || 0,
                total: commit.stats.total || 0,
                comment_count: commit.commit.comment_count || 0,
                files_changed: commit.files.length || 0
            }
        }
    } catch (error: any) {
        if (error.status === 404) {
            return null // Commit not found
        }
        throw error
    }
}

/**
 * Fetch GitHub blob (file) creation date by finding the first commit that introduced the file
 * API Documentation: https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28#list-commits
 */
const fetchGitHubBlobCreationDate = async (
    octokit: Octokit,
    owner: string,
    repo: string,
    path: string,
    ref?: string
): Promise<number | null> => {
    try {
        // Get commits for this file path, oldest first
        const { data: commits } = await octokit.repos.listCommits({
            owner,
            repo,
            path,
            sha: ref, // Optional branch/ref
            per_page: 1, // We only need the oldest commit
            page: 1
        })

        if (commits.length > 0) {
            // The first commit in the response when sorted by oldest is the creation commit
            // However, the API returns newest first by default, so we need to get the last page
            // For now, we'll use a simpler approach: get all commits and take the oldest
            const { data: allCommits } = await octokit.repos.listCommits({
                owner,
                repo,
                path,
                sha: ref,
                per_page: 100 // Limit to prevent excessive API calls
            })

            if (allCommits.length > 0) {
                // Take the oldest commit (last in the array)
                const oldestCommit = allCommits[allCommits.length - 1]
                const createdDate = oldestCommit.commit.author?.date
                return createdDate ? Math.floor(new Date(createdDate).getTime() / 1000) : null
            }
        }

        return null
    } catch (error: any) {
        if (error.status === 404) {
            return null // File or repo not found
        }
        throw error
    }
}

/**
 * Fetch GitHub Gist data using Octokit
 * API Documentation: https://docs.github.com/en/rest/gists/gists?apiVersion=2022-11-28#get-a-gist
 */
export const fetchGitHubGistData = async (
    octokit: Octokit,
    gistId: string
): Promise<GitHubGistEnrichment | null> => {
    try {
        const { data: gist } = await octokit.gists.get({
            gist_id: gistId
        })

        // Extract file names from the files object
        const fileNames = gist.files ? Object.keys(gist.files) : []

        return {
            gist_id: gist.id,
            title: gist.description || null,
            owner_login: gist.owner?.login || null,
            createdAt: gist.created_at ? Math.floor(new Date(gist.created_at).getTime() / 1000) : null,
            updatedAt: gist.updated_at ? Math.floor(new Date(gist.updated_at).getTime() / 1000) : null,
            public: gist.public || false,
            files_count: fileNames.length,
            files: fileNames,
            comments_count: gist.comments || 0
        }
    } catch (error: any) {
        if (error.status === 404) {
            return null // Gist not found
        }
        throw error
    }
}

/**
 * Fetch ExploitDB exploit data from raw endpoint
 * Checks R2 cache first, then fetches from exploit-db.com/raw/{id} and caches the result
 * Parses metadata from the exploit file header
 * @param exploitId - ExploitDB exploit ID
 * @param logger - Optional logger
 * @param r2adapter - Optional R2 adapter for caching external files
 */
export async function fetchExploitDBData(exploitId: string, logger?: Logger, r2adapter?: any): Promise<ExploitDBEnrichment | null> {
    try {
        let rawContent: string | null = null

        // Step 1: Check R2 cache first (no TTL - permanent cache)
        if (r2adapter) {
            const r2Path = getExploitDBRawPath(exploitId)
            rawContent = await retrieveExternalFileFromR2(r2adapter, r2Path, logger)

            if (rawContent) {
                if (logger) {
                    logger.info(`[ExploitDB] ✅ Using cached raw data for ${exploitId} from R2`)
                }
            }
        }

        // Step 2: Fetch from remote if not in cache
        if (!rawContent) {
            const rawUrl = `https://www.exploit-db.com/raw/${exploitId}`
            if (logger) {
                logger.debug(`[ExploitDB] 🔄 Fetching ${rawUrl}...`)
            }

            const response = await axios.get(rawUrl, {
                timeout: 10000,
                headers: {
                    'User-Agent': VULNETIX_USER_AGENT
                },
                validateStatus: () => true
            })

            if (response.status !== 200) {
                if (logger) {
                    logger.debug(`[ExploitDB] HTTP ${response.status}`)
                }
                return null
            }

            rawContent = response.data as string
            if (!rawContent || typeof rawContent !== 'string') {
                if (logger) {
                    logger.debug(`[ExploitDB] Invalid response`)
                }
                return null
            }

            // Step 3: Store to R2 cache (no expiry)
            if (r2adapter && rawContent) {
                try {
                    const r2Path = getExploitDBRawPath(exploitId)
                    await storeExternalFileToR2(r2adapter, r2Path, rawContent, 'text/plain', logger)
                    if (logger) {
                        logger.info(`[ExploitDB] 💾 Stored raw data for ${exploitId} to R2`)
                    }
                } catch (r2Error: any) {
                    if (logger) {
                        logger.warn(`[ExploitDB] Failed to cache raw data to R2: ${r2Error.message}`)
                    }
                }
            }
        }

        // Parse metadata from header
        const lines = rawContent.split('\n')
        let title: string | null = null
        let author: string | null = null
        let date: number | null = null
        let platform: string | null = null
        let type: string | null = null
        let port: number | null = null
        let verified = false

        for (let i = 0; i < Math.min(lines.length, 30); i++) {
            const line = lines[i].trim()

            // Title: can be in multiple formats
            if (!title && (line.match(/^#?\s*Exploit Title\s*[:=]\s*(.+)/i) ||
                          line.match(/^#?\s*Title\s*[:=]\s*(.+)/i))) {
                const match = line.match(/^#?\s*(?:Exploit )?Title\s*[:=]\s*(.+)/i)
                title = match?.[1]?.trim() || null
            }

            // Author
            if (!author && line.match(/^#?\s*Author\s*[:=]\s*(.+)/i)) {
                const match = line.match(/^#?\s*Author\s*[:=]\s*(.+)/i)
                author = match?.[1]?.trim() || null
            }

            // Date - various formats: YYYY-MM-DD, MM/DD/YYYY, etc.
            if (!date && line.match(/^#?\s*(?:Date|Published)\s*[:=]\s*(.+)/i)) {
                const match = line.match(/^#?\s*(?:Date|Published)\s*[:=]\s*(.+)/i)
                const dateStr = match?.[1]?.trim()
                if (dateStr) {
                    const parsedDate = new Date(dateStr)
                    if (!isNaN(parsedDate.getTime())) {
                        date = Math.floor(parsedDate.getTime() / 1000)
                    }
                }
            }

            // Platform
            if (!platform && line.match(/^#?\s*Platform\s*[:=]\s*(.+)/i)) {
                const match = line.match(/^#?\s*Platform\s*[:=]\s*(.+)/i)
                platform = match?.[1]?.trim() || null
            }

            // Type (e.g., remote, local, webapps, dos)
            if (!type && line.match(/^#?\s*Type\s*[:=]\s*(.+)/i)) {
                const match = line.match(/^#?\s*Type\s*[:=]\s*(.+)/i)
                type = match?.[1]?.trim() || null
            }

            // Port
            if (port === null && line.match(/^#?\s*Port\s*[:=]\s*(\d+)/i)) {
                const match = line.match(/^#?\s*Port\s*[:=]\s*(\d+)/i)
                const portNum = match?.[1] ? parseInt(match[1], 10) : null
                if (portNum !== null && !isNaN(portNum)) {
                    port = portNum
                }
            }

            // Verified tag
            if (!verified && line.match(/^#?\s*Verified\s*[:=]?\s*(true|yes|1)/i)) {
                verified = true
            }
        }

        if (logger) {
            logger.debug(`[ExploitDB] Parsed metadata - Title: ${title || 'N/A'}, Author: ${author || 'N/A'}, Date: ${date ? new Date(date * 1000).toISOString() : 'N/A'}, Platform: ${platform || 'N/A'}, Type: ${type || 'N/A'}, Port: ${port !== null ? port : 'N/A'}, Verified: ${verified ? 'Yes' : 'No'}`)
        }

        return {
            exploitId,
            title,
            author,
            date,
            platform,
            type,
            port,
            verified
        }
    } catch (error: any) {
        if (logger) {
            logger.debug(`[ExploitDB] Error: ${error.message}`)
        }
        return null
    }
}

/**
 * Fetch Metasploit module data from GitHub
 * Checks R2 cache first, then fetches from raw.githubusercontent.com and caches the result
 * @param modulePath - Module path (e.g., "/modules/exploits/windows/browser/ie_execcommand_uaf.rb")
 * @param logger - Optional logger
 * @param r2adapter - Optional R2 adapter for caching external files
 */
export async function fetchMetasploitData(modulePath: string, logger?: Logger, r2adapter?: any): Promise<{ content: string; path: string } | null> {
    try {
        let rawContent: string | null = null

        // Step 1: Check R2 cache first (no TTL - permanent cache)
        if (r2adapter) {
            const r2Path = getMetasploitModulePath(modulePath)
            rawContent = await retrieveExternalFileFromR2(r2adapter, r2Path, logger)

            if (rawContent) {
                if (logger) {
                    logger.info(`[Metasploit] ✅ Using cached module for ${modulePath} from R2`)
                }
                return { content: rawContent, path: modulePath }
            }
        }

        // Step 2: Fetch from GitHub if not in cache
        const rawUrl = `https://raw.githubusercontent.com/rapid7/metasploit-framework/master${modulePath}`
        if (logger) {
            logger.debug(`[Metasploit] 🔄 Fetching ${rawUrl}...`)
        }

        const response = await axios.get(rawUrl, {
            timeout: 10000,
            headers: {
                'User-Agent': VULNETIX_USER_AGENT
            },
            validateStatus: () => true
        })

        if (response.status !== 200) {
            if (logger) {
                logger.debug(`[Metasploit] HTTP ${response.status}`)
            }
            return null
        }

        rawContent = response.data as string
        if (!rawContent || typeof rawContent !== 'string') {
            if (logger) {
                logger.debug(`[Metasploit] Invalid response`)
            }
            return null
        }

        // Step 3: Store to R2 cache (no expiry)
        if (r2adapter && rawContent) {
            try {
                const r2Path = getMetasploitModulePath(modulePath)
                const contentType = modulePath.endsWith('.rb') ? 'text/x-ruby' : 'text/plain'
                await storeExternalFileToR2(r2adapter, r2Path, rawContent, contentType, logger)
                if (logger) {
                    logger.info(`[Metasploit] 💾 Stored module for ${modulePath} to R2`)
                }
            } catch (r2Error: any) {
                if (logger) {
                    logger.warn(`[Metasploit] Failed to cache module to R2: ${r2Error.message}`)
                }
            }
        }

        return { content: rawContent, path: modulePath }
    } catch (error: any) {
        if (logger) {
            logger.debug(`[Metasploit] Error: ${error.message}`)
        }
        return null
    }
}

/**
 * Fetch VulnerabilityLab exploit data from plaintext page
 * Parses metadata from the structured text format
 */
export const fetchVulnerabilityLabData = async (
    vlId: string
): Promise<VulnerabilityLabEnrichment | null> => {
    try {
        const vlUrl = `https://www.vulnerability-lab.com/get_content.php?id=${vlId}`
        const response = await axios.get(vlUrl, {
            timeout: 15000,
            headers: {
                'User-Agent': VULNETIX_USER_AGENT
            },
            validateStatus: () => true
        })

        if (response.status !== 200) {
            return null
        }

        const content = response.data as string
        if (!content || typeof content !== 'string') {
            return null
        }

        let title: string | null = null
        let createdAt: number | null = null
        let updatedAt: number | null = null
        let exploitationTechnique: string | null = null
        let authenticationType: string | null = null
        let userInteraction: string | null = null
        let author: string | null = null

        // Parse Release Date
        const releaseDateMatch = content.match(/Release Date:\s*=+\s*(\d{4}-\d{2}-\d{2})/i)
        if (releaseDateMatch) {
            const parsedDate = new Date(releaseDateMatch[1])
            if (!isNaN(parsedDate.getTime())) {
                createdAt = parsedDate.getTime()
            }
        }

        // Parse Document Title
        const titleMatch = content.match(/Document Title:\s*=+\s*(.+?)(?:\n|$)/i)
        if (titleMatch) {
            title = titleMatch[1].trim()
        }

        // Parse Vulnerability Disclosure Timeline for dates
        const timelineMatch = content.match(/Vulnerability Disclosure Timeline:\s*=+\s*([\s\S]*?)(?:\n\n|$)/i)
        if (timelineMatch) {
            const timelineContent = timelineMatch[1]
            const datePattern = /(\d{4}-\d{2}-\d{2})/g
            const dates: number[] = []
            let match: RegExpExecArray | null

            while ((match = datePattern.exec(timelineContent)) !== null) {
                const parsedDate = new Date(match[1])
                if (!isNaN(parsedDate.getTime())) {
                    dates.push(Math.floor(parsedDate.getTime() / 1000))
                }
            }

            if (dates.length > 0) {
                // Use earliest date as createdAt if not already set or if earlier
                const earliestDate = Math.min(...dates)
                if (!createdAt || earliestDate < createdAt) {
                    createdAt = earliestDate
                }
                // Use latest date as updatedAt
                updatedAt = Math.max(...dates)
            }
        }

        // Parse Exploitation Technique
        const exploitationTechniqueMatch = content.match(/Exploitation Technique:\s*=+\s*(.+?)(?:\n|$)/i)
        if (exploitationTechniqueMatch) {
            exploitationTechnique = exploitationTechniqueMatch[1].trim()
        }

        // Parse Authentication Type
        const authenticationTypeMatch = content.match(/Authentication Type:\s*=+\s*(.+?)(?:\n|$)/i)
        if (authenticationTypeMatch) {
            authenticationType = authenticationTypeMatch[1].trim()
        }

        // Parse User Interaction
        const userInteractionMatch = content.match(/User Interaction:\s*=+\s*(.+?)(?:\n|$)/i)
        if (userInteractionMatch) {
            userInteraction = userInteractionMatch[1].trim()
        }

        // Parse Credits & Authors
        const authorMatch = content.match(/Credits & Authors:\s*=+\s*(.+?)(?:\n\n|$)/i)
        if (authorMatch) {
            author = authorMatch[1].trim()
        }

        return {
            vlId,
            title,
            createdAt,
            updatedAt,
            exploitationTechnique,
            authenticationType,
            userInteraction,
            author
        }
    } catch (error: any) {
        // Silently fail - enrichment is optional
        return null
    }
}

/**
 * Fetch README.md content from a GitHub repository using raw URL
 * Pattern: https://raw.githubusercontent.com/:orgName/:repoName/refs/heads/main/README.md
 */
const fetchGitHubReadme = async (
    owner: string,
    repo: string,
    logger: Logger
): Promise<string | null> => {
    try {
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/refs/heads/main/README.md`
        logger.debug(`[GitHub README] Fetching README from ${rawUrl}`)

        const response = await fetch(rawUrl, {
            headers: {
                'User-Agent': 'Vulnetix/1.0'
            }
        })

        if (response.status === 404) {
            logger.debug(`[GitHub README] No README found for ${owner}/${repo}`)
            return null
        }

        if (!response.ok) {
            logger.warn(`[GitHub README] Failed to fetch README for ${owner}/${repo}: HTTP ${response.status}`)
            return null
        }

        const content = await response.text()
        logger.info(`[GitHub README] Successfully fetched README for ${owner}/${repo} (${content.length} chars)`)
        return content
    } catch (error: any) {
        logger.warn(`[GitHub README] Failed to fetch README for ${owner}/${repo}:`, error.message)
        return null
    }
}

/**
 * Enrich RESERVED CVE description with GitHub repository README
 * Creates a new CVEMetadata record with source='github' containing enriched data
 */
export const enrichReservedCVEWithReadme = async (
    prisma: PrismaClient,
    cveId: string,
    source: string,
    githubUrl: string,
    processed: ProcessedReference,
    logger: Logger
): Promise<void> => {
    try {
        // Check if CVE is RESERVED (from cve.org source)
        const cveRecord = await prisma.cVEMetadata.findUnique({
            where: {
                cveId_source: {
                    cveId,
                    source
                }
            },
            select: {
                state: true,
                datePublished: true,
                dateReserved: true
            }
        })

        if (!cveRecord) {
            logger.debug(`[README Enrichment] CVE ${cveId} from ${source} not found, skipping enrichment`)
            return
        }

        // Check if CVE is RESERVED
        if (cveRecord.state !== 'RESERVED') {
            logger.debug(`[README Enrichment] CVE ${cveId} state=${cveRecord.state}, not RESERVED, skipping enrichment`)
            return
        }

        logger.info(`[README Enrichment] Processing RESERVED CVE ${cveId} from ${source}`)

        // Only enrich from cve.org source to avoid duplicate enrichment
        if (source !== 'cve.org') {
            logger.debug(`[README Enrichment] Skipping enrichment for ${cveId} source=${source} (only enriches from cve.org)`)
            return
        }

        // Parse GitHub URL to extract owner/repo
        const githubMatch = githubUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/)
        if (!githubMatch) {
            logger.debug(`[README Enrichment] Could not parse GitHub URL: ${githubUrl}`)
            return
        }

        const owner = githubMatch[1]
        const repo = githubMatch[2].replace(/\.git$/, '') // Remove .git suffix

        // Fetch README using raw URL
        logger.info(`[README Enrichment] Fetching README for ${owner}/${repo}`)
        const readme = await fetchGitHubReadme(owner, repo, logger)

        if (!readme) {
            logger.info(`[README Enrichment] No README found for ${cveId} from ${githubUrl}`)
            return
        }

        // Remove only the first header line, keep rest as markdown
        const cleanContent = readme.replace(/^#+\s+.+$/m, '').trim()

        if (!cleanContent || cleanContent.length < 10) {
            logger.info(`[README Enrichment] README content too short for ${cveId}`)
            return
        }

        // Check if this is an Active exploit (verified/weaponized)
        const isActive = isActiveExploit(githubUrl, processed)

        // Active exploit: E:A (Active) - verified ExploitDB, Metasploit, Nuclei
        // PoC exploit: E:P (Proof of Concept) - DEFAULT for all other exploits
        const vectorString = isActive
            ? 'CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A'
            : 'CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P'

        // Create/update CVEMetadata with source='github' containing enriched data
        await prisma.cVEMetadata.upsert({
            where: {
                cveId_source: {
                    cveId,
                    source: 'github'
                }
            },
            create: {
                cveId,
                source: 'github',
                dataVersion: 'github-enriched',
                state: 'RESERVED',
                datePublished: cveRecord.datePublished,
                dateReserved: cveRecord.dateReserved,
                title: cleanContent,
                vectorString,
                lastFetchedAt: Math.floor(Date.now() / 1000),
                fetchCount: 1
            },
            update: {
                title: cleanContent,
                vectorString,
                lastFetchedAt: Math.floor(Date.now() / 1000),
                fetchCount: {
                    increment: 1
                }
            }
        })

        logger.info(`[GitHub Enrichment] Created/updated CVEMetadata with source='github' for ${cveId}`)
        logger.info(`[README Enrichment] Added description from ${owner}/${repo} README (${cleanContent.length} chars, markdown preserved)`)
        logger.info(`[CVSS Enrichment] Added CVSS 4.0 vector (${isActive ? 'Active' : 'PoC'} exploit detected)`)
    } catch (error) {
        logger.error(`[README Enrichment] Failed to enrich ${cveId}:`, error)
        // Don't throw - enrichment failure shouldn't block reference storage
    }
}

/**
 * Detect if an exploit is Active/Weaponized (vs PoC)
 * Active exploits include: verified ExploitDB, Metasploit modules, Nuclei templates
 * DEFAULT: All exploits are considered PoC unless verified/weaponized
 */
const isActiveExploit = (url: string, processed: ProcessedReference): boolean => {
    const urlLower = url.toLowerCase()

    // 1. Check if ExploitDB verified exploit
    if (processed.exploitDbEnrichment?.verified) {
        return true
    }

    // 2. Check if Metasploit module
    if (urlLower.includes('metasploit.com') ||
        urlLower.includes('github.com/rapid7/metasploit') ||
        urlLower.includes('github.com/rapid7/metasploit-framework')) {
        return true
    }

    // 3. Check if Nuclei template
    if (urlLower.includes('nuclei-templates') ||
        urlLower.includes('projectdiscovery.io') ||
        urlLower.includes('github.com/projectdiscovery/nuclei-templates')) {
        return true
    }

    // Default: treat as PoC
    return false
}

/**
 * Check HTTP status of a URL
 * Returns status code or null if failed
 */
export const checkHttpStatus = async (url: string): Promise<number | null> => {
    try {
        const response = await axios.head(url, {
            timeout: 5000,
            maxRedirects: 5,
            validateStatus: () => true // Accept any status code
        })
        return response.status
    } catch (error) {
        // Try GET if HEAD fails
        try {
            const response = await axios.get(url, {
                timeout: 5000,
                maxRedirects: 5,
                validateStatus: () => true // Accept any status code
            })
            return response.status
        } catch {
            return null
        }
    }
}

/**
 * Process a reference URL to extract type and check status
 * Optionally enriches GitHub PR and commit references with additional metadata
 * @param r2adapter - Optional R2 adapter for caching external reference files
 */
export const processReference = async (
    url: string,
    referenceType?: string,
    checkHttp: boolean = false,
    logger?: Logger,
    r2adapter?: any
): Promise<ProcessedReference> => {
    const categorized = categorizeURL(url)

    let httpStatus: number | null = null
    let deadLink = 0 // 0 = not checked, 1 = dead, 2 = alive
    let prEnrichment: GitHubPREnrichment | undefined = undefined
    let commitEnrichment: GitHubCommitEnrichment | undefined = undefined
    let gistEnrichment: GitHubGistEnrichment | undefined = undefined
    let exploitDbEnrichment: ExploitDBEnrichment | undefined = undefined
    let vlEnrichment: VulnerabilityLabEnrichment | undefined = undefined
    let blobCreatedAt: number | null = null

    if (checkHttp) {
        httpStatus = await checkHttpStatus(url)
        if (httpStatus === null) {
            deadLink = 1 // Dead link
        } else if (httpStatus >= 200 && httpStatus < 400) {
            deadLink = 2 // Alive
        } else if (httpStatus >= 400) {
            deadLink = 1 // Dead link (4xx or 5xx)
        }
    }

    // Enrich GitHub references using Octokit
    if (categorized.category.subcategory === 'github') {
        const { repoOwner, repoName, prNumber, commitHash, gistId, filePath, blobRef } = categorized.category.extractedData || {}

        // Enrich Gist references
        if (gistId) {
            const octokit = createOctokitClient()
            try {
                const enrichment = await fetchGitHubGistData(octokit, gistId)
                if (enrichment) {
                    gistEnrichment = enrichment
                }
            } catch (error) {
                // Silently fail Gist enrichment - it's optional metadata
            }
        }

        if (repoOwner && repoName) {
            const octokit = createOctokitClient()

            // Enrich PR references
            if (prNumber) {
                try {
                    const enrichment = await fetchGitHubPRData(octokit, repoOwner, repoName, parseInt(prNumber, 10))
                    if (enrichment) {
                        prEnrichment = enrichment
                    }
                } catch (error) {
                    // Silently fail PR enrichment - it's optional metadata
                }
            }

            // Enrich commit references
            if (commitHash) {
                try {
                    const enrichment = await fetchGitHubCommitData(octokit, repoOwner, repoName, commitHash)
                    if (enrichment) {
                        commitEnrichment = enrichment
                    }
                } catch (error) {
                    // Silently fail commit enrichment - it's optional metadata
                }
            }

            // Enrich blob (file) references with creation date
            if (filePath && !prNumber && !commitHash) {
                // Only enrich blob URLs that aren't already PR or commit URLs
                try {
                    const creationDate = await fetchGitHubBlobCreationDate(octokit, repoOwner, repoName, filePath, blobRef)
                    if (creationDate) {
                        blobCreatedAt = creationDate
                    }
                } catch (error) {
                    // Silently fail blob enrichment - it's optional metadata
                }
            }
        }
    }

    // Enrich ExploitDB references (with R2 caching)
    if (categorized.category.subcategory === 'exploit-db') {
        const { exploitId } = categorized.category.extractedData || {}

        if (exploitId) {
            try {
                const enrichment = await fetchExploitDBData(exploitId, logger, r2adapter)
                if (enrichment) {
                    exploitDbEnrichment = enrichment
                }
            } catch (error) {
                // Silently fail ExploitDB enrichment - it's optional metadata
            }
        }
    }

    // Enrich VulnerabilityLab references
    if (categorized.category.subcategory === 'vulnerability-lab') {
        const { vlId } = categorized.category.extractedData || {}

        if (vlId) {
            try {
                const enrichment = await fetchVulnerabilityLabData(vlId)
                if (enrichment) {
                    vlEnrichment = enrichment
                }
            } catch (error) {
                // Silently fail VulnerabilityLab enrichment - it's optional metadata
            }
        }
    }

    // Enrich Metasploit framework references (with R2 caching)
    // Detect URLs like: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/...
    if (categorized.category.subcategory === 'github' && url.includes('rapid7/metasploit-framework')) {
        // Extract module path from GitHub URL
        const metasploitMatch = url.match(/rapid7\/metasploit-framework\/blob\/[^\/]+(\/.+)/i)
        if (metasploitMatch && metasploitMatch[1]) {
            const modulePath = metasploitMatch[1]
            try {
                await fetchMetasploitData(modulePath, logger, r2adapter)
                // We don't need to store enrichment data for now, just cache the file
                if (logger) {
                    logger.debug(`[Metasploit] Cached module file for ${modulePath}`)
                }
            } catch (error) {
                // Silently fail Metasploit enrichment - it's optional caching
            }
        }
    }

    return {
        url: url.trim(),
        type: referenceType || categorized.category.subcategory || categorized.category.type,
        title: vlEnrichment?.title || exploitDbEnrichment?.title || prEnrichment?.title || gistEnrichment?.title || null,
        httpStatus,
        deadLink,
        prEnrichment,
        commitEnrichment,
        gistEnrichment,
        exploitDbEnrichment,
        vlEnrichment,
        blobCreatedAt
    }
}

/**
 * Store a reference for a Finding
 */
export const storeFindingReference = async (
    prisma: PrismaClient,
    findingUuid: string,
    reference: ReferenceData,
    source: string,
    logger: Logger,
    checkHttp: boolean = true
): Promise<void> => {
    try {
        const checkExists = await prisma.findingReferences.findFirst({
            where: {
                findingUuid,
                url: reference.url.trim()
            }
        })

        if (checkExists) {
            logger.debug(`Reference already exists for finding ${findingUuid}: ${reference.url}`)
            return
        }

        const processed = await processReference(reference.url, reference.type, checkHttp, logger)

        await prisma.findingReferences.create({
            data: {
                findingUuid,
                url: processed.url,
                source,
                type: processed.type,
                title: reference.title || processed.title,
                createdAt: processed?.blobCreatedAt || processed?.vlEnrichment?.createdAt || processed?.gistEnrichment?.createdAt || processed?.exploitDbEnrichment?.date || processed?.commitEnrichment?.createdAt || processed?.prEnrichment?.merged_at || Math.floor(Date.now() / 1000),
                httpStatus: processed.httpStatus,
                deadLinkCheckedAt: checkHttp ? Math.floor(Date.now() / 1000) : null,
                deadLink: processed.deadLink,
                // ExploitDB enrichment fields
                exploitDbId: processed.exploitDbEnrichment?.exploitId || null,
                exploitDbAuthor: processed.exploitDbEnrichment?.author || null,
                exploitDbDate: processed.exploitDbEnrichment?.date || null,
                exploitDbPlatform: processed.exploitDbEnrichment?.platform || null,
                exploitDbType: processed.exploitDbEnrichment?.type || null,
                exploitDbPort: processed.exploitDbEnrichment?.port || null,
                exploitDbVerified: processed.exploitDbEnrichment?.verified ? 1 : (processed.exploitDbEnrichment ? 0 : null)
            }
        })

        logger.debug(`Stored reference for finding ${findingUuid}: ${processed.url} (type: ${processed.type})`)
    } catch (error) {
        logger.error(`Failed to store finding reference: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
}

/**
 * Store a reference for a CVEMetadata record
 */
export const storeCVEMetadataReference = async (
    prisma: PrismaClient,
    cveId: string,
    source: string,
    reference: ReferenceData,
    referenceSource: string,
    logger: Logger,
    checkHttp: boolean = false,
    forceRefresh: boolean = false
): Promise<void> => {
    try {
        logger.info(`[storeCVEMetadataReference] CALLED for CVE ${cveId}, URL: ${reference.url}, forceRefresh: ${forceRefresh}`)

        // Only check for duplicates if not force refreshing
        if (!forceRefresh) {
            const checkExists = await prisma.cVEMetadataReferences.findFirst({
                where: {
                    cveId,
                    source,
                    url: reference.url.trim()
                }
            })

            if (checkExists) {
                logger.debug(`[storeCVEMetadataReference] Reference already exists for CVE ${cveId}: ${reference.url}`)
                return
            }
        }

        logger.info(`[storeCVEMetadataReference] Processing reference URL: ${reference.url}`)
        const processed = await processReference(reference.url, reference.type, checkHttp, logger)
        logger.info(`[storeCVEMetadataReference] Processed reference - type: ${processed.type}, title: ${processed.title}, hasPREnrichment: ${!!processed.prEnrichment}, hasCommitEnrichment: ${!!processed.commitEnrichment}`)

        // Use upsert when force refreshing to update existing references
        if (forceRefresh) {
            logger.info(`[storeCVEMetadataReference] Force refresh enabled - checking for existing reference`)
            // Find existing reference to get UUID for upsert
            const existing = await prisma.cVEMetadataReferences.findFirst({
                where: {
                    cveId,
                    source,
                    url: processed.url
                }
            })

            if (existing) {
                logger.info(`[storeCVEMetadataReference] Updating existing reference UUID: ${existing.uuid}`)
                // Update existing reference
                await prisma.cVEMetadataReferences.update({
                    where: { uuid: existing.uuid },
                    data: {
                        referenceSource,
                        type: processed.type,
                        title: reference.title || processed.title,
                        createdAt: processed?.blobCreatedAt || processed?.vlEnrichment?.createdAt || processed?.gistEnrichment?.createdAt || processed?.exploitDbEnrichment?.date || processed?.commitEnrichment?.createdAt || processed?.prEnrichment?.merged_at || existing.createdAt,
                        httpStatus: processed.httpStatus,
                        deadLinkCheckedAt: checkHttp ? Math.floor(Date.now() / 1000) : null,
                        deadLink: processed.deadLink,
                        // GitHub PR enrichment fields
                        prDiffUrl: processed.prEnrichment?.diff_url || null,
                        prState: processed.prEnrichment?.state || null,
                        prAuthor: processed.prEnrichment?.author || null,
                        prLabels: processed.prEnrichment?.labels ? JSON.stringify(processed.prEnrichment.labels) : null,
                        prMergedAt: processed.prEnrichment?.merged_at || null,
                        prMergeCommitSha: processed.prEnrichment?.merge_commit_sha || null,
                        prRepoHealth: processed.prEnrichment?.health ? JSON.stringify(processed.prEnrichment.health) : null,
                        // GitHub Commit enrichment fields
                        commitAuthorEmail: processed.commitEnrichment?.author_email || null,
                        commitAuthorLogin: processed.commitEnrichment?.author_login || processed.gistEnrichment?.owner_login || null,
                        commitVerified: processed.commitEnrichment?.verified ? 1 : (processed.commitEnrichment ? 0 : null),
                        commitHealth: processed.commitEnrichment?.commit_health ? JSON.stringify(processed.commitEnrichment.commit_health) : null,
                        // GitHub Gist enrichment fields
                        gistId: processed.gistEnrichment?.gist_id || null,
                        gistPublic: processed.gistEnrichment?.public ? 1 : (processed.gistEnrichment ? 0 : null),
                        gistFilesCount: processed.gistEnrichment?.files_count || null,
                        gistFiles: processed.gistEnrichment?.files ? JSON.stringify(processed.gistEnrichment.files) : null,
                        gistComments: processed.gistEnrichment?.comments_count || null,
                        gistUpdatedAt: processed.gistEnrichment?.updatedAt || null,
                        // ExploitDB enrichment fields
                        exploitDbId: processed.exploitDbEnrichment?.exploitId || null,
                        exploitDbAuthor: processed.exploitDbEnrichment?.author || null,
                        exploitDbDate: processed.exploitDbEnrichment?.date || null,
                        exploitDbPlatform: processed.exploitDbEnrichment?.platform || null,
                        exploitDbType: processed.exploitDbEnrichment?.type || null,
                        exploitDbPort: processed.exploitDbEnrichment?.port || null,
                        exploitDbVerified: processed.exploitDbEnrichment?.verified ? 1 : (processed.exploitDbEnrichment ? 0 : null),
                        // VulnerabilityLab enrichment fields
                        vlId: processed.vlEnrichment?.vlId || null,
                        vlTitle: processed.vlEnrichment?.title || null,
                        vlCreatedAt: processed.vlEnrichment?.createdAt || null,
                        vlUpdatedAt: processed.vlEnrichment?.updatedAt || null,
                        vlExploitationTechnique: processed.vlEnrichment?.exploitationTechnique || null,
                        vlAuthenticationType: processed.vlEnrichment?.authenticationType || null,
                        vlUserInteraction: processed.vlEnrichment?.userInteraction || null,
                        vlAuthor: processed.vlEnrichment?.author || null
                    }
                })
                logger.info(`[storeCVEMetadataReference] ✅ UPDATED reference for CVE ${cveId}: ${processed.url} (type: ${processed.type})`)
            } else {
                logger.info(`[storeCVEMetadataReference] Creating new reference (not found in DB)`)
                // Create new reference
                await prisma.cVEMetadataReferences.create({
                    data: {
                        cveId,
                        source,
                        url: processed.url,
                        referenceSource,
                        type: processed.type,
                        title: reference.title || processed.title,
                        createdAt: processed?.blobCreatedAt || processed?.vlEnrichment?.createdAt || processed?.gistEnrichment?.createdAt || processed?.exploitDbEnrichment?.date || processed?.commitEnrichment?.createdAt || processed?.prEnrichment?.merged_at || Math.floor(Date.now() / 1000),
                        httpStatus: processed.httpStatus,
                        deadLinkCheckedAt: checkHttp ? Math.floor(Date.now() / 1000) : null,
                        deadLink: processed.deadLink,
                        // GitHub PR enrichment fields
                        prDiffUrl: processed.prEnrichment?.diff_url || null,
                        prState: processed.prEnrichment?.state || null,
                        prAuthor: processed.prEnrichment?.author || null,
                        prLabels: processed.prEnrichment?.labels ? JSON.stringify(processed.prEnrichment.labels) : null,
                        prMergedAt: processed.prEnrichment?.merged_at || null,
                        prMergeCommitSha: processed.prEnrichment?.merge_commit_sha || null,
                        prRepoHealth: processed.prEnrichment?.health ? JSON.stringify(processed.prEnrichment.health) : null,
                        // GitHub Commit enrichment fields
                        commitAuthorEmail: processed.commitEnrichment?.author_email || null,
                        commitAuthorLogin: processed.commitEnrichment?.author_login || processed.gistEnrichment?.owner_login || null,
                        commitVerified: processed.commitEnrichment?.verified ? 1 : (processed.commitEnrichment ? 0 : null),
                        commitHealth: processed.commitEnrichment?.commit_health ? JSON.stringify(processed.commitEnrichment.commit_health) : null,
                        // GitHub Gist enrichment fields
                        gistId: processed.gistEnrichment?.gist_id || null,
                        gistPublic: processed.gistEnrichment?.public ? 1 : (processed.gistEnrichment ? 0 : null),
                        gistFilesCount: processed.gistEnrichment?.files_count || null,
                        gistFiles: processed.gistEnrichment?.files ? JSON.stringify(processed.gistEnrichment.files) : null,
                        gistComments: processed.gistEnrichment?.comments_count || null,
                        gistUpdatedAt: processed.gistEnrichment?.updatedAt || null,
                        // ExploitDB enrichment fields
                        exploitDbId: processed.exploitDbEnrichment?.exploitId || null,
                        exploitDbAuthor: processed.exploitDbEnrichment?.author || null,
                        exploitDbDate: processed.exploitDbEnrichment?.date || null,
                        exploitDbPlatform: processed.exploitDbEnrichment?.platform || null,
                        exploitDbType: processed.exploitDbEnrichment?.type || null,
                        exploitDbPort: processed.exploitDbEnrichment?.port || null,
                        exploitDbVerified: processed.exploitDbEnrichment?.verified ? 1 : (processed.exploitDbEnrichment ? 0 : null),
                        // VulnerabilityLab enrichment fields
                        vlId: processed.vlEnrichment?.vlId || null,
                        vlTitle: processed.vlEnrichment?.title || null,
                        vlCreatedAt: processed.vlEnrichment?.createdAt || null,
                        vlUpdatedAt: processed.vlEnrichment?.updatedAt || null,
                        vlExploitationTechnique: processed.vlEnrichment?.exploitationTechnique || null,
                        vlAuthenticationType: processed.vlEnrichment?.authenticationType || null,
                        vlUserInteraction: processed.vlEnrichment?.userInteraction || null,
                        vlAuthor: processed.vlEnrichment?.author || null
                    }
                })
                logger.info(`[storeCVEMetadataReference] ✅ CREATED reference for CVE ${cveId}: ${processed.url} (type: ${processed.type})`)
            }
        } else {
            logger.info(`[storeCVEMetadataReference] Normal mode - creating new reference`)
            // Normal create for non-force-refresh
            await prisma.cVEMetadataReferences.create({
                data: {
                    cveId,
                    source,
                    url: processed.url,
                    referenceSource,
                    type: processed.type,
                    title: reference.title || processed.title,
                    createdAt: processed?.blobCreatedAt || processed?.vlEnrichment?.createdAt || processed?.gistEnrichment?.createdAt || processed?.exploitDbEnrichment?.date || processed?.commitEnrichment?.createdAt || processed?.prEnrichment?.merged_at || Math.floor(Date.now() / 1000),
                    httpStatus: processed.httpStatus,
                    deadLinkCheckedAt: checkHttp ? Math.floor(Date.now() / 1000) : null,
                    deadLink: processed.deadLink,
                    // GitHub PR enrichment fields
                    prDiffUrl: processed.prEnrichment?.diff_url || null,
                    prState: processed.prEnrichment?.state || null,
                    prAuthor: processed.prEnrichment?.author || null,
                    prLabels: processed.prEnrichment?.labels ? JSON.stringify(processed.prEnrichment.labels) : null,
                    prMergedAt: processed.prEnrichment?.merged_at || null,
                    prMergeCommitSha: processed.prEnrichment?.merge_commit_sha || null,
                    prRepoHealth: processed.prEnrichment?.health ? JSON.stringify(processed.prEnrichment.health) : null,
                    // GitHub Commit enrichment fields
                    commitAuthorEmail: processed.commitEnrichment?.author_email || null,
                    commitAuthorLogin: processed.commitEnrichment?.author_login || processed.gistEnrichment?.owner_login || null,
                    commitVerified: processed.commitEnrichment?.verified ? 1 : (processed.commitEnrichment ? 0 : null),
                    commitHealth: processed.commitEnrichment?.commit_health ? JSON.stringify(processed.commitEnrichment.commit_health) : null,
                    // GitHub Gist enrichment fields
                    gistId: processed.gistEnrichment?.gist_id || null,
                    gistPublic: processed.gistEnrichment?.public ? 1 : (processed.gistEnrichment ? 0 : null),
                    gistFilesCount: processed.gistEnrichment?.files_count || null,
                    gistFiles: processed.gistEnrichment?.files ? JSON.stringify(processed.gistEnrichment.files) : null,
                    gistComments: processed.gistEnrichment?.comments_count || null,
                    gistUpdatedAt: processed.gistEnrichment?.updatedAt || null,
                    // ExploitDB enrichment fields
                    exploitDbId: processed.exploitDbEnrichment?.exploitId || null,
                    exploitDbAuthor: processed.exploitDbEnrichment?.author || null,
                    exploitDbDate: processed.exploitDbEnrichment?.date || null,
                    exploitDbPlatform: processed.exploitDbEnrichment?.platform || null,
                    exploitDbType: processed.exploitDbEnrichment?.type || null,
                    exploitDbPort: processed.exploitDbEnrichment?.port || null,
                    exploitDbVerified: processed.exploitDbEnrichment?.verified ? 1 : (processed.exploitDbEnrichment ? 0 : null),
                    // VulnerabilityLab enrichment fields
                    vlId: processed.vlEnrichment?.vlId || null,
                    vlTitle: processed.vlEnrichment?.title || null,
                    vlCreatedAt: processed.vlEnrichment?.createdAt || null,
                    vlUpdatedAt: processed.vlEnrichment?.updatedAt || null,
                    vlExploitationTechnique: processed.vlEnrichment?.exploitationTechnique || null,
                    vlAuthenticationType: processed.vlEnrichment?.authenticationType || null,
                    vlUserInteraction: processed.vlEnrichment?.userInteraction || null,
                    vlAuthor: processed.vlEnrichment?.author || null
                }
            })
            logger.info(`[storeCVEMetadataReference] ✅ STORED reference for CVE ${cveId}: ${processed.url} (type: ${processed.type})`)
        }

        // Enrich RESERVED CVE description with README if this is a GitHub repo
        if (processed.url.includes('github.com/')) {
            logger.info(`[storeCVEMetadataReference] GitHub URL detected, checking for RESERVED CVE enrichment opportunity`)
            await enrichReservedCVEWithReadme(prisma, cveId, source, processed.url, processed, logger)
        }
    } catch (error) {
        logger.error(`[storeCVEMetadataReference] ❌ FAILED to store CVE reference: ${error instanceof Error ? error.message : 'Unknown error'}`, error)
    }
}

/**
 * Batch process and store references for a CVEMetadata record
 */
export const batchStoreCVEReferences = async (
    prisma: PrismaClient,
    cveId: string,
    source: string,
    references: ReferenceData[],
    referenceSource: string,
    logger: Logger,
    checkHttp: boolean = false,
    forceRefresh: boolean = false
): Promise<void> => {
    logger.info(`[batchStoreCVEReferences] CALLED with ${references?.length || 0} references for CVE ${cveId}, source: ${source}, forceRefresh: ${forceRefresh}`)

    if (!references || references.length === 0) {
        logger.warn(`[batchStoreCVEReferences] No references to process for CVE ${cveId}`)
        return
    }

    logger.info(`[batchStoreCVEReferences] Starting to process ${references.length} references for CVE ${cveId} (forceRefresh: ${forceRefresh})`)

    let processedCount = 0
    for (const reference of references) {
        if (!reference?.url) {
            logger.warn(`[batchStoreCVEReferences] Skipping reference without URL: ${JSON.stringify(reference)}`)
            continue
        }
        logger.debug(`[batchStoreCVEReferences] Processing reference ${processedCount + 1}/${references.length}: ${reference.url}`)
        await storeCVEMetadataReference(prisma, cveId, source, reference, referenceSource, logger, checkHttp, forceRefresh)
        processedCount++
    }

    logger.info(`[batchStoreCVEReferences] COMPLETED processing ${processedCount} references for CVE ${cveId}`)
}

/**
 * Batch process and store references for a Finding
 */
export const batchStoreFindingReferences = async (
    prisma: PrismaClient,
    findingUuid: string,
    references: ReferenceData[],
    source: string,
    logger: Logger,
    checkHttp: boolean = false
): Promise<void> => {
    if (!references || references.length === 0) {
        return
    }

    logger.info(`Processing ${references.length} references for finding ${findingUuid}`)

    for (const reference of references) {
        if (!reference?.url) continue
        await storeFindingReference(prisma, findingUuid, reference, source, logger, checkHttp)
    }
}

/**
 * Update dead link status for existing references
 */
export const updateDeadLinkStatus = async (
    prisma: PrismaClient,
    referenceUuid: string,
    isForCVE: boolean,
    logger: Logger
): Promise<void> => {
    try {
        if (isForCVE) {
            const reference = await prisma.cVEMetadataReferences.findUnique({
                where: { uuid: referenceUuid }
            })

            if (!reference) {
                logger.warn(`Reference ${referenceUuid} not found`)
                return
            }

            const httpStatus = await checkHttpStatus(reference.url)
            let deadLink = 0

            if (httpStatus === null) {
                deadLink = 1 // Dead
            } else if (httpStatus >= 200 && httpStatus < 400) {
                deadLink = 2 // Alive
            } else {
                deadLink = 1 // Dead (4xx/5xx)
            }

            await prisma.cVEMetadataReferences.update({
                where: { uuid: referenceUuid },
                data: {
                    httpStatus,
                    deadLinkCheckedAt: Math.floor(Date.now() / 1000),
                    deadLink
                }
            })

            logger.info(`Updated dead link status for reference ${referenceUuid}: ${deadLink === 1 ? 'dead' : 'alive'}`)
        } else {
            const reference = await prisma.findingReferences.findUnique({
                where: { uuid: referenceUuid }
            })

            if (!reference) {
                logger.warn(`Reference ${referenceUuid} not found`)
                return
            }

            const httpStatus = await checkHttpStatus(reference.url)
            let deadLink = 0

            if (httpStatus === null) {
                deadLink = 1 // Dead
            } else if (httpStatus >= 200 && httpStatus < 400) {
                deadLink = 2 // Alive
            } else {
                deadLink = 1 // Dead (4xx/5xx)
            }

            await prisma.findingReferences.update({
                where: { uuid: referenceUuid },
                data: {
                    httpStatus,
                    deadLinkCheckedAt: Math.floor(Date.now() / 1000),
                    deadLink
                }
            })

            logger.info(`Updated dead link status for reference ${referenceUuid}: ${deadLink === 1 ? 'dead' : 'alive'}`)
        }
    } catch (error) {
        logger.error(`Failed to update dead link status: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
}

/**
 * Optimized batch store CVE references using PostgreSQL transactions
 * This improves performance by using efficient batch operations
 *
 * @param prisma - Prisma client (used for read operations only)
 * 
 * @param cveId - CVE identifier
 * @param source - Source identifier (e.g., 'osv', 'github', 'nvd')
 * @param references - Array of reference data to store
 * @param referenceSource - Source type for the reference
 * @param logger - Logger instance
 * @param checkHttp - Whether to check HTTP status (default: false, expensive)
 * @param forceRefresh - Whether to force refresh existing references
 */
export const batchStoreCVEReferencesOptimized = async (
    prisma: PrismaClient,
    cveId: string,
    source: string,
    references: ReferenceData[],
    referenceSource: string,
    logger: Logger,
    checkHttp: boolean = false,
    forceRefresh: boolean = false
): Promise<void> => {
    logger.info(`[batchStoreCVEReferencesOptimized] CALLED with ${references?.length || 0} references for CVE ${cveId}, source: ${source}, forceRefresh: ${forceRefresh}`)

    if (!references || references.length === 0) {
        logger.warn(`[batchStoreCVEReferencesOptimized] No references to process for CVE ${cveId}`)
        return
    }

    logger.info(`[batchStoreCVEReferencesOptimized] Starting optimized batch processing of ${references.length} references`)

    try {
        // Step 1: Process all references to get enriched data
        const processedReferences: ProcessedReference[] = []
        for (const reference of references) {
            if (!reference?.url) {
                logger.warn(`[batchStoreCVEReferencesOptimized] Skipping reference without URL`)
                continue
            }

            const processed = await processReference(reference.url, reference.type, checkHttp, logger)
            processedReferences.push({
                ...processed,
                title: reference.title || processed.title
            })
        }

        logger.info(`[batchStoreCVEReferencesOptimized] Processed ${processedReferences.length} references`)

        if (processedReferences.length === 0) {
            return
        }

        // Step 2: If not force refreshing, check which references already exist
        let existingUrls = new Set<string>()
        if (!forceRefresh) {
            const existing = await prisma.cVEMetadataReferences.findMany({
                where: {
                    cveId,
                    source,
                    url: {
                        in: processedReferences.map(ref => ref.url)
                    }
                },
                select: { url: true, uuid: true }
            })
            existingUrls = new Set(existing.map(ref => ref.url))
            logger.info(`[batchStoreCVEReferencesOptimized] Found ${existingUrls.size} existing references`)
        }

        // Step 3: Prepare batch operations
        const statements: any[] = []
        const newReferences = forceRefresh
            ? processedReferences
            : processedReferences.filter(ref => !existingUrls.has(ref.url))

        logger.info(`[batchStoreCVEReferencesOptimized] Preparing ${newReferences.length} new references for insertion`)

        // Batch insert new references using PostgreSQL transaction
        const insertOperations: Array<{ sql: string; params: any[] }> = []

        for (const processed of newReferences) {
            const uuid = crypto.randomUUID()

            const sql = `INSERT INTO "CVEMetadataReferences" (
                uuid, "cveId", source, url, "referenceSource", type, title, "createdAt",
                "httpStatus", "deadLinkCheckedAt", "deadLink",
                "prDiffUrl", "prState", "prAuthor", "prLabels", "prMergedAt", "prMergeCommitSha", "prRepoHealth",
                "commitAuthorEmail", "commitAuthorLogin", "commitVerified", "commitHealth",
                "gistId", "gistPublic", "gistFilesCount", "gistFiles", "gistComments", "gistUpdatedAt",
                "exploitDbId", "exploitDbAuthor", "exploitDbDate", "exploitDbPlatform", "exploitDbType", "exploitDbPort", "exploitDbVerified",
                "vlId", "vlTitle", "vlCreatedAt", "vlUpdatedAt", "vlExploitationTechnique", "vlAuthenticationType", "vlUserInteraction", "vlAuthor"
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43)
            ON CONFLICT (uuid) DO NOTHING`

            const params = [
                uuid,
                cveId,
                source,
                processed.url,
                referenceSource,
                processed.type,
                processed.title,
                processed?.blobCreatedAt || processed?.vlEnrichment?.createdAt || processed?.gistEnrichment?.createdAt || processed?.exploitDbEnrichment?.date || processed?.commitEnrichment?.createdAt || processed?.prEnrichment?.merged_at || Math.floor(Date.now() / 1000),
                processed.httpStatus,
                checkHttp ? Math.floor(Date.now() / 1000) : null,
                processed.deadLink,
                // GitHub PR enrichment
                processed.prEnrichment?.diff_url || null,
                processed.prEnrichment?.state || null,
                processed.prEnrichment?.author || null,
                processed.prEnrichment?.labels ? JSON.stringify(processed.prEnrichment.labels) : null,
                processed.prEnrichment?.merged_at || null,
                processed.prEnrichment?.merge_commit_sha || null,
                processed.prEnrichment?.health ? JSON.stringify(processed.prEnrichment.health) : null,
                // GitHub Commit enrichment
                processed.commitEnrichment?.author_email || null,
                processed.commitEnrichment?.author_login || processed.gistEnrichment?.owner_login || null,
                processed.commitEnrichment?.verified ? 1 : (processed.commitEnrichment ? 0 : null),
                processed.commitEnrichment?.commit_health ? JSON.stringify(processed.commitEnrichment.commit_health) : null,
                // GitHub Gist enrichment
                processed.gistEnrichment?.gist_id || null,
                processed.gistEnrichment?.public ? 1 : (processed.gistEnrichment ? 0 : null),
                processed.gistEnrichment?.files_count || null,
                processed.gistEnrichment?.files ? JSON.stringify(processed.gistEnrichment.files) : null,
                processed.gistEnrichment?.comments_count || null,
                processed.gistEnrichment?.updatedAt || null,
                // ExploitDB enrichment
                processed.exploitDbEnrichment?.exploitId || null,
                processed.exploitDbEnrichment?.author || null,
                processed.exploitDbEnrichment?.date || null,
                processed.exploitDbEnrichment?.platform || null,
                processed.exploitDbEnrichment?.type || null,
                processed.exploitDbEnrichment?.port || null,
                processed.exploitDbEnrichment?.verified ? 1 : (processed.exploitDbEnrichment ? 0 : null),
                // VulnerabilityLab enrichment
                processed.vlEnrichment?.vlId || null,
                processed.vlEnrichment?.title || null,
                processed.vlEnrichment?.createdAt || null,
                processed.vlEnrichment?.updatedAt || null,
                processed.vlEnrichment?.exploitationTechnique || null,
                processed.vlEnrichment?.authenticationType || null,
                processed.vlEnrichment?.userInteraction || null,
                processed.vlEnrichment?.author || null
            ]

            insertOperations.push({ sql, params })
        }

        // Step 4: Execute batch operations if there are any
        if (insertOperations.length > 0) {
            logger.info(`[batchStoreCVEReferencesOptimized] Executing batch insert of ${insertOperations.length} references`)

            // Execute in chunks for efficient processing (batch size of 100)
            const batchSize = 100
            for (let i = 0; i < insertOperations.length; i += batchSize) {
                const batch = insertOperations.slice(i, i + batchSize)
                try {
                    // Use Prisma transaction to execute all inserts in the batch
                    await prisma.$transaction(async (tx) => {
                        for (const operation of batch) {
                            await tx.$executeRawUnsafe(operation.sql, ...operation.params)
                        }
                    })
                    logger.debug(`[batchStoreCVEReferencesOptimized] Batch ${Math.floor(i / batchSize) + 1} completed: ${batch.length} inserts`)
                } catch (error: any) {
                    logger.error(`[batchStoreCVEReferencesOptimized] Batch insert failed at position ${i}:`, error)
                    // On error, fall back to individual inserts for this batch
                    logger.warn(`[batchStoreCVEReferencesOptimized] Falling back to individual inserts for failed batch`)
                    for (let j = i; j < Math.min(i + batchSize, newReferences.length); j++) {
                        const ref = newReferences[j]
                        await storeCVEMetadataReference(prisma, cveId, source, {
                            url: ref.url,
                            type: ref.type,
                            title: ref.title
                        }, referenceSource, logger, checkHttp, forceRefresh)
                    }
                }
            }

            logger.info(`[batchStoreCVEReferencesOptimized] COMPLETED batch insertion of ${newReferences.length} references`)
        } else {
            logger.info(`[batchStoreCVEReferencesOptimized] No new references to insert`)
        }

    } catch (error: any) {
        logger.error(`[batchStoreCVEReferencesOptimized] Unexpected error:`, error)
        throw error
    }
}
