/**
 * OpenSSF Scorecard Service
 *
 * Service for fetching and storing OpenSSF Scorecard data for GitHub repositories.
 * Implements 7-day caching to avoid unnecessary API calls.
 */

import type { PrismaClient } from '@prisma/client'
import { DepsDevClient, type DepsDevScorecard } from '@shared/deps-dev-client'

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds
const SEVEN_DAYS_SECONDS = 7 * 24 * 60 * 60 // 7 days in seconds

export interface ScorecardServiceOptions {
    prisma: PrismaClient
    logger?: any
}

/**
 * Service for managing OpenSSF Scorecard data
 */
export class OpenSSFScorecardService {
    private readonly prisma: PrismaClient
    private readonly logger: any
    private readonly depsDevClient: DepsDevClient

    constructor(options: ScorecardServiceOptions) {
        this.prisma = options.prisma
        this.logger = options.logger || console
        this.depsDevClient = new DepsDevClient({ logger: this.logger })
    }

    /**
     * Check if we have recent scorecard data (within 7 days)
     *
     * @param githubRepositoryId - GitHub repository ID
     * @returns true if we have recent data (< 7 days old), false otherwise
     */
    private async hasRecentScorecard(githubRepositoryId: number): Promise<boolean> {
        const sevenDaysAgo = Math.floor((Date.now() - SEVEN_DAYS_MS) / 1000)

        const recentScorecard = await this.prisma.openSSFScorecard.findFirst({
            where: {
                githubRepositoryId,
                createdAt: {
                    gte: sevenDaysAgo
                }
            },
            orderBy: {
                createdAt: `desc`
            }
        })

        return !!recentScorecard
    }

    /**
     * Parse ISO date string to Unix timestamp (seconds)
     * Scorecard date format: "YYYY-MM-DD" (midnight UTC)
     */
    private parseDate(dateString: string): number {
        const date = new Date(dateString)
        return Math.floor(date.getTime() / 1000)
    }

    /**
     * Store scorecard data in database
     *
     * @param githubRepositoryId - GitHub repository ID (optional)
     * @param scorecard - Scorecard data from deps.dev
     * @returns Created scorecard UUID
     */
    private async storeScorecardData(
        githubRepositoryId: number | null,
        scorecard: DepsDevScorecard
    ): Promise<string> {
        const timestamp = Math.floor(Date.now() / 1000)
        const scorecardDate = this.parseDate(scorecard.date)

        this.logger.info(`[ScorecardService] Storing scorecard for repository ${githubRepositoryId || 'standalone'}`, {
            date: scorecard.date,
            overallScore: scorecard.overallScore,
            checks: scorecard.checks.length
        })

        try {
            // Generate UUID for the scorecard
            const scorecardUuid = crypto.randomUUID()
            this.logger.debug(`[ScorecardService] Generated scorecard UUID: ${scorecardUuid}`)

            // Create OpenSSFScorecard record
            this.logger.debug(`[ScorecardService] Creating OpenSSFScorecard record`)
            await this.prisma.openSSFScorecard.create({
                data: {
                    uuid: scorecardUuid,
                    githubRepositoryId,
                    date: scorecardDate,
                    repositoryName: scorecard.repository.name,
                    repositoryCommit: scorecard.repository.commit,
                    scorecardVersion: scorecard.scorecard.version,
                    scorecardCommit: scorecard.scorecard.commit,
                    overallScore: scorecard.overallScore,
                    metadata: JSON.stringify(scorecard.metadata || []),
                    createdAt: timestamp
                }
            })
            this.logger.debug(`[ScorecardService] Created OpenSSFScorecard record`)

            // Create OpenSSFScorecardCheck records for each check
            this.logger.debug(`[ScorecardService] Creating ${scorecard.checks.length} check records`)
            for (let i = 0; i < scorecard.checks.length; i++) {
                const check = scorecard.checks[i]
                this.logger.debug(`[ScorecardService] Creating check ${i + 1}/${scorecard.checks.length}: ${check.name}`)
                await this.prisma.openSSFScorecardCheck.create({
                    data: {
                        uuid: crypto.randomUUID(),
                        scorecardUuid,
                        name: check.name,
                        shortDescription: check.documentation.shortDescription,
                        documentationUrl: check.documentation.url,
                        score: check.score,
                        reason: check.reason,
                        details: JSON.stringify(check.details || [])
                    }
                })
            }
            this.logger.debug(`[ScorecardService] Created all ${scorecard.checks.length} check records`)

            this.logger.info(`[ScorecardService] Successfully stored scorecard with ${scorecard.checks.length} checks (UUID: ${scorecardUuid})`)
            return scorecardUuid
        } catch (error) {
            this.logger.error(`[ScorecardService] Error storing scorecard data:`, error)
            throw error
        }
    }

    /**
     * Fetch and store scorecard data for a GitHub repository
     * Respects 7-day cache - skips if recent data exists
     *
     * @param githubRepositoryId - GitHub repository ID
     * @param repoFullName - Repository full name (owner/repo)
     * @returns Scorecard UUID if fetched/stored, null if cached or unavailable
     */
    async fetchAndStoreScorecard(
        githubRepositoryId: number,
        repoFullName: string
    ): Promise<string | null> {
        try {
            this.logger.debug(`[ScorecardService] Checking scorecard for ${repoFullName}`)

            // Check for recent scorecard (7-day cache)
            const hasRecent = await this.hasRecentScorecard(githubRepositoryId)
            if (hasRecent) {
                this.logger.info(`[ScorecardService] Recent scorecard exists for ${repoFullName}, skipping fetch`)
                // Get the existing scorecard UUID
                const existing = await this.getLatestScorecard(githubRepositoryId)
                this.logger.info(`[ScorecardService] Returning existing scorecard UUID: ${existing?.uuid}`)
                return existing?.uuid || null
            }

            // Fetch scorecard from deps.dev
            this.logger.info(`[ScorecardService] Fetching scorecard from deps.dev for ${repoFullName}`)
            const scorecard = await this.depsDevClient.getScorecard(repoFullName)

            if (!scorecard) {
                this.logger.warn(`[ScorecardService] No scorecard data available for ${repoFullName}`)
                return null
            }

            // Store scorecard data
            this.logger.info(`[ScorecardService] About to store scorecard data for ${repoFullName}`)
            const scorecardUuid = await this.storeScorecardData(githubRepositoryId, scorecard)
            this.logger.info(`[ScorecardService] Stored scorecard, UUID: ${scorecardUuid}`)

            this.logger.info(`[ScorecardService] Successfully fetched and stored scorecard for ${repoFullName}`)
            return scorecardUuid
        } catch (error) {
            this.logger.error(`[ScorecardService] Error in fetchAndStoreScorecard for ${repoFullName}:`, error)
            throw error
        }
    }

    /**
     * Fetch and store scorecard data without a GitHubRepository link
     * Useful for packages in non-GitHub ecosystems
     *
     * @param repoFullName - Repository full name (owner/repo)
     * @returns Scorecard UUID if fetched/stored, null if unavailable
     */
    async fetchAndStoreScorecardStandalone(
        repoFullName: string
    ): Promise<string | null> {
        this.logger.debug(`[ScorecardService] Fetching standalone scorecard for ${repoFullName}`)

        // Fetch scorecard from deps.dev
        this.logger.info(`[ScorecardService] Fetching scorecard from deps.dev for ${repoFullName}`)
        const scorecard = await this.depsDevClient.getScorecard(repoFullName)

        if (!scorecard) {
            this.logger.warn(`[ScorecardService] No scorecard data available for ${repoFullName}`)
            return null
        }

        // Store scorecard data without repository link
        const scorecardUuid = await this.storeScorecardData(null, scorecard)

        this.logger.info(`[ScorecardService] Successfully fetched and stored standalone scorecard for ${repoFullName}`)
        return scorecardUuid
    }

    /**
     * Get latest scorecard for a repository
     *
     * @param githubRepositoryId - GitHub repository ID
     * @returns Latest scorecard with checks, or null if none exists
     */
    async getLatestScorecard(githubRepositoryId: number) {
        return await this.prisma.openSSFScorecard.findFirst({
            where: {
                githubRepositoryId
            },
            include: {
                checks: true
            },
            orderBy: {
                date: `desc`
            }
        })
    }

    /**
     * Link a scorecard to CVEMetadata records
     * Updates CVEMetadata records with the scorecard UUID
     *
     * @param cveId - CVE ID
     * @param source - CVE source (e.g., 'cve.org', 'osv', 'github')
     * @param scorecardUuid - Scorecard UUID to link
     * @returns Number of CVEMetadata records updated
     */
    async linkScorecardToCVEMetadata(
        cveId: string,
        source: string,
        scorecardUuid: string
    ): Promise<number> {
        try {
            this.logger.info(`[ScorecardService] Linking scorecard ${scorecardUuid} to ${cveId}:${source}`)

            const result = await this.prisma.cVEMetadata.updateMany({
                where: {
                    cveId,
                    source
                },
                data: {
                    scorecardUuid
                }
            })

            this.logger.info(`[ScorecardService] Linked scorecard to ${result.count} CVEMetadata record(s)`)
            return result.count
        } catch (error) {
            this.logger.error(`[ScorecardService] Failed to link scorecard to CVEMetadata:`, error)
            throw error
        }
    }

    /**
     * Link a scorecard to multiple CVEMetadata sources for the same CVE
     *
     * @param cveId - CVE ID
     * @param scorecardUuid - Scorecard UUID to link
     * @returns Number of CVEMetadata records updated
     */
    async linkScorecardToAllCVESources(
        cveId: string,
        scorecardUuid: string
    ): Promise<number> {
        try {
            this.logger.info(`[ScorecardService] Linking scorecard ${scorecardUuid} to all sources for ${cveId}`)

            const result = await this.prisma.cVEMetadata.updateMany({
                where: {
                    cveId
                },
                data: {
                    scorecardUuid
                }
            })

            this.logger.info(`[ScorecardService] Linked scorecard to ${result.count} CVEMetadata record(s) across all sources`)
            return result.count
        } catch (error) {
            this.logger.error(`[ScorecardService] Failed to link scorecard to CVEMetadata:`, error)
            throw error
        }
    }
}
