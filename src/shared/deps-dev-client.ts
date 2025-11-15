/**
 * Deps.dev API Client
 *
 * Client for interacting with the deps.dev API to retrieve project metadata,
 * including OpenSSF Scorecard data for GitHub repositories.
 *
 * API Documentation: https://docs.deps.dev/api/v3/
 */

import { VULNETIX_USER_AGENT } from "./utils"

export interface DepsDevScorecardCheck {
    name: string
    documentation: {
        shortDescription: string
        url: string
    }
    score: number
    reason: string
    details: string[]
}

export interface DepsDevScorecard {
    date: string // ISO 8601 date string (YYYY-MM-DD)
    repository: {
        name: string // GitHub repository full name
        commit: string // Commit SHA
    }
    scorecard: {
        version: string
        commit: string
    }
    checks: DepsDevScorecardCheck[]
    overallScore: number
    metadata: string[]
}

export interface DepsDevProject {
    projectKey: {
        id: string
    }
    scorecard?: DepsDevScorecard
}

export interface DepsDevSLSAProvenance {
    sourceRepository: string
    commit: string
    url: string
    verified: boolean
}

export interface DepsDevAttestation {
    type: string
    url: string
    verified: boolean
    sourceRepository?: string
    commit?: string
}

export interface DepsDevLink {
    label: string
    url: string
}

export interface DepsDevRelatedProject {
    projectKey: {
        id: string
    }
    relationProvenance: string
    relationType: string
}

export interface DepsDevVersion {
    versionKey: {
        system: string
        name: string
        version: string
    }
    publishedAt: string // ISO 8601 timestamp
    isDefault: boolean
    licenses: string[]
    advisoryKeys: any[]
    links: DepsDevLink[]
    slsaProvenances: DepsDevSLSAProvenance[]
    attestations: DepsDevAttestation[]
    registries: string[]
    relatedProjects: DepsDevRelatedProject[]
}

export interface DepsDevPackageVersion {
    versionKey: {
        system: string
        name: string
        version: string
    }
}

export interface DepsDevProjectPackageVersions {
    versions: DepsDevPackageVersion[]
}

export interface DepsDevDependencyNode {
    versionKey: {
        system: string
        name: string
        version: string
    }
    bundled: boolean
    relation: string // SELF, DIRECT, INDIRECT
    errors: string[]
}

export interface DepsDevDependencyEdge {
    fromNode: number
    toNode: number
    requirement: string
}

export interface DepsDevDependencies {
    nodes: DepsDevDependencyNode[]
    edges: DepsDevDependencyEdge[]
    error: string
}

export interface DepsDevClientOptions {
    logger?: any
    baseUrl?: string
}

/**
 * Client for deps.dev API v3
 */
export class DepsDevClient {
    private readonly baseUrl: string
    private readonly logger: any

    constructor(options: DepsDevClientOptions = {}) {
        this.baseUrl = options.baseUrl || `https://api.deps.dev`
        this.logger = options.logger || console
    }

    /**
     * Get project data including OpenSSF Scorecard
     *
     * @param repoFullName - GitHub repository full name (owner/repo)
     * @returns Project data with scorecard or null if not found
     */
    async getProject(repoFullName: string): Promise<DepsDevProject | null> {
        const projectKey = `github.com/${repoFullName}`
        const url = `${this.baseUrl}/v3/projects/${encodeURIComponent(projectKey)}`

        this.logger.debug(`[DepsDevClient] Fetching project data for ${projectKey}`)

        try {
            const response = await fetch(url, {
                method: `GET`,
                headers: {
                    'Accept': `application/json`,
                    'User-Agent': VULNETIX_USER_AGENT
                }
            })

            if (!response.ok) {
                if (response.status === 404) {
                    this.logger.debug(`[DepsDevClient] Project not found: ${projectKey}`)
                    return null
                }
                throw new Error(`Deps.dev API returned ${response.status}: ${response.statusText}`)
            }

            const data = await response.json() as DepsDevProject

            this.logger.debug(`[DepsDevClient] Retrieved project data for ${projectKey}`, {
                hasScorecard: !!data.scorecard,
                overallScore: data.scorecard?.overallScore
            })

            return data
        } catch (error) {
            this.logger.error(`[DepsDevClient] Failed to fetch project data for ${projectKey}:`, error)
            return null
        }
    }

    /**
     * Get OpenSSF Scorecard data for a GitHub repository
     *
     * @param repoFullName - GitHub repository full name (owner/repo)
     * @returns Scorecard data or null if not found
     */
    async getScorecard(repoFullName: string): Promise<DepsDevScorecard | null> {
        const project = await this.getProject(repoFullName)

        if (!project || !project.scorecard) {
            this.logger.debug(`[DepsDevClient] No scorecard data available for ${repoFullName}`)
            return null
        }

        this.logger.info(`[DepsDevClient] Found scorecard for ${repoFullName}`, {
            overallScore: project.scorecard.overallScore,
            checks: project.scorecard.checks.length,
            date: project.scorecard.date
        })

        return project.scorecard
    }

    /**
     * Get package version metadata from deps.dev
     *
     * API: GET /v3/systems/:ecosystem/packages/:packageName/versions/:packageVersion
     *
     * @param ecosystem - Package ecosystem (e.g., NPM, PyPI, Maven, Go, Cargo)
     * @param packageName - Package name
     * @param packageVersion - Package version
     * @returns Version metadata including SLSA provenances, attestations, licenses, etc.
     */
    async getVersion(ecosystem: string, packageName: string, packageVersion: string): Promise<DepsDevVersion | null> {
        // Normalize ecosystem to uppercase (deps.dev expects uppercase)
        const normalizedEcosystem = ecosystem.toUpperCase()

        // URL encode package name and version to handle special characters
        const encodedPackageName = encodeURIComponent(packageName)
        const encodedVersion = encodeURIComponent(packageVersion)

        const url = `${this.baseUrl}/v3/systems/${normalizedEcosystem}/packages/${encodedPackageName}/versions/${encodedVersion}`

        this.logger.debug(`[DepsDevClient] Fetching version metadata for ${normalizedEcosystem}:${packageName}@${packageVersion}`)

        try {
            const response = await fetch(url, {
                method: `GET`,
                headers: {
                    'Accept': `application/json`,
                    'User-Agent': VULNETIX_USER_AGENT
                }
            })

            if (!response.ok) {
                if (response.status === 404) {
                    this.logger.debug(`[DepsDevClient] Version not found: ${normalizedEcosystem}:${packageName}@${packageVersion}`)
                    return null
                }
                throw new Error(`Deps.dev API returned ${response.status}: ${response.statusText}`)
            }

            const data = await response.json() as DepsDevVersion

            this.logger.info(`[DepsDevClient] Retrieved version metadata for ${normalizedEcosystem}:${packageName}@${packageVersion}`, {
                publishedAt: data.publishedAt,
                hasProvenances: data.slsaProvenances?.length > 0,
                hasAttestations: data.attestations?.length > 0,
                licenses: data.licenses?.length || 0
            })

            return data
        } catch (error) {
            this.logger.error(`[DepsDevClient] Failed to fetch version metadata for ${normalizedEcosystem}:${packageName}@${packageVersion}:`, error)
            return null
        }
    }

    /**
     * Get all package versions published from a GitHub project
     * Useful for detecting which package ecosystem a repository belongs to
     *
     * API: GET /v3/projects/:projectKey:packageversions
     *
     * @param repoFullName - GitHub repository full name (owner/repo)
     * @returns Package versions with their ecosystems
     */
    async getProjectPackageVersions(repoFullName: string): Promise<DepsDevProjectPackageVersions | null> {
        const projectKey = `github.com/${repoFullName}`
        const url = `${this.baseUrl}/v3/projects/${encodeURIComponent(projectKey)}:packageversions`

        this.logger.debug(`[DepsDevClient] Fetching package versions for ${projectKey}`)

        try {
            const response = await fetch(url, {
                method: `GET`,
                headers: {
                    'Accept': `application/json`,
                    'User-Agent': VULNETIX_USER_AGENT
                }
            })

            if (!response.ok) {
                if (response.status === 404) {
                    this.logger.debug(`[DepsDevClient] No package versions found for ${projectKey}`)
                    return null
                }
                throw new Error(`Deps.dev API returned ${response.status}: ${response.statusText}`)
            }

            const data = await response.json() as DepsDevProjectPackageVersions

            this.logger.info(`[DepsDevClient] Retrieved ${data.versions?.length || 0} package versions for ${projectKey}`, {
                ecosystems: [...new Set(data.versions?.map((v: DepsDevPackageVersion) => v.versionKey.system) || [])]
            })

            return data
        } catch (error) {
            this.logger.error(`[DepsDevClient] Failed to fetch package versions for ${projectKey}:`, error)
            return null
        }
    }

    /**
     * Get dependency graph for a specific package version
     *
     * API: GET /v3/systems/:ecosystem/packages/:packageName/versions/:packageVersion:dependencies
     *
     * @param ecosystem - Package ecosystem (e.g., NPM, PyPI, Maven, Go, Cargo)
     * @param packageName - Package name
     * @param packageVersion - Package version
     * @returns Dependency graph with nodes and edges
     */
    async getPackageDependencies(ecosystem: string, packageName: string, packageVersion: string): Promise<DepsDevDependencies | null> {
        // Normalize ecosystem to uppercase (deps.dev expects uppercase)
        const normalizedEcosystem = ecosystem.toUpperCase()

        // URL encode package name and version to handle special characters
        const encodedPackageName = encodeURIComponent(packageName)
        const encodedVersion = encodeURIComponent(packageVersion)

        const url = `${this.baseUrl}/v3/systems/${normalizedEcosystem}/packages/${encodedPackageName}/versions/${encodedVersion}:dependencies`

        this.logger.debug(`[DepsDevClient] Fetching dependencies for ${normalizedEcosystem}:${packageName}@${packageVersion}`)

        try {
            const response = await fetch(url, {
                method: `GET`,
                headers: {
                    'Accept': `application/json`,
                    'User-Agent': VULNETIX_USER_AGENT
                }
            })

            if (!response.ok) {
                if (response.status === 404) {
                    this.logger.debug(`[DepsDevClient] No dependencies found for ${normalizedEcosystem}:${packageName}@${packageVersion}`)
                    return null
                }
                throw new Error(`Deps.dev API returned ${response.status}: ${response.statusText}`)
            }

            const data = await response.json() as DepsDevDependencies

            this.logger.info(`[DepsDevClient] Retrieved dependency graph for ${normalizedEcosystem}:${packageName}@${packageVersion}`, {
                nodes: data.nodes?.length || 0,
                edges: data.edges?.length || 0,
                hasError: !!data.error
            })

            return data
        } catch (error) {
            this.logger.error(`[DepsDevClient] Failed to fetch dependencies for ${normalizedEcosystem}:${packageName}@${packageVersion}:`, error)
            return null
        }
    }
}
