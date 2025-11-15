/**
 * Registry Version Discovery Service
 *
 * Discovers fixed versions from package registries by:
 * 1. Fetching all available versions from deps.dev (primary) or direct registries (fallback)
 * 2. Comparing versions against CVE affected ranges to classify them as vulnerable/fixed
 * 3. Storing discovered versions and their CVE relationships to the database
 * 4. Using multi-layer caching (database -> API) with 7-day staleness threshold
 */

import type { PrismaClient } from '@prisma/client'
import type { PackageEcosystem } from '../../shared/ecosystem-helpers'
import { DepsDevClient } from '../../shared/deps-dev-client'
import { isVersionVulnerable, versionSorter } from '../../shared/utils'
import { randomUUID } from 'crypto'

export interface DiscoveryOptions {
    cveId: string
    ecosystem: PackageEcosystem
    packageName: string
    affectedRange: string // e.g., "< 1.2.0", ">= 1.0.0 < 2.0.0"
    vendor?: string
}

export interface DiscoveryResult {
    affectedVersions: VersionInfo[]
    fixedVersions: VersionInfo[]
    unaffectedVersions: VersionInfo[]
    confidence: 'high' | 'medium' | 'low'
    source: string // "deps.dev", "registry.npmjs.org", etc.
}

export interface VersionInfo {
    version: string
    publishedAt?: string
}

export interface RegistryVersionDiscoveryOptions {
    prisma: PrismaClient
    logger?: any
    depsDevClient?: DepsDevClient
    cacheTTL?: number // Milliseconds, default 7 days
}

/**
 * Registry Version Discovery Service
 */
export class RegistryVersionDiscovery {
    private prisma: PrismaClient
    private logger: any
    private depsDevClient: DepsDevClient
    private cacheTTL: number
    private memoryCache: Map<string, { versions: string[], expiry: number, source: string }>

    constructor(options: RegistryVersionDiscoveryOptions) {
        this.prisma = options.prisma
        this.logger = options.logger || console
        this.depsDevClient = options.depsDevClient || new DepsDevClient({ logger: options.logger })
        this.cacheTTL = options.cacheTTL || (7 * 24 * 60 * 60 * 1000) // 7 days
        this.memoryCache = new Map()
    }

    /**
     * Discover fixed versions for a CVE by fetching all package versions and classifying them
     */
    async discoverFixedVersions(options: DiscoveryOptions): Promise<DiscoveryResult> {
        const { cveId, ecosystem, packageName, affectedRange, vendor } = options

        this.logger.info(`[RegistryVersionDiscovery] Discovering versions for ${ecosystem}:${packageName} (CVE: ${cveId})`)

        // Step 1: Get all versions (cached or fresh)
        const { versions, source, confidence } = await this.getAllVersions(ecosystem, packageName, vendor)

        if (versions.length === 0) {
            this.logger.warn(`[RegistryVersionDiscovery] No versions found for ${ecosystem}:${packageName}`)
            return {
                affectedVersions: [],
                fixedVersions: [],
                unaffectedVersions: [],
                confidence: 'low',
                source
            }
        }

        this.logger.debug(`[RegistryVersionDiscovery] Found ${versions.length} versions from ${source}`)

        // Step 2: Classify versions using affected range
        const classified = this.classifyVersions(versions, affectedRange)

        this.logger.info(`[RegistryVersionDiscovery] Classified versions: ${classified.affectedVersions.length} affected, ${classified.fixedVersions.length} fixed`)

        // Step 3: Store versions in database
        await this.storeVersionsInDatabase(ecosystem, packageName, versions, source)

        // Step 4: Store CVE relationships
        await this.storeCVERelationships(cveId, ecosystem, packageName, classified, affectedRange)

        return {
            ...classified,
            confidence,
            source
        }
    }

    /**
     * Get all versions for a package (with caching)
     */
    private async getAllVersions(
        ecosystem: PackageEcosystem,
        packageName: string,
        vendor?: string
    ): Promise<{ versions: string[], source: string, confidence: 'high' | 'medium' | 'low' }> {
        const cacheKey = `${ecosystem}:${packageName}`

        // Check memory cache first
        const cached = this.memoryCache.get(cacheKey)
        if (cached && Date.now() < cached.expiry) {
            this.logger.debug(`[RegistryVersionDiscovery] Memory cache hit for ${cacheKey}`)
            return { versions: cached.versions, source: cached.source, confidence: 'high' }
        }

        // Check database cache
        const dbCached = await this.getVersionsFromDatabase(ecosystem, packageName)
        if (dbCached && dbCached.versions.length > 0) {
            const staleness = Date.now() - dbCached.lastVerifiedAt
            if (staleness < this.cacheTTL) {
                this.logger.debug(`[RegistryVersionDiscovery] Database cache hit for ${cacheKey} (age: ${Math.floor(staleness / 1000 / 60 / 60)}h)`)

                // Refresh memory cache
                this.memoryCache.set(cacheKey, {
                    versions: dbCached.versions,
                    expiry: Date.now() + (60 * 60 * 1000), // 1 hour memory cache
                    source: dbCached.source
                })

                return { versions: dbCached.versions, source: dbCached.source, confidence: 'high' }
            }
        }

        // Fetch from API
        this.logger.debug(`[RegistryVersionDiscovery] Fetching fresh versions for ${cacheKey}`)

        // Try deps.dev first
        let versions = await this.fetchFromDepsDevWithVersionsEndpoint(ecosystem, packageName)
        let source = 'deps.dev'
        let confidence: 'high' | 'medium' | 'low' = 'high'

        if (!versions || versions.length === 0) {
            // Fallback to direct registry
            this.logger.debug(`[RegistryVersionDiscovery] deps.dev failed, trying direct registry`)
            versions = await this.fetchFromDirectRegistry(ecosystem, packageName, vendor)
            source = this.getRegistrySource(ecosystem)
            confidence = 'medium'
        }

        if (!versions || versions.length === 0) {
            return { versions: [], source: 'none', confidence: 'low' }
        }

        // Update memory cache
        this.memoryCache.set(cacheKey, {
            versions,
            expiry: Date.now() + (60 * 60 * 1000), // 1 hour
            source
        })

        return { versions, source, confidence }
    }

    /**
     * Fetch versions from deps.dev package versions endpoint
     * Note: This requires a new method to be added to DepsDevClient
     */
    private async fetchFromDepsDevWithVersionsEndpoint(
        ecosystem: PackageEcosystem,
        packageName: string
    ): Promise<string[] | null> {
        try {
            const normalizedEcosystem = ecosystem.toUpperCase()
            const encodedPackageName = encodeURIComponent(packageName)
            const url = `https://api.deps.dev/v3/systems/${normalizedEcosystem}/packages/${encodedPackageName}/versions`

            this.logger.debug(`[RegistryVersionDiscovery] Fetching from deps.dev: ${url}`)

            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'Vulnetix-VDB/1.0'
                }
            })

            if (!response.ok) {
                this.logger.debug(`[RegistryVersionDiscovery] deps.dev returned ${response.status}`)
                return null
            }

            const data: any = await response.json()

            // deps.dev returns: { versions: [{ versionKey: { system, name, version } }] }
            if (!data.versions || !Array.isArray(data.versions)) {
                return null
            }

            const versions = data.versions
                .map((v: any) => v.versionKey?.version)
                .filter((v: any) => typeof v === 'string')
                .sort(versionSorter)

            this.logger.info(`[RegistryVersionDiscovery] deps.dev returned ${versions.length} versions`)
            return versions
        } catch (error: any) {
            this.logger.warn(`[RegistryVersionDiscovery] deps.dev fetch failed:`, error.message)
            return null
        }
    }

    /**
     * Fetch versions from direct registry APIs (fallback)
     */
    private async fetchFromDirectRegistry(
        ecosystem: PackageEcosystem,
        packageName: string,
        vendor?: string
    ): Promise<string[] | null> {
        switch (ecosystem) {
            case 'npm':
                return this.fetchNpmVersions(packageName, vendor)
            case 'pypi':
                return this.fetchPyPIVersions(packageName)
            case 'maven':
                return this.fetchMavenVersions(packageName, vendor)
            case 'rubygems':
                return this.fetchRubyGemsVersions(packageName)
            case 'cargo':
                return this.fetchCargoVersions(packageName)
            default:
                this.logger.debug(`[RegistryVersionDiscovery] No direct registry implementation for ${ecosystem}`)
                return null
        }
    }

    /**
     * Fetch versions from NPM registry
     */
    private async fetchNpmVersions(packageName: string, vendor?: string): Promise<string[] | null> {
        try {
            // Try scoped package if vendor provided
            const pkgName = vendor ? `@${vendor}/${packageName}` : packageName
            const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`

            const response = await fetch(url, {
                headers: { 'Accept': 'application/json' }
            })

            if (!response.ok) {
                // If scoped failed, try unscoped
                if (vendor) {
                    return this.fetchNpmVersions(packageName)
                }
                return null
            }

            const data: any = await response.json()

            if (!data.versions || typeof data.versions !== 'object') {
                return null
            }

            return Object.keys(data.versions).sort(versionSorter)
        } catch (error: any) {
            this.logger.warn(`[RegistryVersionDiscovery] NPM fetch failed:`, error.message)
            return null
        }
    }

    /**
     * Fetch versions from PyPI
     */
    private async fetchPyPIVersions(packageName: string): Promise<string[] | null> {
        try {
            const normalizedName = packageName.toLowerCase().replace(/_/g, '-')
            const url = `https://pypi.org/pypi/${encodeURIComponent(normalizedName)}/json`

            const response = await fetch(url, {
                headers: { 'Accept': 'application/json' }
            })

            if (!response.ok) return null

            const data: any = await response.json()

            if (!data.releases || typeof data.releases !== 'object') {
                return null
            }

            return Object.keys(data.releases).sort(versionSorter)
        } catch (error: any) {
            this.logger.warn(`[RegistryVersionDiscovery] PyPI fetch failed:`, error.message)
            return null
        }
    }

    /**
     * Fetch versions from Maven Central
     */
    private async fetchMavenVersions(packageName: string, vendor?: string): Promise<string[] | null> {
        try {
            let groupId: string, artifactId: string

            if (packageName.includes(':')) {
                [groupId, artifactId] = packageName.split(':')
            } else if (vendor) {
                groupId = vendor
                artifactId = packageName
            } else {
                return null // Can't determine Maven coordinates
            }

            const url = `https://search.maven.org/solrsearch/select?q=g:"${encodeURIComponent(groupId)}"+AND+a:"${encodeURIComponent(artifactId)}"&rows=100&wt=json`

            const response = await fetch(url, {
                headers: { 'Accept': 'application/json' }
            })

            if (!response.ok) return null

            const data: any = await response.json()

            if (!data.response?.docs || !Array.isArray(data.response.docs)) {
                return null
            }

            const versions = data.response.docs
                .map((doc: any) => doc.v)
                .filter((v: any) => typeof v === 'string')
                .sort(versionSorter)

            return versions
        } catch (error: any) {
            this.logger.warn(`[RegistryVersionDiscovery] Maven fetch failed:`, error.message)
            return null
        }
    }

    /**
     * Fetch versions from RubyGems
     */
    private async fetchRubyGemsVersions(packageName: string): Promise<string[] | null> {
        try {
            const url = `https://rubygems.org/api/v1/versions/${encodeURIComponent(packageName)}.json`

            const response = await fetch(url, {
                headers: { 'Accept': 'application/json' }
            })

            if (!response.ok) return null

            const data: any = await response.json()

            if (!Array.isArray(data)) return null

            const versions = data
                .map((item: any) => item.number)
                .filter((v: any) => typeof v === 'string')
                .sort(versionSorter)

            return versions
        } catch (error: any) {
            this.logger.warn(`[RegistryVersionDiscovery] RubyGems fetch failed:`, error.message)
            return null
        }
    }

    /**
     * Fetch versions from Cargo (crates.io)
     */
    private async fetchCargoVersions(packageName: string): Promise<string[] | null> {
        try {
            const url = `https://crates.io/api/v1/crates/${encodeURIComponent(packageName)}`

            const response = await fetch(url, {
                headers: { 'Accept': 'application/json' }
            })

            if (!response.ok) return null

            const data: any = await response.json()

            if (!data.versions || !Array.isArray(data.versions)) {
                return null
            }

            const versions = data.versions
                .map((v: any) => v.num)
                .filter((v: any) => typeof v === 'string')
                .sort(versionSorter)

            return versions
        } catch (error: any) {
            this.logger.warn(`[RegistryVersionDiscovery] Cargo fetch failed:`, error.message)
            return null
        }
    }

    /**
     * Classify versions based on affected range
     */
    private classifyVersions(
        versions: string[],
        affectedRange: string
    ): Pick<DiscoveryResult, 'affectedVersions' | 'fixedVersions' | 'unaffectedVersions'> {
        const affected: VersionInfo[] = []
        const fixed: VersionInfo[] = []
        const unaffected: VersionInfo[] = []

        for (const version of versions) {
            try {
                const isVulnerable = isVersionVulnerable(version, [affectedRange])

                if (isVulnerable) {
                    affected.push({ version })
                } else {
                    // Versions outside affected range are potential fixes
                    fixed.push({ version })
                }
            } catch (error: any) {
                this.logger.debug(`[RegistryVersionDiscovery] Failed to classify version ${version}:`, error.message)
                unaffected.push({ version })
            }
        }

        return { affectedVersions: affected, fixedVersions: fixed, unaffectedVersions: unaffected }
    }

    /**
     * Store versions in database
     */
    private async storeVersionsInDatabase(
        ecosystem: PackageEcosystem,
        packageName: string,
        versions: string[],
        source: string
    ): Promise<void> {
        const now = Math.floor(Date.now() / 1000)

        try {
            // Batch insert/update versions
            for (const version of versions) {
                await this.prisma.packageVersion.upsert({
                    where: {
                        ecosystem_packageName_version: {
                            ecosystem,
                            packageName,
                            version
                        }
                    },
                    create: {
                        uuid: randomUUID(),
                        ecosystem,
                        packageName,
                        version,
                        discoveredFrom: source,
                        discoveredAt: now,
                        lastVerifiedAt: now,
                        createdAt: now
                    },
                    update: {
                        lastVerifiedAt: now,
                        updatedAt: now
                    }
                })
            }

            this.logger.info(`[RegistryVersionDiscovery] Stored ${versions.length} versions to database`)
        } catch (error: any) {
            this.logger.error(`[RegistryVersionDiscovery] Failed to store versions:`, error)
        }
    }

    /**
     * Store CVE relationships
     */
    private async storeCVERelationships(
        cveId: string,
        ecosystem: PackageEcosystem,
        packageName: string,
        classified: Pick<DiscoveryResult, 'affectedVersions' | 'fixedVersions' | 'unaffectedVersions'>,
        affectedRange: string
    ): Promise<void> {
        const now = Math.floor(Date.now() / 1000)

        try {
            // Store affected versions
            for (const { version } of classified.affectedVersions) {
                const packageVersion = await this.prisma.packageVersion.findUnique({
                    where: {
                        ecosystem_packageName_version: {
                            ecosystem,
                            packageName,
                            version
                        }
                    }
                })

                if (packageVersion) {
                    await this.prisma.packageVersionCVE.upsert({
                        where: {
                            packageVersionId_cveId_relationshipType: {
                                packageVersionId: packageVersion.uuid,
                                cveId,
                                relationshipType: 'affected'
                            }
                        },
                        create: {
                            uuid: randomUUID(),
                            packageVersionId: packageVersion.uuid,
                            cveId,
                            relationshipType: 'affected',
                            determinedBy: 'registry_inference',
                            confidence: 'medium',
                            versionRange: affectedRange,
                            createdAt: now
                        },
                        update: {
                            // Don't update existing records
                        }
                    })
                }
            }

            // Store fixed versions
            for (const { version } of classified.fixedVersions) {
                const packageVersion = await this.prisma.packageVersion.findUnique({
                    where: {
                        ecosystem_packageName_version: {
                            ecosystem,
                            packageName,
                            version
                        }
                    }
                })

                if (packageVersion) {
                    await this.prisma.packageVersionCVE.upsert({
                        where: {
                            packageVersionId_cveId_relationshipType: {
                                packageVersionId: packageVersion.uuid,
                                cveId,
                                relationshipType: 'fixed'
                            }
                        },
                        create: {
                            uuid: randomUUID(),
                            packageVersionId: packageVersion.uuid,
                            cveId,
                            relationshipType: 'fixed',
                            determinedBy: 'registry_inference',
                            confidence: 'medium',
                            versionRange: affectedRange,
                            createdAt: now
                        },
                        update: {
                            // Don't update existing records
                        }
                    })
                }
            }

            this.logger.info(`[RegistryVersionDiscovery] Stored ${classified.affectedVersions.length} affected and ${classified.fixedVersions.length} fixed relationships`)
        } catch (error: any) {
            this.logger.error(`[RegistryVersionDiscovery] Failed to store CVE relationships:`, error)
        }
    }

    /**
     * Get versions from database cache
     */
    private async getVersionsFromDatabase(
        ecosystem: PackageEcosystem,
        packageName: string
    ): Promise<{ versions: string[], lastVerifiedAt: number, source: string } | null> {
        try {
            const versions = await this.prisma.packageVersion.findMany({
                where: {
                    ecosystem,
                    packageName
                },
                select: {
                    version: true,
                    lastVerifiedAt: true,
                    discoveredFrom: true
                }
            })

            if (versions.length === 0) return null

            // Find most recent lastVerifiedAt
            const lastVerifiedAt = Math.max(...versions.map(v => v.lastVerifiedAt || 0))

            return {
                versions: versions.map(v => v.version).sort(versionSorter),
                lastVerifiedAt: lastVerifiedAt * 1000, // Convert to milliseconds
                source: versions[0].discoveredFrom
            }
        } catch (error: any) {
            this.logger.warn(`[RegistryVersionDiscovery] Database query failed:`, error.message)
            return null
        }
    }

    /**
     * Get registry source name for ecosystem
     */
    private getRegistrySource(ecosystem: PackageEcosystem): string {
        const sources: Record<PackageEcosystem, string> = {
            'npm': 'registry.npmjs.org',
            'pypi': 'pypi.org',
            'maven': 'search.maven.org',
            'rubygems': 'rubygems.org',
            'cargo': 'crates.io',
            'go': 'pkg.go.dev',
            'nuget': 'api.nuget.org',
            'generic': 'unknown'
        }

        return sources[ecosystem] || 'unknown'
    }

    /**
     * Clear memory cache
     */
    clearMemoryCache(): void {
        this.memoryCache.clear()
    }
}
