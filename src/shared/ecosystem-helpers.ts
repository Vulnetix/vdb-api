/**
 * Package Ecosystem Detection Helpers
 *
 * Utilities for detecting package ecosystems from CVE data and GitHub repositories,
 * generating Package URLs (PURLs), and managing dependency information.
 */

import type { PrismaClient } from '@prisma/client'
import { DepsDevClient, type DepsDevProjectPackageVersions, type DepsDevDependencies } from './deps-dev-client'

/**
 * Supported package ecosystems (lowercase as per Google OSI)
 * Maps to deps.dev system names: GO, RUBYGEMS, NPM, CARGO, MAVEN, PYPI, NUGET
 */
export type PackageEcosystem = 'go' | 'rubygems' | 'npm' | 'cargo' | 'maven' | 'pypi' | 'nuget' | 'generic'

/**
 * Map Google OSI system names (uppercase) to our lowercase ecosystem values
 */
const ECOSYSTEM_MAP: Record<string, PackageEcosystem> = {
    'GO': 'go',
    'RUBYGEMS': 'rubygems',
    'NPM': 'npm',
    'CARGO': 'cargo',
    'MAVEN': 'maven',
    'PYPI': 'pypi',
    'NUGET': 'nuget'
}

/**
 * Language to ecosystem mapping (heuristics)
 */
const LANGUAGE_TO_ECOSYSTEM: Record<string, PackageEcosystem> = {
    'go': 'go',
    'golang': 'go',
    'ruby': 'rubygems',
    'javascript': 'npm',
    'typescript': 'npm',
    'node': 'npm',
    'nodejs': 'npm',
    'rust': 'cargo',
    'java': 'maven',
    'kotlin': 'maven',
    'scala': 'maven',
    'python': 'pypi',
    'py': 'pypi',
    'csharp': 'nuget',
    'c#': 'nuget',
    'fsharp': 'nuget',
    'f#': 'nuget',
    'dotnet': 'nuget',
    '.net': 'nuget'
}

/**
 * File pattern to ecosystem mapping
 */
const FILE_PATTERN_TO_ECOSYSTEM: Record<string, PackageEcosystem> = {
    'package.json': 'npm',
    'package-lock.json': 'npm',
    'yarn.lock': 'npm',
    'Gemfile': 'rubygems',
    'Gemfile.lock': 'rubygems',
    'Cargo.toml': 'cargo',
    'Cargo.lock': 'cargo',
    'go.mod': 'go',
    'go.sum': 'go',
    'pom.xml': 'maven',
    'build.gradle': 'maven',
    'requirements.txt': 'pypi',
    'setup.py': 'pypi',
    'Pipfile': 'pypi',
    'pyproject.toml': 'pypi',
    '*.csproj': 'nuget',
    '*.fsproj': 'nuget',
    'packages.config': 'nuget'
}

export interface EcosystemDetectionResult {
    ecosystem: PackageEcosystem
    confidence: 'high' | 'medium' | 'low'
    source: 'cve-language' | 'cve-affected' | 'cve-references' | 'google-osi' | 'default'
    packageName?: string
    packageVersion?: string
}

/**
 * Detect ecosystem from CVE metadata language field
 */
const detectFromLanguage = (language: string | null): EcosystemDetectionResult | null => {
    if (!language) return null

    const normalizedLanguage = language.toLowerCase().trim()
    const ecosystem = LANGUAGE_TO_ECOSYSTEM[normalizedLanguage]

    if (ecosystem) {
        return {
            ecosystem,
            confidence: 'medium',
            source: 'cve-language'
        }
    }

    return null
}

/**
 * Detect ecosystem from CVE affected packages
 * Looks for package manager indicators in package names and versions
 */
const detectFromAffectedPackages = (affected: any[]): EcosystemDetectionResult | null => {
    if (!affected || affected.length === 0) return null

    // Check for package ecosystem in affected entries
    for (const entry of affected) {
        let detectedEcosystem: PackageEcosystem | null = null
        let confidence: 'high' | 'medium' | 'low' = 'medium'

        // Try to detect ecosystem from collectionURL (most reliable)
        if (entry.collectionURL) {
            const url = entry.collectionURL.toLowerCase()
            if (url.includes('npmjs.org') || url.includes('registry.npmjs')) {
                detectedEcosystem = 'npm'
                confidence = 'high'
            } else if (url.includes('pypi.org') || url.includes('pypi.python.org')) {
                detectedEcosystem = 'pypi'
                confidence = 'high'
            } else if (url.includes('maven.apache.org') || url.includes('maven.org')) {
                detectedEcosystem = 'maven'
                confidence = 'high'
            } else if (url.includes('crates.io')) {
                detectedEcosystem = 'cargo'
                confidence = 'high'
            } else if (url.includes('rubygems.org')) {
                detectedEcosystem = 'rubygems'
                confidence = 'high'
            } else if (url.includes('nuget.org')) {
                detectedEcosystem = 'nuget'
                confidence = 'high'
            } else if (url.includes('golang.org') || url.includes('pkg.go.dev')) {
                detectedEcosystem = 'go'
                confidence = 'high'
            }
        }

        // Get packageName from CVEAffected record (database field)
        const packageName = entry.packageName

        // If no ecosystem detected from collectionURL, try package name patterns
        if (!detectedEcosystem && packageName) {
            // Maven uses group:artifact format
            if (packageName.includes(':') && !packageName.includes('/')) {
                detectedEcosystem = 'maven'
                confidence = 'medium'
            }
            // Go uses domain/path format
            else if (packageName.includes('github.com/') || packageName.includes('golang.org/')) {
                detectedEcosystem = 'go'
                confidence = 'high'
            }
            // NPM scoped packages
            else if (packageName.startsWith('@') && packageName.includes('/')) {
                detectedEcosystem = 'npm'
                confidence = 'medium'
            }
        }

        // If we detected an ecosystem, extract version from CVEAffectedVersion records
        if (detectedEcosystem) {
            // Get first affected version from versions array
            const affectedVersion = entry.versions?.find((v: any) => v.status === 'affected')
            const packageVersion = affectedVersion?.version

            return {
                ecosystem: detectedEcosystem,
                confidence,
                source: 'cve-affected',
                packageName,
                packageVersion
            }
        }
    }

    return null
}

/**
 * Detect ecosystem from CVE references
 * Looks for package registry URLs in references
 */
const detectFromReferences = (references: any[]): EcosystemDetectionResult | null => {
    if (!references || references.length === 0) return null

    const registryPatterns: Record<string, PackageEcosystem> = {
        'npmjs.com': 'npm',
        'pypi.org': 'pypi',
        'rubygems.org': 'rubygems',
        'crates.io': 'cargo',
        'nuget.org': 'nuget',
        'mvnrepository.com': 'maven',
        'maven.org': 'maven',
        'pkg.go.dev': 'go'
    }

    for (const ref of references) {
        const url = ref.url || ref.reference
        if (!url) continue

        for (const [pattern, ecosystem] of Object.entries(registryPatterns)) {
            if (url.includes(pattern)) {
                return {
                    ecosystem,
                    confidence: 'high',
                    source: 'cve-references'
                }
            }
        }
    }

    return null
}

/**
 * Detect ecosystem from CVE metadata
 * Tries multiple strategies in order of confidence
 */
export const detectEcosystemFromCVEData = async (
    cveId: string,
    prisma: PrismaClient,
    logger?: any
): Promise<EcosystemDetectionResult | null> => {
    const log = logger || console

    try {
        log.debug(`[EcosystemHelpers] Detecting ecosystem from CVE metadata for ${cveId}`)

        // Fetch CVE metadata with affected versions
        const cveMetadata = await prisma.cVEMetadata.findMany({
            where: { cveId },
            include: {
                references: true,
                affected: {
                    include: {
                        versions: true  // Include CVEAffectedVersion records
                    }
                }
            }
        })

        if (cveMetadata.length === 0) {
            log.debug(`[EcosystemHelpers] No CVE metadata found for ${cveId}`)
            return null
        }

        // Try detection from affected packages first (highest confidence)
        for (const metadata of cveMetadata) {
            if (metadata.affected && metadata.affected.length > 0) {
                const result = detectFromAffectedPackages(metadata.affected)
                if (result) {
                    log.info(`[EcosystemHelpers] Detected ecosystem from affected packages: ${result.ecosystem}`)
                    return result
                }
            }
        }

        // Try detection from references (high confidence)
        for (const metadata of cveMetadata) {
            if (metadata.references && metadata.references.length > 0) {
                const result = detectFromReferences(metadata.references)
                if (result) {
                    log.info(`[EcosystemHelpers] Detected ecosystem from references: ${result.ecosystem}`)
                    return result
                }
            }
        }

        // Try detection from language field (medium confidence)
        for (const metadata of cveMetadata) {
            if (metadata.language) {
                const result = detectFromLanguage(metadata.language)
                if (result) {
                    log.info(`[EcosystemHelpers] Detected ecosystem from language: ${result.ecosystem}`)
                    return result
                }
            }
        }

        log.debug(`[EcosystemHelpers] Could not detect ecosystem from CVE metadata for ${cveId}`)
        return null
    } catch (error) {
        log.error(`[EcosystemHelpers] Error detecting ecosystem from CVE metadata:`, error)
        return null
    }
}

/**
 * Detect ecosystem using Google OSI API
 * Queries the :packageversions endpoint to see which ecosystems have published packages
 */
export const detectEcosystemFromGoogleOSI = async (
    repoFullName: string,
    logger?: any
): Promise<EcosystemDetectionResult | null> => {
    const log = logger || console

    try {
        log.debug(`[EcosystemHelpers] Detecting ecosystem via Google OSI for ${repoFullName}`)

        const depsDevClient = new DepsDevClient({ logger: log })
        const packageVersions = await depsDevClient.getProjectPackageVersions(repoFullName)

        if (!packageVersions || !packageVersions.versions || packageVersions.versions.length === 0) {
            log.debug(`[EcosystemHelpers] No package versions found via Google OSI for ${repoFullName}`)
            return null
        }

        // Get the most common ecosystem (in case multiple exist)
        const ecosystemCounts: Record<string, number> = {}
        let primaryPackage = packageVersions.versions[0]

        for (const version of packageVersions.versions) {
            const system = version.versionKey.system
            ecosystemCounts[system] = (ecosystemCounts[system] || 0) + 1
        }

        // Find the ecosystem with the most versions
        const primarySystem = Object.entries(ecosystemCounts)
            .sort(([, a], [, b]) => b - a)[0][0]

        // Get a package from the primary ecosystem
        primaryPackage = packageVersions.versions.find(v => v.versionKey.system === primarySystem) || primaryPackage

        const ecosystem = ECOSYSTEM_MAP[primarySystem] || 'generic'

        log.info(`[EcosystemHelpers] Detected ecosystem via Google OSI: ${ecosystem}`, {
            system: primarySystem,
            packageName: primaryPackage.versionKey.name,
            totalVersions: packageVersions.versions.length
        })

        return {
            ecosystem,
            confidence: 'high',
            source: 'google-osi',
            packageName: primaryPackage.versionKey.name,
            packageVersion: primaryPackage.versionKey.version
        }
    } catch (error) {
        log.error(`[EcosystemHelpers] Error detecting ecosystem via Google OSI:`, error)
        return null
    }
}

/**
 * Generate Package URL (PURL) from ecosystem and repository info
 * Spec: https://github.com/package-url/purl-spec
 *
 * Format: pkg:<ecosystem>/<namespace>/<name>@<version>
 */
export const generatePURL = (
    ecosystem: PackageEcosystem,
    packageName: string,
    packageVersion?: string,
    namespace?: string
): string => {
    let purl = `pkg:${ecosystem}`

    if (namespace) {
        purl += `/${encodeURIComponent(namespace)}`
    }

    purl += `/${encodeURIComponent(packageName)}`

    if (packageVersion) {
        purl += `@${encodeURIComponent(packageVersion)}`
    }

    return purl
}

/**
 * Generate PURL from GitHub repository and detection result
 */
export const generatePURLFromRepo = (
    repoFullName: string,
    detectionResult: EcosystemDetectionResult
): string => {
    const [owner, repo] = repoFullName.split('/')

    // If we have package name from detection, use it
    if (detectionResult.packageName) {
        // For Maven, package name is already in group:artifact format
        if (detectionResult.ecosystem === 'maven') {
            const [group, artifact] = detectionResult.packageName.split(':')
            return generatePURL(
                detectionResult.ecosystem,
                artifact || detectionResult.packageName,
                detectionResult.packageVersion,
                group
            )
        }

        // For Go, use the full import path
        if (detectionResult.ecosystem === 'go') {
            return generatePURL(
                detectionResult.ecosystem,
                detectionResult.packageName,
                detectionResult.packageVersion
            )
        }

        // For other ecosystems, use package name directly
        return generatePURL(
            detectionResult.ecosystem,
            detectionResult.packageName,
            detectionResult.packageVersion
        )
    }

    // Fallback: use repository name as package name
    // For generic ecosystem, use github.com namespace
    if (detectionResult.ecosystem === 'generic') {
        return `pkg:generic/github.com/${owner}/${repo}`
    }

    // For specific ecosystems, use namespace if applicable
    const namespace = detectionResult.ecosystem === 'maven' ? owner : undefined
    return generatePURL(detectionResult.ecosystem, repo, undefined, namespace)
}

/**
 * Store dependencies from Google OSI in the database
 */
export const storeDependencies = async (
    githubRepositoryId: number,
    ecosystem: PackageEcosystem,
    packageName: string,
    packageVersion: string,
    prisma: PrismaClient,
    logger?: any
): Promise<number> => {
    const log = logger || console

    try {
        log.debug(`[EcosystemHelpers] Fetching dependencies for ${ecosystem}:${packageName}@${packageVersion}`)

        // First, fetch the repository
        const repository = await prisma.gitHubRepository.findUnique({
            where: { id: githubRepositoryId }
        })

        if (!repository) {
            log.error(`[EcosystemHelpers] Repository ${githubRepositoryId} not found`)
            return 0
        }

        // TODO: The current schema doesn't have org association for external CVE reference repositories
        // For now, we'll skip dependency storage for repositories without org context
        // This is expected behavior for external reference repositories discovered via CVE data
        log.warn(`[EcosystemHelpers] Skipping dependency storage for repository ${githubRepositoryId} - no organization context in current schema (external reference repository)`)
        return 0

        const depsDevClient = new DepsDevClient({ logger: log })
        const dependencies = await depsDevClient.getPackageDependencies(ecosystem, packageName, packageVersion)

        if (!dependencies || !dependencies.nodes || dependencies.nodes.length === 0) {
            log.debug(`[EcosystemHelpers] No dependencies found for ${ecosystem}:${packageName}@${packageVersion}`)
            return 0
        }

        log.info(`[EcosystemHelpers] Processing ${dependencies.nodes.length} dependency nodes`)

        let storedCount = 0
        const timestamp = Math.floor(Date.now() / 1000)

        // Store each dependency
        for (const node of dependencies.nodes) {
            // Skip SELF node (the package itself)
            if (node.relation === 'SELF') continue

            try {
                // Ensure the Dependency record exists
                const depEcosystem = ECOSYSTEM_MAP[node.versionKey.system] || 'generic'
                const dependencyKey = `${depEcosystem.toUpperCase()}:${node.versionKey.name}:${node.versionKey.version}`

                await prisma.dependency.upsert({
                    where: {
                        key: dependencyKey
                    },
                    create: {
                        key: dependencyKey,
                        packageEcosystem: depEcosystem,
                        name: node.versionKey.name,
                        version: node.versionKey.version
                    },
                    update: {}
                })

                // Map relation to dependency type flags
                const isDirect = node.relation === 'DIRECT' ? 1 : 0
                const isIndirect = node.relation === 'INDIRECT' ? 1 : 0
                const isTransitive = node.relation === 'TRANSITIVE' ? 1 : 0

                // Create the GitHubRepoDependency junction record
                await prisma.gitHubRepoDependency.upsert({
                    where: {
                        repo_dependency_source_unique: {
                            githubRepositoryId,
                            dependencyKey,
                            source: 'deps-dev'
                        }
                    },
                    create: {
                        githubRepositoryId,
                        orgId,
                        dependencyKey,
                        source: 'deps-dev',
                        detectedAt: timestamp,
                        version: node.versionKey.version,
                        isDirect,
                        isIndirect,
                        isTransitive,
                        isDev: 0,
                        createdAt: timestamp,
                        updatedAt: timestamp
                    },
                    update: {
                        detectedAt: timestamp,
                        version: node.versionKey.version,
                        isDirect,
                        isIndirect,
                        isTransitive,
                        updatedAt: timestamp
                    }
                })

                storedCount++
            } catch (error) {
                log.error(`[EcosystemHelpers] Error storing dependency ${node.versionKey.name}:`, error)
            }
        }

        log.info(`[EcosystemHelpers] Stored ${storedCount} dependencies for repository ${githubRepositoryId}`)
        return storedCount
    } catch (error) {
        log.error(`[EcosystemHelpers] Error storing dependencies:`, error)
        return 0
    }
}
