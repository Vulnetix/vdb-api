import type { PrismaClient } from '@prisma/client'

/**
 * Source preference order for CVE metadata
 */
const SOURCE_PREFERENCE = ['Anchore', 'Anchore ADP', 'Anchore-ADP', 'anchore_adp', 'CISA', 'CISA ADP', 'CISA-ADP', 'cisa_adp', 'CISA Vulnrichment', 'Vulnrichment', 'NVD', 'NIST-NVD', 'nist_nvd', 'OSV', 'OSV.dev', 'osv-org', 'GHSA', 'GitHub', 'github.com', 'Mitre', 'Mitre.org', 'mitre-org', 'CVE.org', 'cve-org', 'EUVD']

/**
 * Normalize source name to display-friendly format
 */
export const normalizeSourceName = (source: string): string => {
    if (!source) return 'Unknown'
    
    const lowerSource = source.toLowerCase()
    
    // Map common source identifiers to display names
    const sourceMap: Record<string, string> = {
        // NIST/NVD variants
        'nvd@nist.gov': 'NIST NVD',
        'nist-nvd': 'NIST NVD',
        'nist_nvd': 'NIST NVD',
        'nvd': 'NIST NVD',
        
        // Mitre/CVE.org variants
        'cve@mitre.org': 'MITRE',
        'mitre.org': 'MITRE',
        'mitre-org': 'MITRE',
        'mitre': 'MITRE',
        'cve.org': 'MITRE',
        'cve-org': 'MITRE',
        'af854a3a-2127-422b-91ae-364da2661108': 'MITRE',
        
        // CISA variants
        'cisa': 'CISA Vulnrichment',
        'cisa adp': 'CISA Vulnrichment',
        'cisa-adp': 'CISA Vulnrichment',
        'cisa_adp': 'CISA Vulnrichment',
        'cisa vulnrichment': 'CISA Vulnrichment',
        'vulnrichment': 'CISA Vulnrichment',
        
        // OSV variants
        'osv': 'OSV.dev',
        'osv.dev': 'OSV.dev',
        'osv-org': 'OSV.dev',
        
        // GitHub variants
        'ghsa': 'GitHub',
        'github': 'GitHub',
        'github.com': 'GitHub',
        
        // Anchore variants
        'anchore': 'Anchore',
        'anchore adp': 'Anchore',
        'anchore-adp': 'Anchore',
        'anchore_adp': 'Anchore',
        
        // Google OSI
        'google': 'Google OSI',
        'google_osi': 'Google OSI',
        'google-osi': 'Google OSI',
        'google_osint': 'Google OSI',
        'google-osint': 'Google OSI',

        // Other sources
        'euvd': 'EUVD',
        'vulnetix': 'Vulnetix',
        'vvd': 'Vulnetix',
        'cisa kev': 'CISA KEV',
        'epss': 'FIRST EPSS',
        'ess': 'Coalition ESS',
        'finding': 'Vulnetix'
    }

    // Check exact match first
    if (sourceMap[lowerSource]) {
        return sourceMap[lowerSource]
    }
    
    // Check partial matches
    for (const [key, displayName] of Object.entries(sourceMap)) {
        if (lowerSource.includes(key)) {
            return displayName
        }
    }
    
    // Return capitalized version of original if no mapping found
    return source.split(/[-_\s]/)
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join(' ')
}
/**
 * Get preference score for a source (higher is better)
 */
function getSourcePreference(source: string): number {
    const index = SOURCE_PREFERENCE.findIndex(s => source.toLowerCase().includes(s.toLowerCase()))
    return index >= 0 ? index : -1
}

/**
 * Compare two values and return the preferred one based on source
 */
function preferBySource(value1: any, source1: string, value2: any, source2: string): any {
    if (!value1) return value2
    if (!value2) return value1
    
    const pref1 = getSourcePreference(source1)
    const pref2 = getSourcePreference(source2)
    
    return pref2 > pref1 ? value2 : value1
}

/**
 * Merge CVE metadata from multiple sources with preference order
 * Preference: NVD > Anchore > OSV > CVE.org > EUVD > others
 * For descriptions: prefer longer
 * For lists: merge and deduplicate
 */
export async function mergeCVEMetadata(prisma: PrismaClient, cveId: string, logger?: any) {
    const normalizedCveId = cveId.trim().toUpperCase()
    
    // Fetch all sources for this CVE
    const primarySources = await prisma.cVEMetadata.findMany({
        where: { cveId: normalizedCveId },
        include: {
            cna: true,
            adp: { include: { adp: true } },
            references: true,
            problemTypes: true,
            metrics: true,
            affected: { include: { versions: true } },
            descriptions: true,
            impacts: { include: { descriptions: true } }
        }
    })

    // Follow aliases: load CVEMetadata for all related identifiers
    const aliasIds = new Set<string>()
    try {
        const aliasRelations = await prisma.cVEAlias.findMany({
            where: {
                OR: [
                    { primaryCveId: normalizedCveId },
                    { aliasCveId: normalizedCveId }
                ]
            },
            distinct: ['aliasCveId', 'primaryCveId']
        })

        for (const rel of aliasRelations) {
            if (rel.primaryCveId && rel.primaryCveId !== normalizedCveId) aliasIds.add(rel.primaryCveId.toUpperCase())
            if (rel.aliasCveId && rel.aliasCveId !== normalizedCveId) aliasIds.add(rel.aliasCveId.toUpperCase())
        }
    } catch (e) {
        logger?.warn(`Failed to query CVEAlias for ${normalizedCveId}:`, e)
    }

    // Load metadata for each alias
    const aliasSourcesArrays = await Promise.all(Array.from(aliasIds).map(aliasId => 
        prisma.cVEMetadata.findMany({
            where: { cveId: aliasId },
            include: {
                cna: true,
                adp: { include: { adp: true } },
                references: true,
                problemTypes: true,
                metrics: true,
                affected: { include: { versions: true } },
                descriptions: true,
                impacts: { include: { descriptions: true } }
            }
        })
    ))

    // Flatten arrays and combine with primary sources
    const allSources = [...primarySources, ...aliasSourcesArrays.flat()]
    
    if (!allSources || allSources.length === 0) {
        return null
    }
    
    // Initialize merged result with preferred sources
    const merged: any = {
        cveId: normalizedCveId,
        state: null,
        datePublished: null,
        dateUpdated: null,
        dateReserved: null,
        title: null,
        descriptions: [] as any[],
        cwes: [] as any[],
        metrics: [] as any[],
        affected: [] as any[],
        references: [] as any[],
        impacts: [] as any[],
        sources: [] as string[]
    }
    
    // Sort sources by preference (lower preference first, so we can overwrite)
    const sortedSources = [...allSources].sort((a, b) => 
        getSourcePreference(a.source) - getSourcePreference(b.source)
    )
    
    // Track all descriptions for length comparison
    const allDescriptions: Array<{ value: string, lang: string, source: string }> = []
    
    // Merge data from all sources
    for (const source of sortedSources) {
        merged.sources.push(source.source)
        
        // Merge simple fields using source preference
        merged.state = merged.state || source.state
        merged.datePublished = merged.datePublished || source.datePublished
        merged.dateUpdated = merged.dateUpdated || source.dateUpdated
        merged.dateReserved = merged.dateReserved || source.dateReserved
        
        // Title: prefer by source, then by length
        if (!merged.title && source.title) {
            merged.title = source.title
        } else if (source.title && source.title.length > (merged.title?.length || 0)) {
            merged.title = preferBySource(merged.title, merged.sources[0], source.title, source.source)
        }
        
        // Descriptions: collect all from CVEDescription table
        if (source.descriptions && source.descriptions.length > 0) {
            for (const desc of source.descriptions) {
                allDescriptions.push({
                    value: desc.value,
                    lang: desc.lang,
                    source: source.source
                })
            }
        }
        
        // Fallback: extract from rawDataJSON
        if (source.rawDataJSON) {
            try {
                const rawData = JSON.parse(source.rawDataJSON)
                const descriptions = rawData?.containers?.cna?.descriptions || rawData?.descriptions || []
                
                for (const desc of descriptions) {
                    if (desc.value || desc.description) {
                        allDescriptions.push({
                            value: desc.value || desc.description,
                            lang: desc.lang || 'en',
                            source: source.source
                        })
                    }
                }
            } catch (e) {
                logger?.warn(`Failed to parse rawDataJSON for descriptions from ${source.source}`)
            }
        }
        
        // CWEs/Problem Types: merge from all sources
        if (source.problemTypes && source.problemTypes.length > 0) {
            for (const pt of source.problemTypes) {
                merged.cwes.push({
                    cweId: pt.cweId,
                    description: pt.description,
                    descriptionType: pt.descriptionType,
                    containerType: pt.containerType,
                    adpOrgId: pt.adpOrgId,
                    source: source.source,
                    lang: pt.lang
                })
            }
        }
        
        // Metrics (CVSS): merge from all sources
        if (source.metrics && source.metrics.length > 0) {
            for (const metric of source.metrics) {
                merged.metrics.push({
                    source: source.source,
                    containerType: metric.containerType,
                    adpOrgId: metric.adpOrgId,
                    metricType: metric.metricType,
                    vectorString: metric.vectorString,
                    baseScore: metric.baseScore,
                    baseSeverity: metric.baseSeverity,
                    metricFormat: metric.metricFormat,
                    scenariosJSON: metric.scenariosJSON
                })
            }
        }
        
        // Fallback: extract CVSS from legacy fields
        if (source.vectorString && !merged.metrics.some((m: any) => m.vectorString === source.vectorString)) {
            const version = source.vectorString.match(/CVSS:(\d+\.\d+)/)?.[1]
            const metricType = version ? `cvssV${version.replace('.', '_')}` : 'other'
            
            merged.metrics.push({
                source: source.source,
                containerType: 'cna',
                metricType,
                vectorString: source.vectorString,
                baseScore: source.vectorString ? calculateBaseScore(source.vectorString) : null,
                baseSeverity: null
            })
        }
        
        // Affected products: merge from all sources
        if (source.affected && source.affected.length > 0) {
            for (const aff of source.affected) {
                merged.affected.push({
                    source: source.source,
                    containerType: aff.containerType,
                    vendor: aff.vendor,
                    product: aff.product,
                    collectionURL: aff.collectionURL,
                    packageName: aff.packageName,
                    cpes: aff.cpes ? JSON.parse(aff.cpes) : null,
                    modules: aff.modules ? JSON.parse(aff.modules) : null,
                    programFiles: aff.programFiles ? JSON.parse(aff.programFiles) : null,
                    programRoutines: aff.programRoutines ? JSON.parse(aff.programRoutines) : null,
                    platforms: aff.platforms ? JSON.parse(aff.platforms) : null,
                    repo: aff.repo,
                    defaultStatus: aff.defaultStatus,
                    versions: aff.versions.map(v => ({
                        version: v.version,
                        status: v.status,
                        versionType: v.versionType,
                        lessThan: v.lessThan,
                        lessThanOrEqual: v.lessThanOrEqual,
                        changes: v.changes ? JSON.parse(v.changes) : null
                    }))
                })
            }
        }
        
        // Fallback: extract affected from legacy fields
        if (source.affectedProduct && !merged.affected.some((a: any) => 
            a.product === source.affectedProduct && a.vendor === source.affectedVendor
        )) {
            merged.affected.push({
                source: source.source,
                containerType: 'cna',
                vendor: source.affectedVendor,
                product: source.affectedProduct,
                versions: source.affectedVersionsJSON ? JSON.parse(source.affectedVersionsJSON) : []
            })
        }
        
        // References: merge from all sources
        if (source.references && source.references.length > 0) {
            for (const ref of source.references) {
                merged.references.push({
                    url: ref.url,
                    title: ref.title,
                    type: ref.type,
                    source: ref.referenceSource
                })
            }
        }
        
        // Impacts: merge from all sources
        if (source.impacts && source.impacts.length > 0) {
            for (const impact of source.impacts) {
                merged.impacts.push({
                    source: source.source,
                    containerType: impact.containerType,
                    capecId: impact.capecId,
                    descriptions: impact.descriptions.map(d => ({
                        lang: d.lang,
                        value: d.value
                    }))
                })
            }
        }
    }
    
    // Process descriptions: group by language, prefer longer ones
    const descriptionsByLang = new Map<string, { value: string, source: string }>()
    
    for (const desc of allDescriptions) {
        const existing = descriptionsByLang.get(desc.lang)
        
        if (!existing) {
            descriptionsByLang.set(desc.lang, { value: desc.value, source: desc.source })
        } else {
            // Prefer longer description, or higher preference source
            if (desc.value.length > existing.value.length) {
                descriptionsByLang.set(desc.lang, { value: desc.value, source: desc.source })
            } else if (desc.value.length === existing.value.length) {
                // Same length, prefer by source
                const preferred = preferBySource(existing.value, existing.source, desc.value, desc.source)
                if (preferred === desc.value) {
                    descriptionsByLang.set(desc.lang, { value: desc.value, source: desc.source })
                }
            }
        }
    }
    
    // Convert descriptions map to array
    merged.descriptions = Array.from(descriptionsByLang.entries()).map(([lang, data]) => ({
        lang,
        value: data.value,
        source: data.source
    }))
    
    // Deduplicate CWEs by cweId
    const cweMap = new Map<string, any>()
    for (const cwe of merged.cwes) {
        if (cwe.cweId && !cweMap.has(cwe.cweId)) {
            cweMap.set(cwe.cweId, cwe)
        }
    }
    merged.cwes = Array.from(cweMap.values())
    
    // Deduplicate metrics by vectorString
    const metricsMap = new Map<string, any>()
    for (const metric of merged.metrics) {
        if (metric.vectorString) {
            const existing = metricsMap.get(metric.vectorString)
            if (!existing) {
                metricsMap.set(metric.vectorString, metric)
            } else {
                // Prefer by source
                const preferred = preferBySource(existing, existing.source, metric, metric.source)
                if (preferred === metric) {
                    metricsMap.set(metric.vectorString, metric)
                }
            }
        }
    }
    merged.metrics = Array.from(metricsMap.values())
    
    // Deduplicate references by URL
    const refMap = new Map<string, any>()
    for (const ref of merged.references) {
        if (!refMap.has(ref.url)) {
            refMap.set(ref.url, ref)
        }
    }
    merged.references = Array.from(refMap.values())
    
    return merged
}

/**
 * Calculate base score from CVSS vector string
 * This is a simplified version - you should use the actual CVSS calculation library
 */
function calculateBaseScore(vectorString: string): number | null {
    try {
        // Import CVSS calculators
        const { CVSS30, CVSS31, CVSS40 } = require('@pandatix/js-cvss')
        
        const version = vectorString.match(/CVSS:(\d+\.\d+)/)?.[1]
        
        if (version === '4.0') {
            const result = CVSS40.calculateCVSSFromVector(vectorString)
            return result?.baseScore || null
        } else if (version === '3.1') {
            const result = CVSS31.calculateCVSSFromVector(vectorString)
            return result?.baseScore || null
        } else if (version === '3.0') {
            const result = CVSS30.calculateCVSSFromVector(vectorString)
            return result?.baseScore || null
        }
    } catch (e) {
        // Failed to calculate score
    }
    
    return null
}
