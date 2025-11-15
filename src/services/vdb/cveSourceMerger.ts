/**
 * CVE Metadata Source Merger
 *
 * Provides specialized merge logic for CVEMetadata source objects,
 * handling deduplication of sources with the same normalized name.
 */

import { deepMergeObjects, mergeArrays, selectPreferredValue, deepMergeRawDataJSON } from '@/shared/deep-merger'

/**
 * Source preference order (from cveMetadataMerger.ts)
 * Higher index = higher preference
 */
const SOURCE_PREFERENCE = [
    'Anchore', 'Anchore ADP', 'Anchore-ADP', 'anchore_adp',
    'CISA', 'CISA ADP', 'CISA-ADP', 'cisa_adp', 'CISA Vulnrichment', 'Vulnrichment',
    'NVD', 'NIST-NVD', 'nist_nvd', 'NIST NVD',
    'OSV', 'OSV.dev', 'osv-org',
    'GHSA', 'GitHub', 'github.com',
    'Mitre', 'Mitre.org', 'mitre-org', 'CVE.org', 'cve-org',
    'EUVD',
    'Vulnetix', 'vulnetix', 'vvd', 'VVD'  // Vulnetix variants
]

/**
 * Get source preference score (higher is better)
 * @param sourceName - Source name (normalized or raw)
 * @returns Preference score (0-based index, -1 if not found)
 */
export function getSourcePreference(sourceName: string): number {
    if (!sourceName) return -1

    const index = SOURCE_PREFERENCE.findIndex(s =>
        sourceName.toLowerCase().includes(s.toLowerCase()) ||
        s.toLowerCase().includes(sourceName.toLowerCase())
    )

    return index >= 0 ? index : -1
}

/**
 * Merge two CVEMetadata source objects into one
 * Applies intelligent field-level merging and tracks contributing cveIds
 *
 * @param baseSrc - Base source object (typically higher preference)
 * @param incomingSrc - Incoming source to merge
 * @returns Merged source object
 */
export function mergeCVEMetadataSources(
    baseSrc: any,
    incomingSrc: any
): any {
    if (!baseSrc) return incomingSrc
    if (!incomingSrc) return baseSrc

    const baseSourcePref = getSourcePreference(baseSrc.source)
    const incomingSourcePref = getSourcePreference(incomingSrc.source)

    // Determine which source is preferred (higher preference score)
    const preferredSrc = baseSourcePref >= incomingSourcePref ? baseSrc : incomingSrc
    const otherSrc = baseSourcePref >= incomingSourcePref ? incomingSrc : baseSrc

    // Track contributing cveIds
    const baseCveIds = baseSrc.cveIds || [baseSrc.cveId]
    const incomingCveIds = incomingSrc.cveIds || [incomingSrc.cveId]
    const allCveIds = [...new Set([...baseCveIds, ...incomingCveIds])].filter(Boolean)

    // Build merged source
    const merged: any = {
        // Keep the normalized source name (should be same, but use preferred)
        source: preferredSrc.source,

        // Track all contributing CVE IDs
        cveIds: allCveIds,

        // Use primary cveId as the main identifier (first from preferred source)
        cveId: preferredSrc.cveId,

        // Merge scalar fields with preference logic
        dataVersion: selectPreferredValue(baseSrc.dataVersion, incomingSrc.dataVersion, 'dataVersion', baseSourcePref, incomingSourcePref),
        state: selectPreferredValue(baseSrc.state, incomingSrc.state, 'state', baseSourcePref, incomingSourcePref),

        // Date fields: earliest for published/reserved, latest for updated
        datePublished: selectPreferredValue(baseSrc.datePublished, incomingSrc.datePublished, 'datePublished', baseSourcePref, incomingSourcePref),
        dateUpdated: selectPreferredValue(baseSrc.dateUpdated, incomingSrc.dateUpdated, 'dateUpdated', baseSourcePref, incomingSourcePref),
        dateReserved: selectPreferredValue(baseSrc.dateReserved, incomingSrc.dateReserved, 'dateReserved', baseSourcePref, incomingSourcePref),

        // CVSS fields: prefer highest score
        vectorString: selectPreferredValue(baseSrc.vectorString, incomingSrc.vectorString, 'vectorString', baseSourcePref, incomingSourcePref),
        cvssVersion: selectPreferredValue(baseSrc.cvssVersion, incomingSrc.cvssVersion, 'cvssVersion', baseSourcePref, incomingSourcePref),
        score: selectPreferredValue(baseSrc.score, incomingSrc.score, 'score', baseSourcePref, incomingSourcePref),

        // Text fields: prefer longer or from higher preference source
        title: selectPreferredValue(baseSrc.title, incomingSrc.title, 'title', baseSourcePref, incomingSourcePref),
        sourceAdvisoryRef: selectPreferredValue(baseSrc.sourceAdvisoryRef, incomingSrc.sourceAdvisoryRef, 'sourceAdvisoryRef', baseSourcePref, incomingSourcePref),

        // Affected fields
        affectedVendor: selectPreferredValue(baseSrc.affectedVendor, incomingSrc.affectedVendor, 'affectedVendor', baseSourcePref, incomingSourcePref),
        affectedProduct: selectPreferredValue(baseSrc.affectedProduct, incomingSrc.affectedProduct, 'affectedProduct', baseSourcePref, incomingSourcePref),

        // Metadata fields: prefer latest/highest
        lastFetchedAt: selectPreferredValue(baseSrc.lastFetchedAt, incomingSrc.lastFetchedAt, 'lastFetchedAt', baseSourcePref, incomingSourcePref),
        fetchCount: selectPreferredValue(baseSrc.fetchCount, incomingSrc.fetchCount, 'fetchCount', baseSourcePref, incomingSourcePref),
    }

    // Merge array fields with deduplication
    merged.affectedVersions = mergeArrays(
        baseSrc.affectedVersions,
        incomingSrc.affectedVersions,
        (item: any) => {
            // Deduplicate by version string or range
            return `${item.version || ''}:${item.lessThan || ''}:${item.status || ''}`
        }
    )

    merged.cpes = mergeArrays(
        baseSrc.cpes,
        incomingSrc.cpes,
        (item: any) => {
            // CPE strings are unique identifiers
            return typeof item === 'string' ? item : item.cpe || JSON.stringify(item)
        }
    )

    merged.adp = mergeArrays(
        baseSrc.adp,
        incomingSrc.adp,
        (item: any) => item.shortName
    )

    // Merge object fields: prefer from higher preference source, or merge if both exist
    if (baseSrc.cna || incomingSrc.cna) {
        // Prefer CNA from higher preference source
        merged.cna = baseSourcePref >= incomingSourcePref
            ? (baseSrc.cna || incomingSrc.cna)
            : (incomingSrc.cna || baseSrc.cna)
    } else {
        merged.cna = null
    }

    if (baseSrc.fileLink || incomingSrc.fileLink) {
        // Prefer fileLink from higher preference source
        merged.fileLink = baseSourcePref >= incomingSourcePref
            ? (baseSrc.fileLink || incomingSrc.fileLink)
            : (incomingSrc.fileLink || baseSrc.fileLink)
    } else {
        merged.fileLink = null
    }

    // Deep merge rawDataJSON
    merged.rawDataJSON = deepMergeRawDataJSON(baseSrc.rawDataJSON, incomingSrc.rawDataJSON)

    return merged
}

/**
 * Deduplicate an array of CVE sources by normalized source name
 * Groups sources by name and merges each group into a single source
 *
 * @param sources - Array of source objects
 * @returns Deduplicated array of sources
 */
export function deduplicateCVESources(sources: any[]): any[] {
    if (!sources || sources.length === 0) return []

    // Group sources by normalized source name
    const sourceGroups = new Map<string, any[]>()

    for (const source of sources) {
        const sourceName = source.source || 'Unknown'
        const group = sourceGroups.get(sourceName) || []
        group.push(source)
        sourceGroups.set(sourceName, group)
    }

    // Merge each group
    const deduplicated: any[] = []

    for (const [sourceName, group] of sourceGroups.entries()) {
        if (group.length === 1) {
            // No duplicates, keep as-is
            deduplicated.push(group[0])
        } else {
            // Multiple sources with same name - merge them
            // Sort by preference first (highest preference first)
            const sorted = group.sort((a, b) => {
                const prefA = getSourcePreference(a.source)
                const prefB = getSourcePreference(b.source)
                return prefB - prefA
            })

            // Merge all sources in the group
            let merged = sorted[0]
            for (let i = 1; i < sorted.length; i++) {
                merged = mergeCVEMetadataSources(merged, sorted[i])
            }

            deduplicated.push(merged)
        }
    }

    // Sort deduplicated sources by preference (highest first)
    deduplicated.sort((a, b) => {
        const prefA = getSourcePreference(a.source)
        const prefB = getSourcePreference(b.source)
        return prefB - prefA
    })

    return deduplicated
}
