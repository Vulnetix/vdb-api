/**
 * Deep Merge Utilities for CVEMetadata Sources
 *
 * Provides reusable deep merge functions for combining CVE metadata from multiple sources
 * while preserving distinct values and applying intelligent merge strategies.
 */

export interface DeepMergeOptions {
    arrayMergeStrategy?: 'concat' | 'deduplicate' | 'replace'
    arrayDedupeKey?: string | ((item: any) => string)
    sourcePreferences?: Record<string, number>
    preferredSourceName?: string
}

/**
 * Merge two arrays with optional deduplication
 * @param baseArray - Base array (preferred items come first)
 * @param incomingArray - Incoming array to merge
 * @param dedupeKey - Key to use for deduplication, or function to generate key
 * @returns Merged array with duplicates removed
 */
export function mergeArrays<T = any>(
    baseArray: T[] | null | undefined,
    incomingArray: T[] | null | undefined,
    dedupeKey?: string | ((item: T) => string)
): T[] {
    const base = baseArray || []
    const incoming = incomingArray || []

    if (!dedupeKey) {
        // No deduplication, just concat
        return [...base, ...incoming]
    }

    // Build deduplication key function
    const getKey = typeof dedupeKey === 'function'
        ? dedupeKey
        : (item: T) => {
            if (typeof item === 'object' && item !== null && dedupeKey in item) {
                return String((item as any)[dedupeKey])
            }
            return String(item)
        }

    // Track seen keys
    const seen = new Set<string>()
    const result: T[] = []

    // Add base items first (preserves order and preference)
    for (const item of base) {
        const key = getKey(item)
        if (!seen.has(key)) {
            seen.add(key)
            result.push(item)
        }
    }

    // Add incoming items if not duplicate
    for (const item of incoming) {
        const key = getKey(item)
        if (!seen.has(key)) {
            seen.add(key)
            result.push(item)
        }
    }

    return result
}

/**
 * Select the preferred value between two values based on field-specific logic
 * @param baseValue - Value from base source
 * @param incomingValue - Value from incoming source
 * @param fieldName - Name of the field being merged
 * @param baseSourcePref - Source preference score for base (higher is better)
 * @param incomingSourcePref - Source preference score for incoming (higher is better)
 * @returns Preferred value
 */
export function selectPreferredValue<T = any>(
    baseValue: T,
    incomingValue: T,
    fieldName: string,
    baseSourcePref: number = 0,
    incomingSourcePref: number = 0
): T {
    // Rule 1: Prefer non-null values
    if (baseValue == null && incomingValue != null) return incomingValue
    if (incomingValue == null && baseValue != null) return baseValue
    if (baseValue == null && incomingValue == null) return baseValue

    // Rule 2: Date handling
    if (fieldName === 'dateUpdated' || fieldName === 'lastFetchedAt') {
        // Prefer latest (highest timestamp)
        return (baseValue as any) > (incomingValue as any) ? baseValue : incomingValue
    }

    if (fieldName === 'datePublished' || fieldName === 'dateReserved') {
        // Prefer earliest (lowest timestamp)
        return (baseValue as any) < (incomingValue as any) ? baseValue : incomingValue
    }

    // Rule 3: Numeric preference (higher is better)
    if (fieldName === 'score' || fieldName === 'fetchCount') {
        return (baseValue as any) > (incomingValue as any) ? baseValue : incomingValue
    }

    // Rule 4: String preference (longer is better for title/description)
    if (fieldName === 'title' || fieldName === 'description') {
        if (typeof baseValue === 'string' && typeof incomingValue === 'string') {
            return baseValue.length >= incomingValue.length ? baseValue : incomingValue
        }
    }

    // Rule 5: Source preference tiebreaker
    // Higher preference score wins
    if (baseSourcePref > incomingSourcePref) return baseValue
    if (incomingSourcePref > baseSourcePref) return incomingValue

    // Default: Keep base value
    return baseValue
}

/**
 * Deep merge two objects recursively
 * @param base - Base object (preferred in conflicts)
 * @param incoming - Incoming object to merge
 * @param options - Merge options
 * @returns Deeply merged object
 */
export function deepMergeObjects<T = any>(
    base: T | null | undefined,
    incoming: T | null | undefined,
    options: DeepMergeOptions = {}
): T {
    // Handle null/undefined cases
    if (!base && !incoming) return {} as T
    if (!base) return incoming as T
    if (!incoming) return base as T

    // If either is not an object, return preferred value
    if (typeof base !== 'object' || typeof incoming !== 'object') {
        const basePref = options.sourcePreferences?.[options.preferredSourceName || ''] || 0
        return selectPreferredValue(base, incoming, '', basePref, 0)
    }

    // Handle arrays specially
    if (Array.isArray(base) || Array.isArray(incoming)) {
        const baseArr = Array.isArray(base) ? base : [base]
        const incomingArr = Array.isArray(incoming) ? incoming : [incoming]

        const strategy = options.arrayMergeStrategy || 'deduplicate'

        if (strategy === 'replace') {
            return incoming as T
        }

        if (strategy === 'concat') {
            return [...baseArr, ...incomingArr] as T
        }

        // Default: deduplicate
        return mergeArrays(baseArr, incomingArr, options.arrayDedupeKey) as T
    }

    // Deep merge objects
    const result = { ...base } as any
    const basePref = options.sourcePreferences?.[options.preferredSourceName || ''] || 0

    for (const key in incoming) {
        if (!incoming.hasOwnProperty(key)) continue

        const incomingValue = (incoming as any)[key]
        const baseValue = result[key]

        // If base doesn't have this key, just add it
        if (!(key in result)) {
            result[key] = incomingValue
            continue
        }

        // Both have the key - decide how to merge
        if (typeof baseValue === 'object' && typeof incomingValue === 'object') {
            // Recursively merge objects/arrays
            result[key] = deepMergeObjects(baseValue, incomingValue, options)
        } else {
            // Use field-specific logic for scalars
            result[key] = selectPreferredValue(baseValue, incomingValue, key, basePref, 0)
        }
    }

    return result as T
}

/**
 * Deep merge rawDataJSON strings by parsing, merging, and re-stringifying
 * Applies specialized deduplication for known CVE data structures
 * @param baseJSON - Base JSON string
 * @param incomingJSON - Incoming JSON string
 * @returns Merged JSON string
 */
export function deepMergeRawDataJSON(
    baseJSON: string | null | undefined,
    incomingJSON: string | null | undefined
): string | null {
    if (!baseJSON && !incomingJSON) return null
    if (!baseJSON) return incomingJSON || null
    if (!incomingJSON) return baseJSON

    try {
        const baseParsed = JSON.parse(baseJSON)
        const incomingParsed = JSON.parse(incomingJSON)

        // Merge with specialized array handling for known CVE structures
        const merged = deepMergeObjects(baseParsed, incomingParsed, {
            arrayMergeStrategy: 'deduplicate'
        })

        // Apply specialized deduplication for known arrays
        if (merged.descriptions && Array.isArray(merged.descriptions)) {
            // Deduplicate descriptions by language, prefer longer
            const descByLang = new Map<string, any>()
            for (const desc of merged.descriptions) {
                const lang = desc.lang || desc.language || 'en'
                const existing = descByLang.get(lang)
                if (!existing || (desc.value?.length || 0) > (existing.value?.length || 0)) {
                    descByLang.set(lang, desc)
                }
            }
            merged.descriptions = Array.from(descByLang.values())
        }

        if (merged.metrics && Array.isArray(merged.metrics)) {
            // Deduplicate metrics by vectorString
            merged.metrics = mergeArrays(merged.metrics, [], 'vectorString')
        }

        if (merged.references && Array.isArray(merged.references)) {
            // Deduplicate references by url
            merged.references = mergeArrays(merged.references, [], 'url')
        }

        if (merged.cwes && Array.isArray(merged.cwes)) {
            // Deduplicate CWEs by cweId
            merged.cwes = mergeArrays(merged.cwes, [], 'cweId')
        }

        if (merged.affected && Array.isArray(merged.affected)) {
            // Deduplicate affected by vendor:product:repo combination
            merged.affected = mergeArrays(merged.affected, [], (item: any) => {
                const vendor = item.vendor || ''
                const product = item.product || ''
                const repo = item.repo || ''
                return `${vendor}:${product}:${repo}`
            })
        }

        if (merged.impacts && Array.isArray(merged.impacts)) {
            // Deduplicate impacts by capecId
            merged.impacts = mergeArrays(merged.impacts, [], 'capecId')
        }

        if (merged.sources && Array.isArray(merged.sources)) {
            // Deduplicate sources array (list of contributing source names)
            merged.sources = [...new Set(merged.sources)]
        }

        if (merged.aliases && Array.isArray(merged.aliases)) {
            // Deduplicate aliases
            merged.aliases = [...new Set(merged.aliases.map(a => a.toUpperCase()))]
        }

        if (merged.computedAliases && Array.isArray(merged.computedAliases)) {
            // Deduplicate computed aliases
            merged.computedAliases = [...new Set(merged.computedAliases.map(a => a.toUpperCase()))]
        }

        return JSON.stringify(merged)
    } catch (e) {
        // Parse error - return base
        return baseJSON
    }
}
