/**
 * Stub file for finding.ts - not used in API-only mode
 */

export function latestTriage(triages: any[]): any | null {
    if (!triages || triages.length === 0) return null
    return triages[0]
}
