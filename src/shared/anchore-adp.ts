/**
 * Stub for Anchore ADP - External API disabled in database-only mode
 */

export class AnchoreADP {
    async query(...args: any[]): Promise<null> {
        console.warn('Anchore ADP integration is disabled in database-only mode')
        return null
    }
}

export function parseAnchoreAdpToCVE(data: any, cveId: string): any {
    return null
}
