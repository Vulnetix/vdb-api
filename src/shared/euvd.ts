/**
 * Stub for EUVD - External API disabled in database-only mode
 */

export class EUVD {
    async query(...args: any[]): Promise<null> {
        console.warn('EUVD integration is disabled in database-only mode')
        return null
    }
}

export function parseEUVDToCVE(data: any, identifier: string, useCveId?: boolean): any {
    return null
}
