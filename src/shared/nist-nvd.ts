/**
 * Stub for NIST NVD - External API disabled in database-only mode
 */

export class NistNVD {
    async query(...args: any[]): Promise<null> {
        console.warn('NIST NVD integration is disabled in database-only mode')
        return null
    }
}
