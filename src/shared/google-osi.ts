/**
 * Stub for Google OSI - External API disabled in database-only mode
 */

export class GoogleOsi {
    async query(...args: any[]): Promise<null> {
        console.warn('Google OSI integration is disabled in database-only mode')
        return null
    }
}

export function parseGoogleOsiToCVE(data: any, identifier: string, baseCVE?: any): any {
    return null
}
