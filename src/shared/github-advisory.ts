/**
 * Stub for GitHub Advisory - External API disabled in database-only mode
 */

export class GitHubAdvisory {
    async query(...args: any[]): Promise<null> {
        console.warn('GitHub Advisory integration is disabled in database-only mode')
        return null
    }
}

export function parseGitHubAdvisoryToCVE(data: any, identifier: string): any {
    return null
}
