// URL Categorization for CVE References
// This module categorizes URLs commonly found in CVE references and extracts relevant data

export interface URLCategory {
    type: 'advisory' | 'exploit' | 'fix' | 'poc' | 'discussion' | 'vendor' | 'research' | 'documentation' | 'database' | 'sighting' | 'unknown';
    confidence: number; // 0-100, how confident we are in the categorization
    subcategory?: string;
    extractedData?: Record<string, any>;
    description?: string;
}

export interface CategorizedURL {
    url: string;
    category: URLCategory;
    domain: string;
    path: string;
}

// Domain-based categorization patterns
const DOMAIN_PATTERNS = {
    // Security Advisories & Official Sources
    'nvd.nist.gov': {
        type: 'database' as const,
        confidence: 95,
        subcategory: 'nvd',
        description: 'National Vulnerability Database',
        extractors: ['cveId', 'nvdId']
    },
    'cve.mitre.org': {
        type: 'database' as const,
        confidence: 95,
        subcategory: 'mitre',
        description: 'MITRE CVE Database',
        extractors: ['cveId']
    },
    'cisa.gov': {
        type: 'advisory' as const,
        confidence: 90,
        subcategory: 'cisa',
        description: 'CISA Security Advisory',
        extractors: ['advisoryId']
    },
    'cert.org': {
        type: 'advisory' as const,
        confidence: 85,
        subcategory: 'cert',
        description: 'CERT Advisory',
        extractors: ['certId']
    },
    'security.snyk.io': {
        type: 'database' as const,
        confidence: 90,
        subcategory: 'snyk',
        description: 'Snyk Vulnerability Database',
        extractors: ['snykId', 'packageName']
    },
    'snyk.io': {
        type: 'database' as const,
        confidence: 85,
        subcategory: 'snyk',
        description: 'Snyk Security',
        extractors: ['snykId', 'packageName']
    },
    'vuldb.com': {
        type: 'database' as const,
        confidence: 90,
        subcategory: 'vuldb',
        description: 'VulDB Database',
        extractors: ['vulnDbId']
    },
    'zerodayinitiative.com': {
        type: 'advisory' as const,
        confidence: 90,
        subcategory: 'zdi',
        description: 'Zero Day Initiative Advisory',
        extractors: ['zdiId']
    },
    
    // Exploit Databases & PoCs
    'exploit-db.com': {
        type: 'exploit' as const,
        confidence: 95,
        subcategory: 'exploit-db',
        description: 'Exploit Database',
        extractors: ['exploitId']
    },
    'packetstormsecurity.com': {
        type: 'exploit' as const,
        confidence: 90,
        subcategory: 'packetstorm',
        description: 'Packet Storm Security',
        extractors: ['packetStormId']
    },
    'vulnerability-lab.com': {
        type: 'exploit' as const,
        confidence: 90,
        subcategory: 'vulnerability-lab',
        description: 'Vulnerability Lab Database',
        extractors: ['vlId']
    },
    'seclists.org': {
        type: 'discussion' as const,
        confidence: 80,
        subcategory: 'seclists',
        description: 'Security Mailing Lists',
        extractors: ['mailingList', 'messageId']
    },
    
    // Code Repositories & Fixes
    'github.com': {
        type: 'unknown' as const, // Will be refined by path analysis
        confidence: 70,
        subcategory: 'github',
        description: 'GitHub Repository',
        extractors: ['repoOwner', 'repoName', 'commitHash', 'issueNumber', 'prNumber']
    },
    'gitlab.com': {
        type: 'unknown' as const,
        confidence: 70,
        subcategory: 'gitlab',
        description: 'GitLab Repository',
        extractors: ['repoOwner', 'repoName', 'commitHash', 'issueNumber', 'prNumber']
    },
    'bitbucket.org': {
        type: 'unknown' as const,
        confidence: 70,
        subcategory: 'bitbucket',
        description: 'Bitbucket Repository',
        extractors: ['repoOwner', 'repoName', 'commitHash']
    },
    
    // Vendor Security Pages
    'microsoft.com': {
        type: 'advisory' as const,
        confidence: 85,
        subcategory: 'microsoft',
        description: 'Microsoft Security Advisory',
        extractors: ['msrcId', 'kbId']
    },
    'support.apple.com': {
        type: 'advisory' as const,
        confidence: 90,
        subcategory: 'apple',
        description: 'Apple Security Update',
        extractors: ['appleId']
    },
    'security.gentoo.org': {
        type: 'advisory' as const,
        confidence: 90,
        subcategory: 'gentoo',
        description: 'Gentoo Security Advisory',
        extractors: ['glsaId']
    },
    'access.redhat.com': {
        type: 'advisory' as const,
        confidence: 90,
        subcategory: 'redhat',
        description: 'Red Hat Security Advisory',
        extractors: ['rhsaId', 'rhelId']
    },
    'ubuntu.com': {
        type: 'advisory' as const,
        confidence: 85,
        subcategory: 'ubuntu',
        description: 'Ubuntu Security Notice',
        extractors: ['usnId']
    },
    'debian.org': {
        type: 'advisory' as const,
        confidence: 85,
        subcategory: 'debian',
        description: 'Debian Security Advisory',
        extractors: ['dsaId']
    },
    
    // Research & Analysis
    'blog.checkpoint.com': {
        type: 'research' as const,
        confidence: 80,
        subcategory: 'checkpoint',
        description: 'Check Point Research',
        extractors: ['blogPost']
    },
    'research.checkpoint.com': {
        type: 'research' as const,
        confidence: 85,
        subcategory: 'checkpoint',
        description: 'Check Point Research',
        extractors: ['researchId']
    },
    'blog.talosintelligence.com': {
        type: 'research' as const,
        confidence: 80,
        subcategory: 'talos',
        description: 'Talos Intelligence',
        extractors: ['blogPost']
    },
    'unit42.paloaltonetworks.com': {
        type: 'research' as const,
        confidence: 80,
        subcategory: 'unit42',
        description: 'Unit 42 Research',
        extractors: ['blogPost']
    },
    
    // Bug Bounty & Security Platforms
    'hackerone.com': {
        type: 'discussion' as const,
        confidence: 75,
        subcategory: 'hackerone',
        description: 'HackerOne Report',
        extractors: ['reportId']
    },
    'bugzilla.mozilla.org': {
        type: 'discussion' as const,
        confidence: 80,
        subcategory: 'bugzilla',
        description: 'Mozilla Bugzilla',
        extractors: ['bugId']
    },
    
    // Documentation & Standards
    'owasp.org': {
        type: 'documentation' as const,
        confidence: 85,
        subcategory: 'owasp',
        description: 'OWASP Documentation',
        extractors: ['owaspId']
    },
    'cwe.mitre.org': {
        type: 'documentation' as const,
        confidence: 90,
        subcategory: 'cwe',
        description: 'Common Weakness Enumeration',
        extractors: ['cweId']
    },
    
    // Social & Discussion
    'reddit.com': {
        type: 'discussion' as const,
        confidence: 60,
        subcategory: 'reddit',
        description: 'Reddit Discussion',
        extractors: ['subreddit', 'postId']
    },
    'stackoverflow.com': {
        type: 'discussion' as const,
        confidence: 70,
        subcategory: 'stackoverflow',
        description: 'Stack Overflow Question',
        extractors: ['questionId']
    },
    'twitter.com': {
        type: 'discussion' as const,
        confidence: 50,
        subcategory: 'twitter',
        description: 'Twitter/X Post',
        extractors: ['username', 'tweetId']
    },
    'x.com': {
        type: 'discussion' as const,
        confidence: 50,
        subcategory: 'twitter',
        description: 'Twitter/X Post',
        extractors: ['username', 'tweetId']
    }
};

// Path-based refinement patterns for GitHub-like repositories
// IMPORTANT: Order matters! Specific patterns MUST come before generic patterns
// to prevent miscategorization (e.g., exploit commits being marked as fixes)
export const GITHUB_PATH_PATTERNS = [
    // Known exploit repositories - check these FIRST
    {
        pattern: /\/projectdiscovery\/nuclei-templates\//i,
        type: 'exploit' as const,
        confidence: 90,
        extractor: () => ({})
    },
    {
        pattern: /\/nomi-sec\/PoC-in-GitHub\//i,
        type: 'poc' as const,
        confidence: 75,
        extractor: () => ({})
    },
    // Detect exploit/PoC repositories by naming patterns - check BEFORE generic commit pattern
    // Matches repositories with: exploit, poc, proof-of-concept, vulnerability, cve in the name
    // Examples: /CVE-2024-1234-exploit/, /wordpress-poc/, /vulnerability-research/
    // This prevents exploit commits from being miscategorized as fixes
    {
        pattern: /\/[^\/]*(?:exploit|poc|proof-of-concept|vulnerability|cve-\d{4}-\d+)[^\/]*\//i,
        type: 'exploit' as const,
        confidence: 75,
        extractor: () => ({})
    },
    // Generic commit pattern - comes AFTER exploit detection to avoid miscategorization
    {
        pattern: /\/commit\/([a-f0-9]{7,40})/i,
        type: 'fix' as const,
        confidence: 90,
        extractor: (match: RegExpMatchArray) => ({ commitHash: match[1] })
    },
    {
        pattern: /\/pull\/(\d+)/i,
        type: 'fix' as const,
        confidence: 80,
        extractor: (match: RegExpMatchArray) => ({ prNumber: parseInt(match[1]) })
    },
    {
        pattern: /\/issues\/(\d+)/i,
        type: 'discussion' as const,
        confidence: 75,
        extractor: (match: RegExpMatchArray) => ({ issueNumber: parseInt(match[1]) })
    },
    {
        pattern: /\/releases\/tag\/([^\/]+)/i,
        type: 'fix' as const,
        confidence: 70,
        extractor: (match: RegExpMatchArray) => ({ releaseTag: match[1] })
    },
    {
        pattern: /\/blob\/([^\/]+)\/(.*\.(py|js|java|cpp?|php|rb|go|rs|md|txt|sh|pl|lua|r))$/i,
        type: 'poc' as const,
        confidence: 65,
        extractor: (match: RegExpMatchArray) => ({
            blobRef: match[1],
            filePath: match[2],
            fileType: match[3]
        })
    },
    {
        pattern: /gist\.github\.com/i,
        type: 'poc' as const,
        confidence: 80,
        extractor: () => ({})
    }
];

// Data extraction functions
const DATA_EXTRACTORS = {
    cveId: (url: string) => {
        const match = url.match(/CVE-(\d{4}-\d{4,})/i);
        return match ? { cveId: match[0].toUpperCase() } : {};
    },
    
    nvdId: (url: string) => {
        const match = url.match(/vuln\/detail\/(CVE-\d{4}-\d{4,})/i);
        return match ? { nvdId: match[1].toUpperCase() } : {};
    },
    
    snykId: (url: string) => {
        const match = url.match(/\/vuln\/(SNYK-[^\/]+)/i);
        return match ? { snykId: match[1] } : {};
    },
    
    packageName: (url: string) => {
        const match = url.match(/\/package\/([^\/]+)\/([^\/]+)/i);
        return match ? { packageManager: match[1], packageName: match[2] } : {};
    },
    
    exploitId: (url: string) => {
        const match = url.match(/\/exploits\/(\d+)/i);
        return match ? { exploitId: match[1] } : {};
    },
    
    vulnDbId: (url: string) => {
        const match = url.match(/\?(?:id|ctiid|submit)\.(\d+)/i);
        return match ? { vulnDbId: parseInt(match[1]) } : {};
    },
    
    vuldbId: (url: string) => {
        const match = url.match(/\/(\d+)/i);
        return match ? { vuldbId: parseInt(match[1]) } : {};
    },
    
    repoOwner: (url: string) => {
        const match = url.match(/github\.com\/([^\/]+)\/([^\/]+)/i);
        return match ? { repoOwner: match[1], repoName: match[2] } : {};
    },
    
    repoName: (url: string) => {
        const match = url.match(/github\.com\/([^\/]+)\/([^\/]+)/i);
        return match ? { repoOwner: match[1], repoName: match[2] } : {};
    },

    gistId: (url: string) => {
        // Match gist URLs with or without username
        // Format: gist.github.com/username/gistid OR gist.github.com/gistid
        const matchWithUser = url.match(/gist\.github\.com\/([^\/]+)\/([a-f0-9]+)/i);
        const matchWithoutUser = url.match(/gist\.github\.com\/([a-f0-9]+)/i);

        if (matchWithUser) {
            // Has username: gist.github.com/username/gistid
            return {
                repoOwner: matchWithUser[1],
                gistId: matchWithUser[2]
            };
        } else if (matchWithoutUser) {
            // Anonymous gist: gist.github.com/gistid
            return {
                gistId: matchWithoutUser[1]
            };
        }
        return {};
    },

    commitHash: (url: string) => {
        const match = url.match(/\/commit\/([a-f0-9]{7,40})/i);
        return match ? { commitHash: match[1] } : {};
    },
    
    issueNumber: (url: string) => {
        const match = url.match(/\/issues\/(\d+)/i);
        return match ? { issueNumber: parseInt(match[1]) } : {};
    },
    
    prNumber: (url: string) => {
        const match = url.match(/\/pull\/(\d+)/i);
        return match ? { prNumber: parseInt(match[1]) } : {};
    },
    
    msrcId: (url: string) => {
        const match = url.match(/(MS\d{2}-\d{3}|CVE-\d{4}-\d{4,})/i);
        return match ? { msrcId: match[1] } : {};
    },
    
    kbId: (url: string) => {
        const match = url.match(/KB(\d+)/i);
        return match ? { kbId: `KB${match[1]}` } : {};
    },
    
    rhsaId: (url: string) => {
        const match = url.match(/(RHSA-\d{4}:\d+)/i);
        return match ? { rhsaId: match[1] } : {};
    },
    
    usnId: (url: string) => {
        const match = url.match(/(USN-\d+-\d+)/i);
        return match ? { usnId: match[1] } : {};
    },
    
    dsaId: (url: string) => {
        const match = url.match(/(DSA-\d+-\d+)/i);
        return match ? { dsaId: match[1] } : {};
    },
    
    zdiId: (url: string) => {
        const match = url.match(/(ZDI-\d{2}-\d+)/i);
        return match ? { zdiId: match[1] } : {};
    },
    
    glsaId: (url: string) => {
        const match = url.match(/(GLSA-\d{6}-\d+)/i);
        return match ? { glsaId: match[1] } : {};
    },
    
    cweId: (url: string) => {
        const match = url.match(/(CWE-\d+)/i);
        return match ? { cweId: match[1] } : {};
    },
    
    reportId: (url: string) => {
        const match = url.match(/\/reports\/(\d+)/i);
        return match ? { reportId: parseInt(match[1]) } : {};
    },
    
    bugId: (url: string) => {
        const match = url.match(/show_bug\.cgi\?id=(\d+)/i);
        return match ? { bugId: parseInt(match[1]) } : {};
    },
    
    questionId: (url: string) => {
        const match = url.match(/\/questions\/(\d+)/i);
        return match ? { questionId: parseInt(match[1]) } : {};
    },
    
    subreddit: (url: string) => {
        const match = url.match(/\/r\/([^\/]+)/i);
        return match ? { subreddit: match[1] } : {};
    },
    
    postId: (url: string) => {
        const match = url.match(/\/comments\/([^\/]+)/i);
        return match ? { postId: match[1] } : {};
    },
    
    username: (url: string) => {
        const match = url.match(/(?:twitter\.com|x\.com)\/([^\/]+)/i);
        return match ? { username: match[1] } : {};
    },
    
    tweetId: (url: string) => {
        const match = url.match(/status\/(\d+)/i);
        return match ? { tweetId: match[1] } : {};
    },
    
    advisoryId: (url: string) => {
        const match = url.match(/[A-Z]+-\d{4}-\d+/i);
        return match ? { advisoryId: match[0] } : {};
    },
    
    certId: (url: string) => {
        const match = url.match(/(VU#\d+|CA-\d{4}-\d+)/i);
        return match ? { certId: match[1] } : {};
    },
    
    packetStormId: (url: string) => {
        const match = url.match(/\/files\/(\d+)/i);
        return match ? { packetStormId: parseInt(match[1]) } : {};
    },

    vlId: (url: string) => {
        const match = url.match(/[?&]id=(\d+)/i);
        return match ? { vlId: match[1] } : {};
    },

    mailingList: (url: string) => {
        const match = url.match(/\/([^\/]+)\/\d{4}-\w+/i);
        return match ? { mailingList: match[1] } : {};
    },
    
    messageId: (url: string) => {
        const match = url.match(/(\d{4}-\w+)/i);
        return match ? { messageId: match[1] } : {};
    },
    
    blogPost: (url: string) => {
        const pathSegments = new URL(url).pathname.split('/').filter(Boolean);
        const lastSegment = pathSegments[pathSegments.length - 1];
        return { blogPost: lastSegment };
    },
    
    researchId: (url: string) => {
        const match = url.match(/\/([^\/]+)$/i);
        return match ? { researchId: match[1] } : {};
    },
    
    owaspId: (url: string) => {
        const match = url.match(/OWASP[_-]([^\/]+)/i);
        return match ? { owaspId: `OWASP_${match[1]}` } : {};
    },
    
    appleId: (url: string) => {
        const match = url.match(/(HT\d+)/i);
        return match ? { appleId: match[1] } : {};
    }
};

/**
 * Categorizes a URL and extracts relevant data based on common CVE reference patterns
 */
export function categorizeURL(url: string): CategorizedURL {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.replace(/^www\./, '').toLowerCase();
        const path = urlObj.pathname;
        
        // Find matching domain pattern
        let domainPattern = DOMAIN_PATTERNS[domain];
        
        // Try partial domain matches for subdomains
        if (!domainPattern) {
            for (const [patternDomain, pattern] of Object.entries(DOMAIN_PATTERNS)) {
                if (domain.endsWith(patternDomain)) {
                    domainPattern = pattern;
                    break;
                }
            }
        }
        
        if (!domainPattern) {
            return {
                url,
                domain,
                path,
                category: {
                    type: 'unknown',
                    confidence: 10,
                    description: 'Unknown domain type'
                }
            };
        }
        
        let category: URLCategory = {
            type: domainPattern.type,
            confidence: domainPattern.confidence,
            subcategory: domainPattern.subcategory,
            description: domainPattern.description,
            extractedData: {}
        };
        
        // Extract data using configured extractors
        if (domainPattern.extractors) {
            for (const extractorName of domainPattern.extractors) {
                const extractor = DATA_EXTRACTORS[extractorName as keyof typeof DATA_EXTRACTORS];
                if (extractor) {
                    const extracted = extractor(url);
                    category.extractedData = { ...category.extractedData, ...extracted };
                }
            }
        }
        
        // Apply path-based refinements for repositories
        if (domain.includes('github.com') || domain.includes('gitlab.com') || domain.includes('bitbucket.org')) {
            for (const pathPattern of GITHUB_PATH_PATTERNS) {
                const match = path.match(pathPattern.pattern);
                if (match) {
                    category.type = pathPattern.type;
                    category.confidence = Math.max(category.confidence, pathPattern.confidence);
                    const pathData = pathPattern.extractor(match);
                    category.extractedData = { ...category.extractedData, ...pathData };
                    
                    // Update description based on refined type
                    if (category.type === 'fix') {
                        category.description = 'Code fix or patch';
                    } else if (category.type === 'poc') {
                        category.description = 'Proof of concept code';
                    } else if (category.type === 'discussion') {
                        category.description = 'Issue or discussion';
                    }
                    break;
                }
            }
        }
        
        // Special handling for gists
        if (url.includes('gist.github.com')) {
            category.type = 'poc';
            category.confidence = 80;
            category.description = 'GitHub Gist (likely PoC)';
            // Extract gist ID
            const gistExtractor = DATA_EXTRACTORS['gistId'];
            if (gistExtractor) {
                const gistData = gistExtractor(url);
                category.extractedData = { ...category.extractedData, ...gistData };
            }
        }
        
        return {
            url,
            domain,
            path,
            category
        };
        
    } catch (error) {
        return {
            url,
            domain: '',
            path: '',
            category: {
                type: 'unknown',
                confidence: 0,
                description: 'Invalid URL format'
            }
        };
    }
}

/**
 * Batch categorize multiple URLs
 */
export function categorizeURLs(urls: string[]): CategorizedURL[] {
    return urls.map(categorizeURL);
}

/**
 * Get statistics about categorized URLs
 */
export function getCategorizedURLStats(categorizedURLs: CategorizedURL[]) {
    const stats = {
        total: categorizedURLs.length,
        byType: {} as Record<string, number>,
        bySubcategory: {} as Record<string, number>,
        averageConfidence: 0,
        highConfidence: 0, // >= 80%
        mediumConfidence: 0, // 50-79%
        lowConfidence: 0 // < 50%
    };
    
    let totalConfidence = 0;
    
    for (const categorized of categorizedURLs) {
        const { type, subcategory, confidence } = categorized.category;
        
        // Count by type
        stats.byType[type] = (stats.byType[type] || 0) + 1;
        
        // Count by subcategory
        if (subcategory) {
            stats.bySubcategory[subcategory] = (stats.bySubcategory[subcategory] || 0) + 1;
        }
        
        // Confidence tracking
        totalConfidence += confidence;
        if (confidence >= 80) {
            stats.highConfidence++;
        } else if (confidence >= 50) {
            stats.mediumConfidence++;
        } else {
            stats.lowConfidence++;
        }
    }
    
    stats.averageConfidence = Math.round(totalConfidence / stats.total);
    
    return stats;
}
