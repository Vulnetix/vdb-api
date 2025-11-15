/**
 * CWE to CVSS v4.0 Vector Mapper
 *
 * Self-contained, reusable module for generating CVSS v4.0 vectors from CWE data.
 * Supports all CWE types and can be used across the application with multiple data sources:
 * - CVE List v5 (CVEMetadata + relations)
 * - NVD JSON 2.0
 * - GitHub SARIF
 * - Standard SARIF 2.1.0
 */

import type { PrismaClient } from '@prisma/client'

/**
 * Context data extracted from CVE records to inform CVSS generation
 */
export interface CVEContextData {
    cwes: string[]
    descriptions: string[]
    problemTypes: Array<{
        cweId: string | null
        description: string
        containerType: string
    }>
    title?: string | null
    keywords: string[]
}

/**
 * CWE category for mapping to CVSS metrics
 */
interface CWECategory {
    attackVector: 'N' | 'A' | 'L' | 'P'  // Network, Adjacent, Local, Physical
    attackComplexity: 'L' | 'H'  // Low, High
    privilegesRequired: 'N' | 'L' | 'H'  // None, Low, High
    userInteraction: 'N' | 'P' | 'A'  // None, Passive, Active
    confidentiality: 'H' | 'L' | 'N'  // High, Low, None
    integrity: 'H' | 'L' | 'N'  // High, Low, None
    availability: 'H' | 'L' | 'N'  // High, Low, None
    subsequentConfidentiality: 'H' | 'L' | 'N'  // Subsequent System
    subsequentIntegrity: 'H' | 'L' | 'N'  // Subsequent System
    subsequentAvailability: 'H' | 'L' | 'N'  // Subsequent System
}

/**
 * Comprehensive CWE to CVSS metrics mapping
 * Covers major CWE categories and their typical impact patterns
 */
const CWE_MAPPINGS: Record<string, CWECategory> = {
    // Injection Vulnerabilities (Remote, High Impact)
    'CWE-79': { // XSS
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'P',
        confidentiality: 'L', integrity: 'L', availability: 'N',
        subsequentConfidentiality: 'L', subsequentIntegrity: 'L', subsequentAvailability: 'N'
    },
    'CWE-89': { // SQL Injection
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'L',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-78': { // OS Command Injection
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-94': { // Code Injection
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-77': { // Command Injection
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-91': { // XML Injection
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'L',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },

    // Information Disclosure
    'CWE-200': { // Exposure of Sensitive Information
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'N', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-209': { // Information Exposure Through Error Message
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'L', integrity: 'N', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-532': { // Insertion of Sensitive Information into Log File
        attackVector: 'L', attackComplexity: 'L', privilegesRequired: 'L', userInteraction: 'N',
        confidentiality: 'H', integrity: 'N', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },

    // Denial of Service
    'CWE-400': { // Uncontrolled Resource Consumption
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'N', integrity: 'N', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-770': { // Allocation of Resources Without Limits
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'N', integrity: 'N', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-835': { // Loop with Unreachable Exit Condition
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'N', integrity: 'N', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },

    // Authentication & Access Control
    'CWE-287': { // Improper Authentication
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-306': { // Missing Authentication for Critical Function
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-798': { // Use of Hard-coded Credentials
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-862': { // Missing Authorization
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-863': { // Incorrect Authorization
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },

    // Memory Safety (Local)
    'CWE-119': { // Improper Restriction of Operations within Buffer
        attackVector: 'L', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-125': { // Out-of-bounds Read
        attackVector: 'L', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'N', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-787': { // Out-of-bounds Write
        attackVector: 'L', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-416': { // Use After Free
        attackVector: 'L', attackComplexity: 'H', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },
    'CWE-415': { // Double Free
        attackVector: 'L', attackComplexity: 'H', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },

    // Path Traversal & File Operations
    'CWE-22': { // Path Traversal
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'N', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-434': { // Unrestricted Upload of File with Dangerous Type
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },

    // Cryptographic Issues
    'CWE-327': { // Use of a Broken or Risky Cryptographic Algorithm
        attackVector: 'N', attackComplexity: 'H', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-328': { // Use of Weak Hash
        attackVector: 'N', attackComplexity: 'H', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'L', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-326': { // Inadequate Encryption Strength
        attackVector: 'N', attackComplexity: 'H', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'N', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },

    // CSRF & SSRF
    'CWE-352': { // Cross-Site Request Forgery
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'P',
        confidentiality: 'L', integrity: 'H', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-918': { // Server-Side Request Forgery
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'N',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },

    // Deserialization
    'CWE-502': { // Deserialization of Untrusted Data
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'H', subsequentIntegrity: 'H', subsequentAvailability: 'H'
    },

    // Race Conditions
    'CWE-362': { // Concurrent Execution using Shared Resource with Improper Synchronization
        attackVector: 'L', attackComplexity: 'H', privilegesRequired: 'L', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },

    // NULL Pointer Dereference
    'CWE-476': { // NULL Pointer Dereference
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'N', integrity: 'N', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },

    // Integer Overflow/Underflow
    'CWE-190': { // Integer Overflow
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
    'CWE-191': { // Integer Underflow
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N',
        confidentiality: 'H', integrity: 'H', availability: 'H',
        subsequentConfidentiality: 'N', subsequentIntegrity: 'N', subsequentAvailability: 'N'
    },
}

/**
 * Query CVE context data from database
 * Fetches CWEs, descriptions, and problem types from CVEMetadata relations
 */
export async function getCVEContextData(prisma: PrismaClient, cveId: string): Promise<CVEContextData> {
    const cwes: string[] = []
    const descriptions: string[] = []
    const problemTypes: Array<{ cweId: string | null; description: string; containerType: string }> = []
    let title: string | null = null

    // Query CVEMetadata and related data
    const cveMetadataRecords = await prisma.cVEMetadata.findMany({
        where: { cveId },
        include: {
            problemTypes: true,
            descriptions: true
        }
    })

    for (const record of cveMetadataRecords) {
        // Collect title from first record with title
        if (record.title && !title) {
            title = record.title
        }

        // Collect problem types (CWEs)
        for (const pt of record.problemTypes) {
            if (pt.cweId) {
                cwes.push(pt.cweId)
            }
            problemTypes.push({
                cweId: pt.cweId,
                description: pt.description,
                containerType: pt.containerType
            })
        }

        // Collect descriptions
        for (const desc of record.descriptions) {
            if (desc.value) {
                descriptions.push(desc.value)
            }
        }
    }

    // Extract keywords from descriptions and title
    const keywords = extractKeywords([...descriptions, title || ''])

    return {
        cwes: [...new Set(cwes)], // Deduplicate
        descriptions: [...new Set(descriptions)],
        problemTypes,
        title,
        keywords
    }
}

/**
 * Extract security-relevant keywords from text
 */
function extractKeywords(texts: string[]): string[] {
    const keywords: Set<string> = new Set()
    const combinedText = texts.join(' ').toLowerCase()

    // Attack vectors
    if (/\b(remote|network|internet)\b/i.test(combinedText)) keywords.add('remote')
    if (/\b(local|privilege|elevated)\b/i.test(combinedText)) keywords.add('local')
    if (/\b(adjacent|same network)\b/i.test(combinedText)) keywords.add('adjacent')

    // Attack types
    if (/\b(rce|remote code execution|command execution)\b/i.test(combinedText)) keywords.add('rce')
    if (/\b(sqli|sql injection)\b/i.test(combinedText)) keywords.add('sqli')
    if (/\b(xss|cross.?site scripting)\b/i.test(combinedText)) keywords.add('xss')
    if (/\b(dos|denial.?of.?service)\b/i.test(combinedText)) keywords.add('dos')
    if (/\b(buffer overflow|memory corruption)\b/i.test(combinedText)) keywords.add('memory')
    if (/\b(auth|authentication|login)\b/i.test(combinedText)) keywords.add('auth')
    if (/\b(disclosure|leak|exposure|sensitive)\b/i.test(combinedText)) keywords.add('disclosure')

    // Impact
    if (/\b(confidentiality|data.?leak)\b/i.test(combinedText)) keywords.add('confidentiality')
    if (/\b(integrity|modify|tamper)\b/i.test(combinedText)) keywords.add('integrity')
    if (/\b(availability|crash|hang)\b/i.test(combinedText)) keywords.add('availability')

    return Array.from(keywords)
}

/**
 * Generate CVSS v4.0 vector from CWE and context
 * Can return multiple vectors if the CWE has multiple potential scenarios
 */
export function generateCvssFromCWE(
    cweId: string,
    context?: {
        description?: string
        keywords?: string[]
        title?: string
    }
): string[] {
    // Look up CWE mapping
    const mapping = CWE_MAPPINGS[cweId]

    if (!mapping) {
        // Unknown CWE - use conservative defaults
        return [buildCvssVector({
            attackVector: 'N',
            attackComplexity: 'L',
            privilegesRequired: 'N',
            userInteraction: 'N',
            confidentiality: 'L',
            integrity: 'L',
            availability: 'L',
            subsequentConfidentiality: 'N',
            subsequentIntegrity: 'N',
            subsequentAvailability: 'N'
        })]
    }

    // Start with base mapping
    let adjustedMapping = { ...mapping }

    // Adjust based on keywords
    if (context?.keywords) {
        adjustedMapping = adjustMappingFromKeywords(adjustedMapping, context.keywords)
    }

    return [buildCvssVector(adjustedMapping)]
}

/**
 * Adjust CVSS metrics based on keywords from description
 */
function adjustMappingFromKeywords(mapping: CWECategory, keywords: string[]): CWECategory {
    const adjusted = { ...mapping }

    // Attack vector adjustments
    if (keywords.includes('remote') || keywords.includes('network')) {
        adjusted.attackVector = 'N'
    } else if (keywords.includes('local')) {
        adjusted.attackVector = 'L'
    } else if (keywords.includes('adjacent')) {
        adjusted.attackVector = 'A'
    }

    // RCE gets maximum impact
    if (keywords.includes('rce')) {
        adjusted.confidentiality = 'H'
        adjusted.integrity = 'H'
        adjusted.availability = 'H'
        adjusted.subsequentConfidentiality = 'H'
        adjusted.subsequentIntegrity = 'H'
        adjusted.subsequentAvailability = 'H'
    }

    // DoS affects availability
    if (keywords.includes('dos')) {
        adjusted.availability = 'H'
    }

    // Disclosure affects confidentiality
    if (keywords.includes('disclosure')) {
        adjusted.confidentiality = 'H'
    }

    return adjusted
}

/**
 * Build CVSS v4.0 vector string from metrics
 */
function buildCvssVector(metrics: CWECategory): string {
    // CVSS v4.0 requires Attack Requirements (AT) - set to None by default
    const at = 'N'

    return `CVSS:4.0/AV:${metrics.attackVector}/AC:${metrics.attackComplexity}/AT:${at}/PR:${metrics.privilegesRequired}/UI:${metrics.userInteraction}/VC:${metrics.confidentiality}/VI:${metrics.integrity}/VA:${metrics.availability}/SC:${metrics.subsequentConfidentiality}/SI:${metrics.subsequentIntegrity}/SA:${metrics.subsequentAvailability}`
}

/**
 * Main entry point: Generate CVSS vector for a CVE from database
 * Returns the first valid CVSS vector generated, or null if none can be generated
 */
export async function generateCvssVectorForCVE(
    prisma: PrismaClient,
    cveId: string
): Promise<string | null> {
    // Get context data from database
    const context = await getCVEContextData(prisma, cveId)

    if (context.cwes.length === 0) {
        // No CWEs found - use conservative default based on keywords
        if (context.keywords.length > 0) {
            const vectors = generateCvssFromCWE('CWE-UNKNOWN', {
                description: context.descriptions.join(' '),
                keywords: context.keywords,
                title: context.title || undefined
            })
            return vectors[0] || null
        }
        return null
    }

    // Generate vector from first CWE (prioritize the first one from CNA)
    const primaryCWE = context.cwes[0]
    const vectors = generateCvssFromCWE(primaryCWE, {
        description: context.descriptions.join(' '),
        keywords: context.keywords,
        title: context.title || undefined
    })

    return vectors[0] || null
}

/**
 * Check if CVE already has CVSS data from any source
 * Returns the first existing CVSS vector found, prioritizing certain sources
 */
export async function getExistingCvssVector(
    prisma: PrismaClient,
    cveId: string
): Promise<{ vectorString: string; source: string } | null> {
    // Try CVEMetadata.vectorString first (deprecated field)
    const metadataWithVector = await prisma.cVEMetadata.findFirst({
        where: {
            cveId,
            vectorString: { not: null }
        },
        orderBy: [
            // Prefer certain sources
            { source: 'asc' }
        ]
    })

    if (metadataWithVector?.vectorString) {
        return {
            vectorString: metadataWithVector.vectorString,
            source: metadataWithVector.source
        }
    }

    // Try CVEMetric table (new way)
    const metric = await prisma.cVEMetric.findFirst({
        where: {
            cveId,
            vectorString: { not: null }
        },
        orderBy: [
            { source: 'asc' }
        ]
    })

    if (metric?.vectorString) {
        return {
            vectorString: metric.vectorString,
            source: metric.source
        }
    }

    return null
}
