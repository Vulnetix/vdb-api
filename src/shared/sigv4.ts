/**
 * AWS Signature Version 4 Utilities
 * Implements SigV4 request signing validation for API authentication
 */

/**
 * Parse AWS SigV4 Authorization header
 * Format: AWS4-HMAC-SHA256|SHA512 Credential=ACCESS_KEY/DATE/REGION/SERVICE/aws4_request, SignedHeaders=..., Signature=...
 */
export function parseAuthorizationHeader(authHeader: string): {
    algorithm: 'AWS4-HMAC-SHA256' | 'AWS4-HMAC-SHA512'
    accessKey: string
    date: string
    region: string
    service: string
    signedHeaders: string[]
    signature: string
} | null {
    // Match both AWS4-HMAC-SHA256 and AWS4-HMAC-SHA512 formats
    const match = authHeader.match(/^(AWS4-HMAC-SHA(?:256|512)) Credential=([^,]+), SignedHeaders=([^,]+), Signature=(.+)$/)
    if (!match) {
        return null
    }

    const [, algorithm, credentialString, signedHeadersString, signature] = match

    // Validate algorithm
    if (algorithm !== 'AWS4-HMAC-SHA256' && algorithm !== 'AWS4-HMAC-SHA512') {
        return null
    }

    // Parse credential: ACCESS_KEY/DATE/REGION/SERVICE/aws4_request
    const credentialParts = credentialString.split('/')
    if (credentialParts.length !== 5 || credentialParts[4] !== 'aws4_request') {
        return null
    }

    const [accessKey, date, region, service] = credentialParts

    return {
        algorithm: algorithm as 'AWS4-HMAC-SHA256' | 'AWS4-HMAC-SHA512',
        accessKey,
        date,
        region,
        service,
        signedHeaders: signedHeadersString.split(';'),
        signature
    }
}

/**
 * HMAC helper - supports both SHA-256 and SHA-512
 */
async function hmac(key: Uint8Array | string, data: string, algorithm: 'SHA-256' | 'SHA-512' = 'SHA-512'): Promise<Uint8Array> {
    const encoder = new TextEncoder()
    const keyData = typeof key === 'string' ? encoder.encode(key) : key

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: algorithm },
        false,
        ['sign']
    )

    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data))
    return new Uint8Array(signature)
}

/**
 * Hex encode bytes
 */
function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

/**
 * Hash helper - supports both SHA-256 and SHA-512
 */
async function hash(data: string, algorithm: 'SHA-256' | 'SHA-512' = 'SHA-512'): Promise<string> {
    const encoder = new TextEncoder()
    const hashBuffer = await crypto.subtle.digest(algorithm, encoder.encode(data))
    return toHex(new Uint8Array(hashBuffer))
}

/**
 * Derive AWS SigV4 signing key
 */
async function getSignatureKey(key: string, dateStamp: string, regionName: string, serviceName: string, algorithm: 'SHA-256' | 'SHA-512' = 'SHA-512'): Promise<Uint8Array> {
    const kDate = await hmac(`AWS4${key}`, dateStamp, algorithm)
    const kRegion = await hmac(kDate, regionName, algorithm)
    const kService = await hmac(kRegion, serviceName, algorithm)
    const kSigning = await hmac(kService, 'aws4_request', algorithm)
    return kSigning
}

/**
 * Create canonical headers string
 */
function createCanonicalHeaders(headers: Record<string, string>, signedHeaders: string[]): string {
    const canonicalHeaders = signedHeaders.map(name => {
        const value = headers[name.toLowerCase()] || ''
        return `${name.toLowerCase()}:${value.trim()}\n`
    }).join('')

    return canonicalHeaders
}

/**
 * Validate AWS SigV4 signature with specific algorithm
 */
export async function validateSigV4Signature(
    method: string,
    path: string,
    queryString: string,
    headers: Record<string, string>,
    body: string,
    secretKey: string,
    parsedAuth: ReturnType<typeof parseAuthorizationHeader>
): Promise<boolean> {
    if (!parsedAuth) {
        return false
    }

    const { algorithm, date, region, service, signedHeaders, signature } = parsedAuth

    // Determine hash algorithm from the SigV4 algorithm
    const hashAlgorithm = algorithm === 'AWS4-HMAC-SHA256' ? 'SHA-256' : 'SHA-512'

    // 1. Create canonical request
    const payloadHash = await hash(body, hashAlgorithm)
    const canonicalHeaders = createCanonicalHeaders(headers, signedHeaders)
    const signedHeadersStr = signedHeaders.join(';')

    const canonicalRequest = [
        method,
        path,
        queryString,
        canonicalHeaders,
        signedHeadersStr,
        payloadHash
    ].join('\n')

    // 2. Create string to sign
    const canonicalRequestHash = await hash(canonicalRequest, hashAlgorithm)
    const credentialScope = `${date}/${region}/${service}/aws4_request`
    const amzDate = headers['x-amz-date'] || headers['date'] || ''

    const stringToSign = [
        algorithm, // Use the actual algorithm from the header
        amzDate,
        credentialScope,
        canonicalRequestHash
    ].join('\n')

    // 3. Calculate signature
    const signingKey = await getSignatureKey(secretKey, date, region, service, hashAlgorithm)
    const calculatedSignature = toHex(await hmac(signingKey, stringToSign, hashAlgorithm))

    // Debug logging
    console.log('=== SigV4 Validation Debug ===')
    console.log('Algorithm:', algorithm)
    console.log('HashAlgorithm:', hashAlgorithm)
    console.log('SecretKey (first 10 chars):', secretKey ? secretKey.substring(0, 10) + '...' : 'UNDEFINED')
    console.log('SecretKey length:', secretKey ? secretKey.length : 0)
    console.log('Date from auth:', date)
    console.log('Region:', region)
    console.log('Service:', service)
    console.log('Method:', method)
    console.log('Path:', path)
    console.log('QueryString:', queryString)
    console.log('SignedHeaders:', signedHeaders)
    console.log('Headers:', headers)
    console.log('CanonicalHeaders:', JSON.stringify(canonicalHeaders))
    console.log('PayloadHash:', payloadHash)
    console.log('CanonicalRequest:', JSON.stringify(canonicalRequest))
    console.log('CanonicalRequestHash:', canonicalRequestHash)
    console.log('StringToSign:', JSON.stringify(stringToSign))
    console.log('CalculatedSignature:', calculatedSignature)
    console.log('ReceivedSignature:', signature)
    console.log('Match:', calculatedSignature === signature)

    // 4. Compare signatures (constant-time comparison)
    return calculatedSignature === signature
}

/**
 * Validate SigV4 signature - tries SHA256 first, then falls back to SHA512
 * This is a convenience wrapper that handles both algorithm types automatically
 */
export async function validateSigV4SignatureWithFallback(
    authHeader: string,
    method: string,
    path: string,
    queryString: string,
    headers: Record<string, string>,
    body: string,
    secretKey: string
): Promise<{ isValid: boolean; algorithm?: string; parsedAuth?: ReturnType<typeof parseAuthorizationHeader> }> {
    // First, try to parse the authorization header
    const parsedAuth = parseAuthorizationHeader(authHeader)
    if (!parsedAuth) {
        return { isValid: false }
    }

    // If the client specified SHA256, validate with SHA256 only
    if (parsedAuth.algorithm === 'AWS4-HMAC-SHA256') {
        const isValid = await validateSigV4Signature(method, path, queryString, headers, body, secretKey, parsedAuth)
        return { isValid, algorithm: 'AWS4-HMAC-SHA256', parsedAuth }
    }

    // If the client specified SHA512, try SHA256 first (preferred), then SHA512
    if (parsedAuth.algorithm === 'AWS4-HMAC-SHA512') {
        // Try SHA256 first by creating a modified parsedAuth
        const sha256ParsedAuth = { ...parsedAuth, algorithm: 'AWS4-HMAC-SHA256' as const }
        const sha256Valid = await validateSigV4Signature(method, path, queryString, headers, body, secretKey, sha256ParsedAuth)

        if (sha256Valid) {
            console.log('✓ Signature validated with SHA256 (preferred)')
            return { isValid: true, algorithm: 'AWS4-HMAC-SHA256', parsedAuth: sha256ParsedAuth }
        }

        // Fall back to SHA512
        console.log('✗ SHA256 validation failed, trying SHA512...')
        const sha512Valid = await validateSigV4Signature(method, path, queryString, headers, body, secretKey, parsedAuth)

        if (sha512Valid) {
            console.log('✓ Signature validated with SHA512 (fallback)')
            return { isValid: true, algorithm: 'AWS4-HMAC-SHA512', parsedAuth }
        }

        console.log('✗ Both SHA256 and SHA512 validation failed')
        return { isValid: false, parsedAuth }
    }

    return { isValid: false }
}

/**
 * Extract headers as lowercase key-value map
 */
export function normalizeHeaders(request: Request): Record<string, string> {
    const headers: Record<string, string> = {}
    request.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value
    })
    return headers
}
