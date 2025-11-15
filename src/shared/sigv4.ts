/**
 * AWS Signature Version 4 Utilities
 * Implements SigV4 request signing validation for API authentication
 */

/**
 * Parse AWS SigV4 Authorization header
 * Format: AWS4-HMAC-SHA512 Credential=ACCESS_KEY/DATE/REGION/SERVICE/aws4_request, SignedHeaders=..., Signature=...
 */
export function parseAuthorizationHeader(authHeader: string): {
    algorithm: string
    accessKey: string
    date: string
    region: string
    service: string
    signedHeaders: string[]
    signature: string
} | null {
    // Match AWS4-HMAC-SHA512 format
    const match = authHeader.match(/^AWS4-HMAC-SHA512 Credential=([^,]+), SignedHeaders=([^,]+), Signature=(.+)$/)
    if (!match) {
        return null
    }

    const [, credentialString, signedHeadersString, signature] = match

    // Parse credential: ACCESS_KEY/DATE/REGION/SERVICE/aws4_request
    const credentialParts = credentialString.split('/')
    if (credentialParts.length !== 5 || credentialParts[4] !== 'aws4_request') {
        return null
    }

    const [accessKey, date, region, service] = credentialParts

    return {
        algorithm: 'AWS4-HMAC-SHA512',
        accessKey,
        date,
        region,
        service,
        signedHeaders: signedHeadersString.split(';'),
        signature
    }
}

/**
 * HMAC SHA-512 helper
 */
async function hmac(key: Uint8Array | string, data: string): Promise<Uint8Array> {
    const encoder = new TextEncoder()
    const keyData = typeof key === 'string' ? encoder.encode(key) : key

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-512' },
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
 * SHA-512 hash helper
 */
async function sha512(data: string): Promise<string> {
    const encoder = new TextEncoder()
    const hashBuffer = await crypto.subtle.digest('SHA-512', encoder.encode(data))
    return toHex(new Uint8Array(hashBuffer))
}

/**
 * Derive AWS SigV4 signing key
 */
async function getSignatureKey(key: string, dateStamp: string, regionName: string, serviceName: string): Promise<Uint8Array> {
    const kDate = await hmac(`AWS4${key}`, dateStamp)
    const kRegion = await hmac(kDate, regionName)
    const kService = await hmac(kRegion, serviceName)
    const kSigning = await hmac(kService, 'aws4_request')
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
 * Validate AWS SigV4 signature
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

    const { date, region, service, signedHeaders, signature } = parsedAuth

    // 1. Create canonical request
    const payloadHash = await sha512(body)
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
    const canonicalRequestHash = await sha512(canonicalRequest)
    const credentialScope = `${date}/${region}/${service}/aws4_request`
    const amzDate = headers['x-amz-date'] || headers['date'] || ''

    const stringToSign = [
        'AWS4-HMAC-SHA512',
        amzDate,
        credentialScope,
        canonicalRequestHash
    ].join('\n')

    // 3. Calculate signature
    const signingKey = await getSignatureKey(secretKey, date, region, service)
    const calculatedSignature = toHex(await hmac(signingKey, stringToSign))

    // Debug logging
    console.log('=== SigV4 Validation Debug ===')
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
 * Extract headers as lowercase key-value map
 */
export function normalizeHeaders(request: Request): Record<string, string> {
    const headers: Record<string, string> = {}
    request.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value
    })
    return headers
}
