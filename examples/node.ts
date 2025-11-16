import crypto from 'crypto';
import fetch from 'node-fetch';

const VVD_ORG = "";
const VVD_SECRET = "";
const VVD_ACCESS_KEY = VVD_ORG;
const BASE_URL = "https://api.vdb.vulnetix.com/v1";

function hmacSha512(key: string | Buffer, data: string): Buffer {
    return crypto.createHmac('sha512', key).update(data).digest();
}

function sha512(data: string): string {
    return crypto.createHash('sha512').update(data).digest('hex');
}

function getSignatureKey(key: string, dateStamp: string, region: string, service: string): Buffer {
    const kDate = hmacSha512(`AWS4${key}`, dateStamp);
    const kRegion = hmacSha512(kDate, region);
    const kService = hmacSha512(kRegion, service);
    const kSigning = hmacSha512(kService, 'aws4_request');
    return kSigning;
}

function signRequest(
    accessKey: string,
    secretKey: string,
    method: string,
    path: string,
    body: string = ''
): Record<string, string> {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.substring(0, 8);
    const region = 'us-east-1';
    const service = 'vdb';

    const payloadHash = sha512(body);
    const canonicalHeaders = `x-amz-date:${amzDate}\n`;
    const signedHeaders = 'x-amz-date';

    const canonicalRequest = [
        method,
        path,
        '',
        canonicalHeaders,
        signedHeaders,
        payloadHash
    ].join('\n');

    const algorithm = 'AWS4-HMAC-SHA512';
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = [
        algorithm,
        amzDate,
        credentialScope,
        sha512(canonicalRequest)
    ].join('\n');

    const signingKey = getSignatureKey(secretKey, dateStamp, region, service);
    const signature = hmacSha512(signingKey, stringToSign).toString('hex');

    const authHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
        'X-Amz-Date': amzDate,
        'Authorization': authHeader
    };
}

async function getJWTToken(): Promise<string> {
    const path = '/auth/token';
    const signedHeaders = signRequest(VVD_ACCESS_KEY, VVD_SECRET, 'GET', path);

    const response = await fetch(`${BASE_URL}${path}`, {
        method: 'GET',
        headers: signedHeaders
    });

    if (!response.ok) {
        throw new Error(`Failed to obtain JWT token: ${response.status}`);
    }

    const data = await response.json() as {
        token: string;
        iss: string;
        sub: string;
        exp: number;
    };

    console.log(`JWT token obtained (expires in 15 minutes): ${data.token.substring(0, 50)}...`);
    console.log('Token details:', {
        iss: data.iss,
        sub: data.sub,
        exp: new Date(data.exp * 1000).toISOString()
    });

    return data.token;
}

async function makeAPIRequest(): Promise<void> {
    const jwtToken = await getJWTToken();

    const response = await fetch(`${BASE_URL}/ecosystems`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json'
        }
    });

    if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
    }

    const data = await response.json();
    console.log('API Response:', JSON.stringify(data, null, 2));
}

makeAPIRequest().catch(console.error);
