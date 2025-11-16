// VDB API Testing - AWS SigV4 Authentication Example (JavaScript/Node.js)
// This example works in both Node.js and modern browsers with Web Crypto API

// Step 1: Configuration - Set your Organization credentials
const VVD_ORG = "f7c11fc1-d422-4242-a05e-ea3e747b07bc"; // Organization UUID (used as access key)
const VVD_SECRET = "ldCTA9jeOLtHdkByhLl8DyIIo5bd2Meb6IA4rATn0KCanfzU2s97CTBQ7bxtYTIs"; // Organization Secret (64 chars)
const VVD_ACCESS_KEY = VVD_ORG; // Access key is the Organization UUID

// Step 2: AWS SigV4 Signing Functions
async function hmacSha512(key, data) {
    const encoder = new TextEncoder();
    const keyData = typeof key === "string" ? encoder.encode(key) : key;
    
    const cryptoKey = await crypto.subtle.importKey(
        "raw", keyData,
        { name: "HMAC", hash: "SHA-512" },
        false, ["sign"]
    );
    
    const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(data));
    return new Uint8Array(signature);
}

function toHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

async function sha512(data) {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest("SHA-512", encoder.encode(data));
    return toHex(new Uint8Array(hashBuffer));
}

async function getSignatureKey(key, dateStamp, region, service) {
    const kDate = await hmacSha512(`AWS4${key}`, dateStamp);
    const kRegion = await hmacSha512(kDate, region);
    const kService = await hmacSha512(kRegion, service);
    const kSigning = await hmacSha512(kService, "aws4_request");
    return kSigning;
}

// Step 3: Sign the request
async function signRequest(accessKey, secretKey, method, path, headers = {}, body = "") {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const dateStamp = amzDate.substring(0, 8);
    const region = "us-east-1";
    const service = "vdb";
    
    // Add required headers (x-amz-date only - browsers block setting host header)
    const allHeaders = { ...headers, "x-amz-date": amzDate };
    
    // Create canonical request
    const payloadHash = await sha512(body);
    const signedHeaders = Object.keys(allHeaders).sort().join(";");
    const canonicalHeaders = Object.keys(allHeaders).sort()
        .map(k => `${k}:${allHeaders[k].trim()}\n`)
        .join("");
    
    const canonicalRequest = [
        method, path, "", // query string
        canonicalHeaders, signedHeaders, payloadHash
    ].join("\n");
    
    // Create string to sign
    const canonicalRequestHash = await sha512(canonicalRequest);
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = [
        "AWS4-HMAC-SHA512", amzDate, credentialScope, canonicalRequestHash
    ].join("\n");
    
    // Calculate signature
    const signingKey = await getSignatureKey(secretKey, dateStamp, region, service);
    const signature = toHex(await hmacSha512(signingKey, stringToSign));
    
    // Build authorization header
    const authHeader = `AWS4-HMAC-SHA512 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    
    return {
        ...allHeaders,
        "Authorization": authHeader
    };
}

// Step 4: Get JWT token from /v1/auth/token
async function getJWTToken() {
    const method = "GET";
    const path = "/auth/token";
    
    // Sign the request
    const signedHeaders = await signRequest(VVD_ACCESS_KEY, VVD_SECRET, method, path);
    
    // Make the request
    const response = await fetch("https://api.vdb.vulnetix.com/v1" + path, {
        method: method,
        headers: signedHeaders
    });
    
    const data = await response.json();
    
    if (!data.token) {
        throw new Error("Failed to obtain JWT token");
    }
    
    console.log("JWT token obtained (expires in 15 minutes):", data.token.substring(0, 50) + "...");
    console.log("Token details:", {
        iss: data.iss,
        sub: data.sub,
        exp: new Date(data.exp * 1000).toISOString()
    });
    
    return data.token;
}

// Step 5: Make authenticated API request
async function makeAPIRequest() {
    // Get JWT token
    const jwtToken = await getJWTToken();
    
    // Make GET request to /ecosystems
    const response = await fetch("https://api.vdb.vulnetix.com/v1/ecosystems", {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${jwtToken}`,
            "Content-Type": "application/json"
        }
    });
    
    const data = await response.json();
    console.log("API Response:", data);
    return data;
}

// Execute the request
makeAPIRequest().catch(console.error);
