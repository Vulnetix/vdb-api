#!/usr/bin/env bash
# Generate API tests from OpenAPI Specification
# Uses openapi-to-postmanv2 and other tools to generate test collections

set -e

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Generate Tests from OpenAPI Spec${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OAS_URL="${1:-http://localhost:8778/v1/spec}"
OUTPUT_DIR="${PROJECT_ROOT}/tests/generated"

echo -e "${YELLOW}OpenAPI URL:${NC} ${OAS_URL}"
echo -e "${YELLOW}Output Directory:${NC} ${OUTPUT_DIR}"
echo ""

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Method 1: Fetch OpenAPI spec
echo -e "${BLUE}Step 1:${NC} Fetching OpenAPI specification..."
if curl -f -s "${OAS_URL}" -o "${OUTPUT_DIR}/openapi.json"; then
    echo -e "${GREEN}✓ OpenAPI spec downloaded${NC}"
else
    echo -e "${YELLOW}Warning: Could not fetch from ${OAS_URL}${NC}"
    echo -e "${YELLOW}Make sure the development server is running: just dev${NC}"
    exit 1
fi
echo ""

# Method 2: Convert to Postman Collection with AWS Auth
echo -e "${BLUE}Step 2:${NC} Converting to Postman Collection..."
if command -v openapi2postmanv2 &> /dev/null; then
    openapi2postmanv2 -s "${OUTPUT_DIR}/openapi.json" -o "${OUTPUT_DIR}/postman-collection-base.json" -p

    # Post-process the collection to add AWS Signature auth to /auth/token endpoint
    if command -v jq &> /dev/null; then
        # First, create the pre-request script content as a JSON file
        cat > "${OUTPUT_DIR}/prerequest-script.json" <<'PREREQ_EOF'
[
  "// AWS Signature V4 Authentication with SHA-512",
  "// This implementation uses SHA-512 instead of standard SHA-256",
  "// Based on vdb-manager API tester implementation",
  "",
  "const CryptoJS = require('crypto-js');",
  "",
  "// Get AWS credentials from collection/environment variables",
  "const accessKey = pm.collectionVariables.get('awsAccessKeyId') || pm.environment.get('awsAccessKeyId');",
  "const secretKey = pm.collectionVariables.get('awsSecretAccessKey') || pm.environment.get('awsSecretAccessKey');",
  "const region = pm.collectionVariables.get('awsRegion') || 'us-east-1';",
  "const service = pm.collectionVariables.get('awsService') || 'vdb';",
  "",
  "if (!accessKey || !secretKey) {",
  "    console.error('AWS credentials not configured. Set awsAccessKeyId and awsSecretAccessKey in collection variables.');",
  "    return;",
  "}",
  "",
  "// Generate timestamp",
  "const now = new Date();",
  "const amzDate = now.toISOString().replace(/[:-]|\\.\\d{3}/g, '');",
  "const dateStamp = amzDate.substring(0, 8);",
  "",
  "// Set X-Amz-Date header",
  "pm.request.headers.add({",
  "    key: 'X-Amz-Date',",
  "    value: amzDate",
  "});",
  "",
  "// Get request details",
  "const method = pm.request.method;",
  "const url = pm.request.url;",
  "const path = url.getPath();",
  "const query = url.getQueryString() || '';",
  "const body = pm.request.body ? pm.request.body.raw || '' : '';",
  "",
  "// Calculate payload hash (SHA-512)",
  "const payloadHash = CryptoJS.SHA512(body).toString(CryptoJS.enc.Hex);",
  "",
  "// Build canonical request",
  "const canonicalHeaders = `x-amz-date:${amzDate}\\n`;",
  "const signedHeaders = 'x-amz-date';",
  "const canonicalRequest = [",
  "    method,",
  "    path,",
  "    query,",
  "    canonicalHeaders,",
  "    signedHeaders,",
  "    payloadHash",
  "].join('\\n');",
  "",
  "// Create string to sign",
  "const algorithm = 'AWS4-HMAC-SHA512';",
  "const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;",
  "const canonicalRequestHash = CryptoJS.SHA512(canonicalRequest).toString(CryptoJS.enc.Hex);",
  "const stringToSign = [",
  "    algorithm,",
  "    amzDate,",
  "    credentialScope,",
  "    canonicalRequestHash",
  "].join('\\n');",
  "",
  "// Calculate signature",
  "const kDate = CryptoJS.HmacSHA512(dateStamp, 'AWS4' + secretKey);",
  "const kRegion = CryptoJS.HmacSHA512(region, kDate);",
  "const kService = CryptoJS.HmacSHA512(service, kRegion);",
  "const kSigning = CryptoJS.HmacSHA512('aws4_request', kService);",
  "const signature = CryptoJS.HmacSHA512(stringToSign, kSigning).toString(CryptoJS.enc.Hex);",
  "",
  "// Build authorization header",
  "const authHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;",
  "",
  "// Set Authorization header",
  "pm.request.headers.add({",
  "    key: 'Authorization',",
  "    value: authHeader",
  "});",
  "",
  "console.log('AWS SigV4 (SHA-512) authentication applied');",
  "console.log('X-Amz-Date:', amzDate);",
  "console.log('Authorization:', authHeader.substring(0, 80) + '...');"
]
PREREQ_EOF

        # Recursively find and update /auth/token endpoint with AWS Signature V4 auth
        jq --slurpfile prereqScript "${OUTPUT_DIR}/prerequest-script.json" '
            # Function to recursively process items
            def process_items:
                if type == "array" then
                    map(process_items)
                elif type == "object" then
                    if .request? and (.request.url.path? | if type == "array" then . == ["auth", "token"] else (. | tostring | contains("/auth/token") or contains("auth/token")) end) then
                        .request.auth = {
                            "type": "awsv4",
                            "awsv4": [
                                {"key": "accessKey", "value": "{{awsAccessKeyId}}", "type": "string"},
                                {"key": "secretKey", "value": "{{awsSecretAccessKey}}", "type": "string"},
                                {"key": "region", "value": "{{awsRegion}}", "type": "string"},
                                {"key": "service", "value": "{{awsService}}", "type": "string"},
                                {"key": "sessionToken", "value": "", "type": "string"}
                            ]
                        } |
                        # Add pre-request script for AWS SigV4 with SHA-512
                        .event = [
                            {
                                "listen": "prerequest",
                                "script": {
                                    "exec": $prereqScript[0],
                                    "type": "text/javascript"
                                }
                            }
                        ]
                    elif .item? then
                        .item = (.item | process_items)
                    else
                        .
                    end
                else
                    .
                end;

            # Process all items
            .item = (.item | process_items)
        ' "${OUTPUT_DIR}/postman-collection-base.json" > "${OUTPUT_DIR}/postman-collection.json"
        rm "${OUTPUT_DIR}/postman-collection-base.json"
        rm "${OUTPUT_DIR}/prerequest-script.json"

        # Add collection-level variables
        jq '.variable += [
            {"key": "awsAccessKeyId", "value": "YOUR_AWS_ACCESS_KEY_ID", "type": "default", "description": "AWS Access Key ID for Signature V4 authentication"},
            {"key": "awsSecretAccessKey", "value": "YOUR_AWS_SECRET_ACCESS_KEY", "type": "secret", "description": "AWS Secret Access Key for Signature V4 authentication"},
            {"key": "awsRegion", "value": "us-east-1", "type": "default", "description": "AWS Region (e.g., us-east-1)"},
            {"key": "awsService", "value": "vdb", "type": "default", "description": "AWS Service name (e.g., vdb)"},
            {"key": "baseUrl", "value": "http://localhost:8778", "type": "default", "description": "API Base URL"}
        ]' "${OUTPUT_DIR}/postman-collection.json" > "${OUTPUT_DIR}/postman-collection-temp.json"
        mv "${OUTPUT_DIR}/postman-collection-temp.json" "${OUTPUT_DIR}/postman-collection.json"

        echo -e "${GREEN}✓ Postman collection generated with AWS SigV4 (SHA-512) auth${NC}"
        echo -e "  ${YELLOW}Note:${NC} Uses pre-request script for SHA-512 variant (not standard SHA-256)"
        echo -e "  ${YELLOW}Note:${NC} X-Amz-Date header is automatically generated by the script"
    else
        mv "${OUTPUT_DIR}/postman-collection-base.json" "${OUTPUT_DIR}/postman-collection.json"
        echo -e "${YELLOW}⚠ jq not available - AWS auth not configured${NC}"
    fi
else
    echo -e "${YELLOW}⚠ openapi2postmanv2 not installed${NC}"
    echo -e "Install with: ${YELLOW}npm install -g openapi-to-postmanv2${NC}"
fi
echo ""

# Method 3: Generate HTTP snippets with native AWS auth (httpyac format)
echo -e "${BLUE}Step 3:${NC} Generating HTTP snippets..."
cat > "${OUTPUT_DIR}/generated-requests.http" << 'EOF'
###
# Auto-generated API requests from OpenAPI specification
# For httpyac: https://httpyac.github.io/
# For VS Code REST Client: https://marketplace.visualstudio.com/items?itemName=humao.rest-client
###

@baseUrl = http://localhost:8778
@token = YOUR_JWT_TOKEN_HERE

###
# Authentication - Exchange SigV4-signed request for JWT token
# Uses httpyac's built-in AWS Signature V4 support
# @name getAuthToken
# @aws
GET {{baseUrl}}/auth/token
AWS-Access-Key-Id: {{$processEnv AWS_ACCESS_KEY_ID}}
AWS-Secret-Access-Key: {{$processEnv AWS_SECRET_ACCESS_KEY}}
AWS-Region: {{$processEnv AWS_REGION}}
AWS-Service: {{$processEnv AWS_SERVICE}}

###
# Alternative: Using environment file (.env)
# Create a .env file with:
# AWS_ACCESS_KEY_ID=your_key
# AWS_SECRET_ACCESS_KEY=your_secret
# AWS_REGION=us-east-1
# AWS_SERVICE=vdb

EOF

# Parse the OpenAPI spec and generate requests for other endpoints
if command -v jq &> /dev/null; then
    # Extract paths and generate requests (excluding /auth/token which we handled above)
    jq -r '.paths | to_entries[] | select(.key != "/auth/token" and .key != "/api/auth/token") | "\n### \(.key)\n" + (.value | to_entries[] | "\(.key | ascii_upcase) {{baseUrl}}\(.key)\nAuthorization: Bearer {{token}}\nContent-Type: application/json\n")' \
        "${OUTPUT_DIR}/openapi.json" >> "${OUTPUT_DIR}/generated-requests.http"

    echo -e "${GREEN}✓ HTTP snippets generated with AWS auth${NC}"
else
    echo -e "${YELLOW}⚠ jq not installed (optional)${NC}"
    echo -e "Install with: ${YELLOW}brew install jq${NC} or ${YELLOW}apt-get install jq${NC}"
fi
echo ""

# Method 4: Generate AWS SigV4 signing helper script (SHA-512 variant)
echo -e "${BLUE}Step 4:${NC} Generating AWS SigV4 helper script..."
cat > "${OUTPUT_DIR}/sign-aws-request.js" << 'JSEOF'
#!/usr/bin/env node
/**
 * AWS Signature Version 4 Request Signer (SHA-512 variant)
 * Generates the X-Amz-Date header and Authorization header for VDB API requests
 *
 * NOTE: This uses SHA-512 instead of the standard SHA-256
 *       This matches the VDB API's implementation
 *
 * Usage:
 *   node sign-aws-request.js <method> <url> [body]
 *
 * Environment variables:
 *   AWS_ACCESS_KEY_ID - Your AWS access key
 *   AWS_SECRET_ACCESS_KEY - Your AWS secret key
 *   AWS_REGION - AWS region (default: us-east-1)
 *   AWS_SERVICE - AWS service name (default: vdb)
 */

const crypto = require('crypto');
const { URL } = require('url');

// Configuration from environment or defaults
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID || 'YOUR_ACCESS_KEY';
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY || 'YOUR_SECRET_KEY';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const AWS_SERVICE = process.env.AWS_SERVICE || 'vdb';

// Parse arguments
const method = (process.argv[2] || 'GET').toUpperCase();
const urlString = process.argv[3] || 'http://localhost:8778/auth/token';
const body = process.argv[4] || '';

// Generate signature using SHA-512
function sign(key, msg) {
    return crypto.createHmac('sha512', key).update(msg).digest();
}

function getSignatureKey(key, dateStamp, regionName, serviceName) {
    const kDate = sign('AWS4' + key, dateStamp);
    const kRegion = sign(kDate, regionName);
    const kService = sign(kRegion, serviceName);
    const kSigning = sign(kService, 'aws4_request');
    return kSigning;
}

function hash(data) {
    return crypto.createHash('sha512').update(data).digest('hex');
}

// Create canonical request
const url = new URL(urlString);
const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
const dateStamp = amzDate.substring(0, 8);

const canonicalUri = url.pathname;
const canonicalQuerystring = url.search.substring(1);
// Only sign x-amz-date header (browsers block setting host header)
const canonicalHeaders = `x-amz-date:${amzDate}\n`;
const signedHeaders = 'x-amz-date';
const payloadHash = hash(body);

const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

// Create string to sign
const algorithm = 'AWS4-HMAC-SHA512';
const credentialScope = `${dateStamp}/${AWS_REGION}/${AWS_SERVICE}/aws4_request`;
const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${hash(canonicalRequest)}`;

// Calculate signature
const signingKey = getSignatureKey(AWS_SECRET_ACCESS_KEY, dateStamp, AWS_REGION, AWS_SERVICE);
const signature = crypto.createHmac('sha512', signingKey).update(stringToSign).digest('hex');

// Build authorization header
const authorizationHeader = `${algorithm} Credential=${AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

// Output as JSON
console.log(JSON.stringify({
    'X-Amz-Date': amzDate,
    'Authorization': authorizationHeader
}, null, 2));
JSEOF

chmod +x "${OUTPUT_DIR}/sign-aws-request.js"
echo -e "${GREEN}✓ AWS SigV4 helper script generated${NC}"
echo ""

# Method 5: Generate .env.example file
echo -e "${BLUE}Step 5:${NC} Generating .env.example file..."
cat > "${OUTPUT_DIR}/.env.example" << 'ENVEOF'
# AWS Credentials for VDB API Authentication
# Copy this file to .env and fill in your actual credentials
# The .env file will be automatically loaded by httpyac

# AWS Access Key ID
AWS_ACCESS_KEY_ID=your_access_key_id_here

# AWS Secret Access Key
AWS_SECRET_ACCESS_KEY=your_secret_access_key_here

# AWS Region (default: us-east-1)
AWS_REGION=us-east-1

# AWS Service Name (default: vdb)
AWS_SERVICE=vdb

# API Base URL (optional - defaults in .http files)
# BASE_URL=http://localhost:8778

# For production testing
# BASE_URL=https://api.vdb.vulnetix.com
ENVEOF

echo -e "${GREEN}✓ Environment template created${NC}"
echo ""

# Method 6: Create documentation files
echo -e "${BLUE}Step 6:${NC} Generating documentation files..."

# Create POSTMAN_SETUP.md if needed
if [ ! -f "${OUTPUT_DIR}/POSTMAN_SETUP.md" ]; then
    cat > "${OUTPUT_DIR}/POSTMAN_SETUP.md" << 'PMREADMEEOF'
# Postman Collection Setup Guide

## Key Feature: AWS Signature V4 with SHA-512

The `/auth/token` endpoint uses **AWS Signature V4 authentication with SHA-512**.

**Important:** This API uses SHA-512 instead of the standard SHA-256. A pre-request script handles the signing automatically.

## Quick Setup

1. **Import:** Import `postman-collection.json` into Postman
2. **Configure:** Set collection variables (see below)
3. **Send:** Click Send on `/auth/token` - the pre-request script handles signing!

## Collection Variables

Set these in the **Variables** tab:

| Variable | Value | Example |
|----------|-------|---------|
| `awsAccessKeyId` | Your AWS Access Key | `AKIAIOSFODNN7EXAMPLE` |
| `awsSecretAccessKey` | Your AWS Secret Key | `wJalrXUtn...` (will be masked) |
| `awsRegion` | `us-east-1` | Pre-filled |
| `awsService` | `vdb` | Pre-filled |
| `baseUrl` | `http://localhost:8778` | Pre-filled |

## What the Pre-Request Script Does Automatically

When you send the `/auth/token` request, the embedded pre-request script:

✅ **Generates X-Amz-Date Header** - Current timestamp (e.g., `20250115T123456Z`)
✅ **Calculates SHA-512 Hash** - Payload and canonical request hashing
✅ **Computes HMAC-SHA512 Signature** - AWS Signature V4 with SHA-512
✅ **Adds Authorization Header** - `AWS4-HMAC-SHA512 Credential=...`

**You just click Send!**

## Verify Setup

1. Open `/auth/token` request
2. Go to **Authorization** tab
3. Should show:
   - Type: **AWS Signature**
   - AccessKey: `{{awsAccessKeyId}}`
   - SecretKey: `{{awsSecretAccessKey}}`
   - AWS Region: `{{awsRegion}}`
   - Service Name: `{{awsService}}`

## Troubleshooting

**401 Unauthorized?**
- Check AWS credentials are correct
- Verify region is `us-east-1` and service is `vdb`
- Ensure system clock is accurate (AWS requires ±5 minutes)

**Variables not working?**
- Save collection variables
- Set values in "Current Value" column, not just "Initial Value"
- Restart Postman if needed

For detailed documentation, see the full guide in this directory.
PMREADMEEOF
    echo -e "${GREEN}✓ POSTMAN_SETUP.md created${NC}"
fi

# Create README.md if it doesn't exist
if [ ! -f "${OUTPUT_DIR}/README.md" ]; then
    cat > "${OUTPUT_DIR}/README.md" << 'READMEEOF'
# Generated API Tests

Auto-generated test files from the VDB API OpenAPI specification.

## Quick Start

### Using Postman (Easiest)
1. Import `postman-collection.json`
2. Set Collection Variables: `awsAccessKeyId`, `awsSecretAccessKey`, `awsRegion`, `awsService`
3. Send the `/auth/token` request - AWS signing is automatic!

### Using httpyac (CLI)
1. Copy `.env.example` to `.env` and add your AWS credentials
2. Run: `httpyac send generated-requests.http --name getAuthToken`

### Using curl
1. Set AWS env vars: `export AWS_ACCESS_KEY_ID=...`
2. Run: `./tests/scripts/test-auth-endpoint.sh`

## Files

- **openapi.json** - OpenAPI 3.x specification
- **postman-collection.json** - Postman collection with AWS Signature V4 auth
- **generated-requests.http** - HTTP snippets with built-in AWS auth directives
- **sign-aws-request.js** - Manual signing helper for curl
- **.env.example** - Template for credentials (copy to `.env`)

## Authentication Flow

1. **Get JWT Token**: Use AWS Signature V4 to call `/auth/token`
2. **Use Token**: Include JWT in `Authorization: Bearer <token>` for protected endpoints

## Available Endpoints

1. `GET /v1/spec` - OpenAPI specification (public)
2. `GET /v1/swagger` - Swagger UI (public)
3. `GET /auth/token` - Get JWT token (AWS SigV4 auth)
4. `GET /v1/info/{id}` - CVE metadata (JWT auth)
5. `GET /v1/vuln/{id}` - CVE data (JWT auth)
6. `GET /v1/exploits/{id}` - Exploit intel (JWT auth)

## Regenerate

```bash
./tests/scripts/generate-from-oas.sh
```
READMEEOF
    echo -e "${GREEN}✓ README created${NC}"
else
    echo -e "${BLUE}Step 6:${NC} README.md already exists, skipping..."
fi
echo ""

# Summary
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Generation Complete${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "Generated files in: ${GREEN}${OUTPUT_DIR}${NC}"
echo ""
echo -e "${GREEN}Files created:${NC}"
echo -e "  • ${YELLOW}openapi.json${NC} - OpenAPI specification"
echo -e "  • ${YELLOW}postman-collection.json${NC} - Postman collection with AWS Signature V4 auth"
echo -e "  • ${YELLOW}generated-requests.http${NC} - HTTP snippets with built-in AWS auth"
echo -e "  • ${YELLOW}sign-aws-request.js${NC} - AWS SigV4 helper for curl/manual testing"
echo -e "  • ${YELLOW}.env.example${NC} - Environment template for credentials"
echo -e "  • ${YELLOW}README.md${NC} - Detailed usage instructions"
echo -e "  • ${YELLOW}POSTMAN_SETUP.md${NC} - Step-by-step Postman configuration guide"
echo ""
echo -e "${GREEN}AWS Signature V4 Authentication:${NC}"
echo -e "The /auth/token endpoint uses AWS Signature V4 - signing is automatic!"
echo ""
echo -e "${YELLOW}Option 1: Postman (Easiest - Recommended)${NC}"
echo -e "  1. Import ${YELLOW}postman-collection.json${NC} into Postman"
echo -e "  2. Set collection variables: awsAccessKeyId, awsSecretAccessKey"
echo -e "  3. Click Send - Postman auto-generates X-Amz-Date and signs the request!"
echo -e "  4. See ${YELLOW}POSTMAN_SETUP.md${NC} for detailed setup guide"
echo ""
echo -e "${YELLOW}Option 2: httpyac (CLI)${NC}"
echo -e "  1. Set environment: ${YELLOW}export AWS_ACCESS_KEY_ID=...${NC}"
echo -e "  2. Run: ${YELLOW}httpyac send ${OUTPUT_DIR}/generated-requests.http --name getAuthToken${NC}"
echo -e "  3. Or create a .env file with AWS credentials (see README)"
echo ""
echo -e "${YELLOW}Option 3: curl with helper script${NC}"
echo -e "  1. Run: ${YELLOW}./tests/scripts/test-auth-endpoint.sh${NC}"
echo -e "  2. Or manually: ${YELLOW}node ${OUTPUT_DIR}/sign-aws-request.js GET <url>${NC}"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo -e "1. Read ${YELLOW}${OUTPUT_DIR}/README.md${NC} for detailed authentication instructions"
echo -e "2. Set your AWS credentials (environment variables or .env file)"
echo -e "3. Test authentication: ${YELLOW}./tests/scripts/test-auth-endpoint.sh${NC}"
echo -e "4. Import ${YELLOW}postman-collection.json${NC} for GUI testing"
echo -e "5. Customize tests in ${YELLOW}tests/v1/${NC} directories"
echo ""
