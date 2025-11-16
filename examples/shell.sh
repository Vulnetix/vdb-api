#!/bin/bash
# VDB API Testing Console - AWS SigV4 Authentication Example

# Step 1: Set your Organization credentials
export VVD_ORG="f7c11fc1-d422-4242-a05e-ea3e747b07bc"  # Organization UUID (used as access key)
export VVD_SECRET="ldCTA9jeOLtHdkByhLl8DyIIo5bd2Meb6IA4rATn0KCanfzU2s97CTBQ7bxtYTIs"  # Organization Secret (64 chars)
export VVD_ACCESS_KEY="${VVD_ORG}"  # Access key is the Organization UUID

# Step 2: Generate timestamp for request signing
AMZ_DATE=$(date -u +"%Y%m%dT%H%M%SZ")  # ISO 8601 format: 20240101T120000Z
DATE_STAMP=$(date -u +"%Y%m%d")        # Date stamp: 20240101
REGION="us-east-1"
SERVICE="vdb"

# Step 3: Create canonical request for signing
METHOD="GET"
CANONICAL_URI="/v1/auth/token"
CANONICAL_QUERYSTRING=""
CANONICAL_HEADERS="x-amz-date:${AMZ_DATE}\n"
SIGNED_HEADERS="x-amz-date"

# Calculate empty payload hash
PAYLOAD_HASH=$(echo -n "" | openssl dgst -sha512 -hex | sed "s/^.* //")

# Build canonical request string
CANONICAL_REQUEST="${METHOD}\n${CANONICAL_URI}\n${CANONICAL_QUERYSTRING}\n${CANONICAL_HEADERS}\n${SIGNED_HEADERS}\n${PAYLOAD_HASH}"

# Step 4: Create string to sign
ALGORITHM="AWS4-HMAC-SHA512"
CREDENTIAL_SCOPE="${DATE_STAMP}/${REGION}/${SERVICE}/aws4_request"
REQUEST_HASH=$(echo -n "${CANONICAL_REQUEST}" | openssl dgst -sha512 -hex | sed "s/^.* //")
STRING_TO_SIGN="${ALGORITHM}\n${AMZ_DATE}\n${CREDENTIAL_SCOPE}\n${REQUEST_HASH}"

# Step 5: Calculate AWS SigV4 signature using openssl
kDate=$(echo -n "${DATE_STAMP}" | openssl dgst -sha512 -hmac "AWS4${VVD_SECRET}" -binary)
kRegion=$(echo -n "${REGION}" | openssl dgst -sha512 -hmac "${kDate}" -binary)
kService=$(echo -n "${SERVICE}" | openssl dgst -sha512 -hmac "${kRegion}" -binary)
kSigning=$(echo -n "aws4_request" | openssl dgst -sha512 -hmac "${kService}" -binary)
SIGNATURE=$(echo -n "${STRING_TO_SIGN}" | openssl dgst -sha512 -hmac "${kSigning}" -hex | sed "s/^.* //")

# Step 6: Build Authorization header
AUTHORIZATION="${ALGORITHM} Credential=${VVD_ACCESS_KEY}/${CREDENTIAL_SCOPE}, SignedHeaders=${SIGNED_HEADERS}, Signature=${SIGNATURE}"

# Step 7: Exchange signed request for JWT token
echo "Requesting JWT token from /v1/auth/token"
JWT_RESPONSE=$(curl -s -X GET "https://api.vdb.vulnetix.com/v1/auth/token" \
  -H "Authorization: ${AUTHORIZATION}" \
  -H "X-Amz-Date: ${AMZ_DATE}")

# Expected response format:
# {
#   "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
#   "iss": "urn:vulnetix:vdb",
#   "sub": "urn:uuid:12345678-1234-1234-1234-123456789abc",
#   "exp": 1234567890
# }

# Save JWT token to variable
export VVD_JWT=$(echo "${JWT_RESPONSE}" | jq -r '.token')
echo "JWT token obtained (expires in 15 minutes): ${VVD_JWT:0:50}..."

# Step 8: Make authenticated API request
echo "Making GET request to /ecosystems..."
curl -X GET "https://api.vdb.vulnetix.com/v1/ecosystems" \
  -H "Authorization: Bearer ${VVD_JWT}" \
  -H "Content-Type: application/json" | jq
