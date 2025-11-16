#!/usr/bin/env bash
# Test the /v1/auth/token endpoint with AWS SigV4 authentication
# This script demonstrates how to use the sign-aws-request.js helper

set -e

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}VDB API Authentication Test${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SIGNER="${PROJECT_ROOT}/tests/generated/sign-aws-request.js"
BASE_URL="${1:-http://localhost:8778}"
AUTH_ENDPOINT="${BASE_URL}/v1/auth/token"

echo -e "${YELLOW}API Base URL:${NC} ${BASE_URL}"
echo -e "${YELLOW}Auth Endpoint:${NC} ${AUTH_ENDPOINT}"
echo ""

# Check for required tools
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is required but not installed${NC}"
    echo -e "Install from: https://nodejs.org/"
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is required but not installed${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Warning: jq is not installed (optional, for pretty output)${NC}"
    echo -e "Install with: ${YELLOW}brew install jq${NC} or ${YELLOW}apt-get install jq${NC}"
    echo ""
fi

# Check for AWS credentials
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo -e "${YELLOW}⚠ AWS credentials not set in environment${NC}"
    echo ""
    echo -e "Please set your AWS credentials:"
    echo -e "  ${YELLOW}export AWS_ACCESS_KEY_ID=your_access_key${NC}"
    echo -e "  ${YELLOW}export AWS_SECRET_ACCESS_KEY=your_secret_key${NC}"
    echo -e "  ${YELLOW}export AWS_REGION=us-east-1${NC} (optional)"
    echo -e "  ${YELLOW}export AWS_SERVICE=vdb${NC} (optional)"
    echo ""
    echo -e "Or run this script with test credentials:"
    echo -e "  ${YELLOW}AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test ./test-auth-endpoint.sh${NC}"
    echo ""
    exit 1
fi

# Check if signer exists
if [ ! -f "$SIGNER" ]; then
    echo -e "${RED}Error: AWS signer not found at ${SIGNER}${NC}"
    echo -e "Run: ${YELLOW}./tests/scripts/generate-from-oas.sh${NC} first"
    exit 1
fi

# Generate AWS Signature
echo -e "${BLUE}Step 1:${NC} Generating AWS Signature V4..."
HEADERS_JSON=$(node "$SIGNER" GET "$AUTH_ENDPOINT")

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Failed to generate AWS signature${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Signature generated${NC}"
echo ""

# Extract headers
AMZ_DATE=$(echo "$HEADERS_JSON" | grep -o '"X-Amz-Date": "[^"]*"' | cut -d'"' -f4)
AUTH_HEADER=$(echo "$HEADERS_JSON" | grep -o '"Authorization": "[^"]*"' | sed 's/"Authorization": "//' | sed 's/"$//')

echo -e "${YELLOW}Generated Headers:${NC}"
echo -e "  X-Amz-Date: ${AMZ_DATE}"
echo -e "  Authorization: ${AUTH_HEADER:0:60}..."
echo ""

# Make request
echo -e "${BLUE}Step 2:${NC} Making authenticated request to ${AUTH_ENDPOINT}..."
echo ""

HTTP_CODE=$(curl -w "%{http_code}" -s -o /tmp/vdb-auth-response.json \
    -X GET "$AUTH_ENDPOINT" \
    -H "X-Amz-Date: $AMZ_DATE" \
    -H "Authorization: $AUTH_HEADER" \
    -H "Content-Type: application/json")

echo -e "${YELLOW}HTTP Status Code:${NC} ${HTTP_CODE}"
echo ""

# Check response
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Authentication successful!${NC}"
    echo ""
    echo -e "${YELLOW}Response:${NC}"
    if command -v jq &> /dev/null; then
        cat /tmp/vdb-auth-response.json | jq .
    else
        cat /tmp/vdb-auth-response.json
    fi
    echo ""

    # Extract and save token
    if command -v jq &> /dev/null; then
        TOKEN=$(cat /tmp/vdb-auth-response.json | jq -r '.token // .accessToken // empty')
        if [ -n "$TOKEN" ]; then
            echo -e "${GREEN}JWT Token extracted:${NC}"
            echo "$TOKEN"
            echo ""
            echo -e "${YELLOW}Token saved to:${NC} /tmp/vdb-jwt-token.txt"
            echo "$TOKEN" > /tmp/vdb-jwt-token.txt
            echo ""
            echo -e "${GREEN}You can now use this token for protected endpoints:${NC}"
            echo -e "  ${YELLOW}export VDB_TOKEN=\$(cat /tmp/vdb-jwt-token.txt)${NC}"
            echo -e "  ${YELLOW}curl -H \"Authorization: Bearer \$VDB_TOKEN\" ${BASE_URL}/v1/info/CVE-2024-1234${NC}"
        fi
    fi
elif [ "$HTTP_CODE" = "401" ]; then
    echo -e "${RED}✗ Authentication failed (401 Unauthorized)${NC}"
    echo ""
    echo -e "${YELLOW}Response:${NC}"
    cat /tmp/vdb-auth-response.json
    echo ""
    echo -e "${YELLOW}Possible causes:${NC}"
    echo -e "  • Invalid AWS credentials"
    echo -e "  • Signature mismatch (check time sync)"
    echo -e "  • Incorrect region or service name"
    exit 1
elif [ "$HTTP_CODE" = "403" ]; then
    echo -e "${RED}✗ Forbidden (403)${NC}"
    echo ""
    echo -e "${YELLOW}Response:${NC}"
    cat /tmp/vdb-auth-response.json
    echo ""
    echo -e "${YELLOW}Possible causes:${NC}"
    echo -e "  • Access key not authorized for this organization"
    echo -e "  • API endpoint permissions issue"
    exit 1
else
    echo -e "${RED}✗ Request failed with status ${HTTP_CODE}${NC}"
    echo ""
    echo -e "${YELLOW}Response:${NC}"
    cat /tmp/vdb-auth-response.json
    echo ""
    exit 1
fi

# Cleanup
rm -f /tmp/vdb-auth-response.json

echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Test Complete${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
