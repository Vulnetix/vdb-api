#!/usr/bin/env bash
# Quick test of VDB API with AWS Signature V4 authentication
# This is a minimal example showing the authentication flow

set -e

BASE_URL="${1:-http://localhost:8778}"

echo "🔐 VDB API Quick Test"
echo "===================="
echo ""
echo "Base URL: $BASE_URL"
echo ""

# Check for httpyac
if ! command -v httpyac &> /dev/null; then
    echo "⚠️  httpyac not found. Installing..."
    npm install -g httpyac
fi

# Check for AWS credentials
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "❌ AWS credentials not set"
    echo ""
    echo "Please set:"
    echo "  export AWS_ACCESS_KEY_ID=your_key"
    echo "  export AWS_SECRET_ACCESS_KEY=your_secret"
    echo "  export AWS_REGION=us-east-1"
    echo "  export AWS_SERVICE=vdb"
    echo ""
    exit 1
fi

# Create a temporary .http file
TMP_FILE=$(mktemp /tmp/vdb-test.XXXXXX.http)
cat > "$TMP_FILE" << EOF
# @aws
GET ${BASE_URL}/v1/auth/token
AWS-Access-Key-Id: {{$processEnv AWS_ACCESS_KEY_ID}}
AWS-Secret-Access-Key: {{$processEnv AWS_SECRET_ACCESS_KEY}}
AWS-Region: {{$processEnv AWS_REGION}}
AWS-Service: {{$processEnv AWS_SERVICE}}
EOF

echo "✅ Credentials configured"
echo "🚀 Testing /v1/auth/token endpoint..."
echo ""

# Run the request
httpyac send "$TMP_FILE"

# Cleanup
rm -f "$TMP_FILE"

echo ""
echo "✨ Test complete!"
echo ""
echo "Next steps:"
echo "  • Save the token from the response"
echo "  • Use it with: curl -H 'Authorization: Bearer <token>' ${BASE_URL}/v1/info/CVE-2024-1234"
echo "  • Or run: ./tests/scripts/generate-from-oas.sh for full test suite"
