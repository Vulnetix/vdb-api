# VDB API Integration Tests

Comprehensive integration test suite for the Vulnetix VDB API.

## Overview

This test suite provides:
- **Organized by route**: Tests are grouped by API endpoint for easy maintenance
- **Versioned**: All tests target `/v1` API endpoints
- **Automated**: Scripts for running full test suites
- **VS Code compatible**: Uses `.http` files compatible with REST Client and Postman extensions
- **OAS-driven**: Ability to generate tests from OpenAPI specification

## Directory Structure

```
tests/
├── test.config.http          # Shared configuration (base URLs, credentials)
├── oas/                       # OpenAPI specification tests
│   └── openapi.http
├── v1/                        # API v1 tests
│   ├── auth/                  # Authentication tests
│   │   └── token.http
│   ├── info/                  # CVE information tests
│   │   └── cve-info.http
│   ├── vuln/                  # Vulnerability data tests
│   │   └── vulnerability.http
│   └── exploits/              # Exploit intelligence tests
│       └── exploit-intel.http
├── scripts/                   # Test automation scripts
│   ├── run-tests.sh          # Main test runner
│   └── generate-from-oas.sh  # Generate tests from OpenAPI
├── generated/                 # Auto-generated test files (gitignored)
└── results/                   # Test results (gitignored)
```

## Prerequisites

### Option 1: VS Code Extensions (Recommended)

Install one or more of these VS Code extensions:

1. **REST Client** by Huachao Mao
   ```
   code --install-extension humao.rest-client
   ```

2. **Postman** by Postman
   ```
   code --install-extension Postman.postman-for-vscode
   ```

3. **Thunder Client** by Thunder Client
   ```
   code --install-extension rangav.vscode-thunder-client
   ```

### Option 2: Command Line (httpyac)

```bash
# Install httpyac globally
npm install -g httpyac

# Or use via npx
npx httpyac --version
```

### Option 3: Postman Desktop

Download from: https://www.postman.com/downloads/

## Quick Start

### 1. Configure Test Environment

Edit `tests/test.config.http` and set your credentials:

```http
@baseUrl = http://localhost:8778
@orgId = YOUR_ORG_UUID_HERE
@orgSecret = YOUR_ORG_SECRET_HERE
@token = YOUR_JWT_TOKEN_HERE
```

### 2. Start Development Server

```bash
just dev
# Or: npm run dev
```

### 3. Run Tests

**Using VS Code REST Client:**
- Open any `.http` file
- Click "Send Request" above each test
- Or use keyboard shortcut: `Ctrl+Alt+R` (Windows/Linux) or `Cmd+Alt+R` (Mac)

**Using Command Line:**
```bash
# Run all tests
just test

# Run specific test file
httpyac send tests/v1/info/cve-info.http --all

# Run tests with verbose output
httpyac send tests/v1/info/cve-info.http --all --verbose
```

**Using Postman VS Code Extension:**
1. Install Postman extension in VS Code
2. Open Command Palette (`Ctrl+Shift+P`)
3. Select "Postman: Import API Specification"
4. Enter: `http://localhost:8778/v1/spec`
5. Tests will be auto-imported with the collection

## Test Workflow

### Manual Testing

1. **Get JWT Token** (`v1/auth/token.http`)
   - Generate AWS SigV4 signature (see AUTH.md)
   - Send request to get JWT token
   - Copy token to `test.config.http`

2. **Run Endpoint Tests**
   - Open test file for the endpoint you want to test
   - Execute individual tests or run all

3. **Review Results**
   - Check response status codes
   - Validate response structure
   - Verify data correctness

### Automated Testing

Run the full test suite:

```bash
# Run all tests
./tests/scripts/run-tests.sh

# Run tests against production
./tests/scripts/run-tests.sh production

# View results
cat tests/results/*.json
```

## Generating Tests from OpenAPI

### Method 1: Auto-generate Test Suite

```bash
# Generate tests from running server
just test:generate

# Or run script directly
./tests/scripts/generate-from-oas.sh

# Specify custom OAS URL
./tests/scripts/generate-from-oas.sh https://api.vdb.vulnetix.com/v1/spec
```

This generates:
- `tests/generated/openapi.json` - Downloaded OAS spec
- `tests/generated/postman-collection.json` - Postman collection
- `tests/generated/generated-requests.http` - Basic HTTP requests

### Method 2: Import to Postman VS Code Extension

1. Open VS Code
2. Install Postman extension
3. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
4. Select **"Postman: Import API Specification"**
5. Choose **"Import from URL"**
6. Enter: `http://localhost:8778/v1/spec` (or production URL)
7. Postman will:
   - Import all endpoints
   - Generate example requests
   - Create test scripts
   - Set up environment variables

**Configure Postman Environment:**
1. Click on Postman icon in sidebar
2. Go to "Environments"
3. Create new environment "VDB API Local"
4. Add variables:
   ```
   baseUrl: http://localhost:8778
   apiVersion: v1
   token: <your-jwt-token>
   ```

**Run Postman Collection:**
1. Open the imported collection
2. Right-click collection → "Run Collection"
3. Select environment
4. Click "Run VDB API"

### Method 3: Generate Using CLI Tools

```bash
# Install openapi-to-postmanv2
npm install -g openapi-to-postmanv2

# Generate Postman collection
openapi2postmanv2 \
  -s http://localhost:8778/v1/spec \
  -o tests/generated/postman-collection.json \
  -p

# Import into Postman or use with newman
newman run tests/generated/postman-collection.json \
  --environment tests/postman-environment.json
```

### Method 4: Generate HTTP Files from OAS

```bash
# Using oas-to-har (generates HAR, convert to HTTP)
npm install -g oas-to-har

# Fetch OAS and convert
curl http://localhost:8778/v1/spec > openapi.json
oas-to-har openapi.json > requests.har

# Or use online converters:
# https://editor.swagger.io - Import OAS, generate client code
# https://openapi.tools - Various OAS tooling
```

## Test Configuration

### Environment Variables

Tests support multiple environments via `test.config.http`:

```http
# Local Development
@baseUrl = http://localhost:8778

# Staging
# @baseUrl = https://staging-api.vdb.vulnetix.com

# Production
# @baseUrl = https://api.vdb.vulnetix.com
```

### Authentication

Tests require JWT tokens obtained from `/v1/auth/token`:

1. Generate AWS SigV4 signature (see `docs/AUTH.md`)
2. Exchange for JWT token
3. Use token in `Authorization: Bearer {{token}}` headers

### Test Assertions

Tests use embedded JavaScript for assertions:

```http
GET {{baseUrl}}/v1/info/CVE-2024-1234
Authorization: Bearer {{token}}

> {%
  client.test("Response is valid", function() {
    client.assert(response.status === 200, "Status is 200");
    client.assert(response.body.matched === true, "CVE matched");
  });
%}
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: API Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm install -g httpyac

      - name: Start API server
        run: |
          npm install
          npm run dev &
          sleep 10

      - name: Run integration tests
        run: ./tests/scripts/run-tests.sh

      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: test-results
          path: tests/results/
```

## Writing New Tests

### 1. Create Test File

```bash
# Create new test file
touch tests/v1/myendpoint/my-test.http
```

### 2. Add Configuration Import

```http
###
# My Endpoint Tests
###

< ../../test.config.http
```

### 3. Write Tests

```http
###
# Test 1: Basic request
GET {{baseUrl}}/{{apiVersion}}/myendpoint
Authorization: Bearer {{token}}

###
# Test 2: With assertions
# @name myTest
GET {{baseUrl}}/{{apiVersion}}/myendpoint/123
Authorization: Bearer {{token}}

> {%
  client.test("Test passes", function() {
    client.assert(response.status === 200, "Response is OK");
  });
%}
```

### 4. Run Your Tests

```bash
# Using httpyac
httpyac send tests/v1/myendpoint/my-test.http --all

# Or open in VS Code REST Client
code tests/v1/myendpoint/my-test.http
```

## Best Practices

1. **Organize by endpoint**: Keep related tests together
2. **Use shared config**: Leverage `test.config.http` for common variables
3. **Add assertions**: Validate responses with embedded scripts
4. **Test error cases**: Include tests for 401, 404, 400, etc.
5. **Document tests**: Add comments explaining what each test does
6. **Version your tests**: Match test versions to API versions
7. **Keep tokens fresh**: JWT tokens expire in 15 minutes
8. **Use descriptive names**: Name tests clearly: `# Test 1: Get CVE by ID`

## Troubleshooting

### Tests Failing with 401

- Check that JWT token is valid and not expired
- Verify token is correctly set in `test.config.http`
- Re-authenticate to get a fresh token

### Server Not Responding

- Ensure development server is running: `just dev`
- Check server is on correct port (8778)
- Verify `@baseUrl` in `test.config.http`

### httpyac Not Found

```bash
npm install -g httpyac
# Or use npx
npx httpyac send tests/v1/info/cve-info.http
```

### VS Code Extension Not Working

- Verify extension is installed: `code --list-extensions`
- Reload VS Code: `Ctrl+Shift+P` → "Reload Window"
- Check Output panel for error messages

## Resources

- [VS Code REST Client Docs](https://marketplace.visualstudio.com/items?itemName=humao.rest-client)
- [httpyac Documentation](https://httpyac.github.io/)
- [Postman VS Code Extension](https://marketplace.visualstudio.com/items?itemName=Postman.postman-for-vscode)
- [OpenAPI Tools](https://openapi.tools/)
- [VDB API Documentation](../README.md)
