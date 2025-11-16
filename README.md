# Vulnetix VDB API

> Cloudflare Workers API for Vulnerability Database Management

## Overview

This is a **Cloudflare Workers API-only project** built with [Hono](https://hono.dev/) framework. It provides comprehensive vulnerability management, security analysis, and DevSecOps automation through a unified API.

### Key Features

- **Unified CVE Metadata**: Aggregated data from MITRE, NIST NVD, VulnCheck, CISA KEV, GHSA, OSV, and EUVD
- **Exploit Intelligence**: Real-world exploit tracking from ExploitDB, Metasploit, Nuclei, CrowdSec, and GitHub
- **CVEListV5 Format**: Standards-compliant vulnerability records with enrichment
- **AWS SigV4 Authentication**: Enterprise-grade authentication with JWT tokens
- **Cloudflare Infrastructure**: Built on Workers, Hyperdrive (PostgreSQL), KV Cache, R2 Storage, and Queues

## Architecture

This is a **pure API project** - there is no frontend code. The worker is deployed to Cloudflare Workers and uses:

- **Hono**: Fast, lightweight web framework
- **Prisma**: Type-safe database ORM with PostgreSQL via Hyperdrive
- **TypeScript**: Full type safety
- **Wrangler**: Cloudflare's CLI tool for development and deployment

## Prerequisites

- **Node.js** v20+ (LTS recommended)
- **Yarn** v4+ (uses Yarn Berry with PnP)
- **PostgreSQL** 14+ (local or cloud)
- **Cloudflare Account** with Workers, KV, R2, Queues, and Hyperdrive configured
- **just** command runner (optional but recommended): `brew install just` or `cargo install just`

## Quick Start

### 1. Install Dependencies

```bash
# Using just (recommended)
just install

# Or using yarn directly
yarn install
```

### 2. Configure Environment

Copy the example environment file and configure your local database:

```bash
cp .env.example .env
# Edit .env and set your DATABASE_URL
```

### 3. Generate Types

Generate TypeScript types for Cloudflare Workers and Prisma:

```bash
# Using just
just types

# Or using npm scripts
npx wrangler types
npx prisma generate
```

### 4. Run Development Server

```bash
# Using just
just dev

# Or using npm/yarn
npm run dev
# or
yarn dev

# The API will be available at http://localhost:8778
```

## Development Workflow

### Available Commands

Use `just` for a streamlined development experience:

```bash
just help              # Show all available commands
just install           # Install dependencies
just types             # Generate TypeScript types (Wrangler + Prisma)
just dev               # Run development server with live reload
just build             # Validate production build (dry-run)
just deploy            # Deploy to production (requires GitOps approval)
just logs              # Tail production logs
just whoami            # Check Cloudflare authentication
just clean             # Remove temporary files
```

### Without `just`

You can also use npm/yarn scripts directly:

```bash
yarn install           # Install dependencies
npm run dev            # Development server
npm run build          # Validate build
npm run deploy         # Deploy to production
```

## Project Structure

```
vdb-api/
├── _worker.ts                 # Main Worker entry point
├── api/                       # API route handlers
│   ├── auth.ts               # AWS SigV4 authentication
│   ├── info.ts               # CVE metadata endpoint
│   ├── vuln.ts               # Vulnerability data (CVEListV5)
│   ├── exploits.ts           # Exploit intelligence
│   ├── oas.ts                # OpenAPI specification
│   ├── search.ts             # Search functionality
│   └── [[catchall]].ts       # Catch-all handler
├── src/                       # Source code
│   ├── cache/                # Caching layer (KV + PostgreSQL)
│   ├── middleware/           # Authentication, rate limiting
│   ├── services/             # Business logic
│   └── shared/               # Shared utilities
├── scheduled/                 # Cron job handlers
├── schemas/                   # JSON schemas
├── prisma/                    # Prisma schema and migrations
├── wrangler.toml             # Cloudflare Workers configuration
├── tsconfig.json             # TypeScript configuration
├── justfile                  # Development commands
└── package.json              # Dependencies and scripts
```

## API Endpoints

All API endpoints are versioned under `/v1` for stability and future compatibility.

### Public Endpoints

- `GET /v1/spec` - OpenAPI specification (JSON)
- `GET /v1/spec/ui` - Interactive documentation

### Authentication

- `GET /v1/auth/token` - Exchange SigV4-signed request for JWT token

### Protected Endpoints (Require JWT)

#### CVE Information & Vulnerability Data

- `GET /v1/info/{identifier}` - CVE metadata and data source information
- `GET /v1/vuln/{identifier}` - Vulnerability records in CVEListV5 format
- `GET /v1/exploits/{identifier}` - Exploit intelligence and sightings

#### Product/Package API

- `GET /v1/product/{name}` - Product information by package name with pagination
- `GET /v1/product/{name}/{version}` - Product information for specific version
- `GET /v1/product/{name}/{version}/{ecosystem}` - Product information for specific version and ecosystem
- `GET /v1/ecosystems` - List all ecosystems with package counts
- `GET /v1/{package}/versions` - All versions for a package with pagination
- `GET /v1/{package}/vulns` - All vulnerabilities affecting a package with version mapping

## Error Handling

### Overview

The API uses standard HTTP status codes and returns consistent JSON error responses. All errors include a `success: false` field and descriptive `error` message. Understanding these error patterns will help you build robust client applications.

### Error Response Format

All error responses follow this structure:

```json
{
  "success": false,
  "error": "Error category or message",
  "details": "Additional context (optional)"
}
```

### HTTP Status Codes

| Status Code | Meaning | When It Occurs |
|------------|---------|----------------|
| `400` | Bad Request | Missing or invalid parameters |
| `401` | Unauthorized | Authentication failed or token invalid/expired |
| `403` | Forbidden | Organization is inactive or blocked |
| `404` | Not Found | Resource does not exist |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Unexpected server error |

### Authentication Errors (401)

#### Missing Authentication

**Request:**
```bash
curl https://api.vdb.vulnetix.com/v1/info/CVE-2024-1234
```

**Response:**
```json
{
  "success": false,
  "error": "Missing Authorization header. Please provide a Bearer token."
}
```

**How to Fix:** Include the `Authorization: Bearer <token>` header in your request.

---

#### Invalid Authorization Format

**Request:**
```bash
curl https://api.vdb.vulnetix.com/v1/info/CVE-2024-1234 \
  -H "Authorization: InvalidFormat"
```

**Response:**
```json
{
  "success": false,
  "error": "Invalid Authorization header format. Expected \"Bearer <token>\"."
}
```

**How to Fix:** Use the correct format: `Authorization: Bearer YOUR_JWT_TOKEN`

---

#### Token Expired

**Response:**
```json
{
  "success": false,
  "error": "Token has expired. Please obtain a new token from /v1/auth/token."
}
```

**How to Fix:** 
1. Request a new token from `/v1/auth/token` using AWS SigV4 authentication
2. Tokens expire after 15 minutes
3. Implement automatic token refresh in your client

**Example Token Refresh:**
```python
import time
from datetime import datetime, timedelta

class VDBClient:
    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = None
        self.token_expiry = None
    
    def get_token(self):
        """Get valid token, refreshing if needed"""
        if self.token and self.token_expiry > datetime.now():
            return self.token
        
        # Request new token with SigV4 signature
        response = self._request_token()  # Your SigV4 implementation
        self.token = response['token']
        self.token_expiry = datetime.fromtimestamp(response['exp'])
        return self.token
```

---

#### Invalid Token Signature

**Response:**
```json
{
  "success": false,
  "error": "Invalid token signature"
}
```

**How to Fix:** The token has been tampered with or is from a different environment. Request a new token.

---

#### Invalid SigV4 Signature (Token Exchange)

**Request to `/v1/auth/token`:**
```json
{
  "success": false,
  "error": "Invalid signature"
}
```

**How to Fix:**
1. Verify your AWS Access Key ID and Secret Access Key
2. Ensure proper SigV4 signature calculation
3. Check that the `X-Amz-Date` header is current (within 15 minutes)
4. Verify the `Authorization` header format: `AWS4-HMAC-SHA512 Credential=...`

See `examples/` directory for SigV4 implementation examples in multiple languages.

---

#### Inactive Credentials

**Response:**
```json
{
  "success": false,
  "error": "Credentials are inactive"
}
```

**How to Fix:** Contact Vulnetix support to reactivate your organization credentials.

---

### Rate Limiting Errors (429)

The API enforces two types of rate limits:
- **Per-minute limit:** Maximum requests per minute
- **Per-week limit:** Maximum requests per week (resets Sunday 00:00 UTC)

#### Rate Limit Response

**Response:**
```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "details": "Too many requests. Limit: 60 requests per minute. Try again in 42 seconds."
}
```

**Headers:**
```
RateLimit-MinuteLimit: 60
RateLimit-WeekLimit: 10000
RateLimit-Remaining: 0
RateLimit-Reset: 42
```

**How to Fix:**
1. Implement exponential backoff
2. Monitor `RateLimit-Remaining` header
3. Wait for `RateLimit-Reset` seconds before retrying
4. Consider caching responses

**Example Rate Limit Handler:**
```javascript
async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Authorization': `Bearer ${token}`,
      ...options.headers
    }
  });

  // Check rate limit headers
  const remaining = response.headers.get('RateLimit-Remaining');
  const reset = response.headers.get('RateLimit-Reset');

  if (response.status === 429) {
    const retryAfter = parseInt(reset) || 60;
    console.log(`Rate limited. Retrying in ${retryAfter} seconds...`);
    
    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
    return apiRequest(url, options); // Retry
  }

  if (remaining !== 'unlimited' && parseInt(remaining) < 10) {
    console.warn(`Rate limit warning: ${remaining} requests remaining`);
  }

  return response;
}
```

---

#### Weekly Rate Limit

**Response:**
```json
{
  "success": false,
  "error": "Weekly rate limit exceeded",
  "details": "Weekly quota exceeded. Limit: 10000 requests per week. Resets in 48 hours."
}
```

**How to Fix:** 
1. Wait until Sunday 00:00 UTC for quota reset
2. Contact Vulnetix to upgrade your plan
3. Optimize queries to reduce request volume

---

### Resource Not Found Errors (404)

#### CVE/Vulnerability Not Found

**Response:**
```json
{
  "error": "Vulnerability not found",
  "identifier": "CVE-2024-99999",
  "details": "No data sources returned results",
  "sourcesAttempted": ["mitre", "nist-nvd", "osv"]
}
```

**How to Fix:**
1. Verify the CVE ID format (e.g., `CVE-2024-1234`)
2. Check if the vulnerability exists in public databases
3. The API attempts to fetch from multiple sources; if none have data, it returns 404

---

#### Organization Not Found

**Response:**
```json
{
  "success": false,
  "error": "Organization not found"
}
```

**How to Fix:** Your organization credentials are invalid. Contact Vulnetix support.

---

### Bad Request Errors (400)

#### Missing Parameter

**Response:**
```json
{
  "error": "Missing vulnerability ID"
}
```

**How to Fix:** Include the required parameter in your request path.

**Example:**
```bash
# Wrong
curl https://api.vdb.vulnetix.com/v1/info/

# Correct
curl https://api.vdb.vulnetix.com/v1/info/CVE-2024-1234
```

---

#### Invalid Parameter Format

**Response:**
```json
{
  "error": "Unknown exploit type: invalid-type"
}
```

**How to Fix:** Use valid parameter values as documented in the API specification.

---

### Server Errors (500)

#### Internal Server Error

**Response:**
```json
{
  "success": false,
  "error": "Failed to fetch CVE information",
  "details": "Database connection timeout"
}
```

**How to Fix:**
1. Retry the request with exponential backoff
2. If the error persists, contact Vulnetix support
3. Check API status page for ongoing incidents

**Example Retry Logic:**
```python
import time
import requests

def retry_with_backoff(func, max_retries=3, base_delay=1):
    """Retry function with exponential backoff"""
    for attempt in range(max_retries):
        try:
            response = func()
            
            # Don't retry client errors (4xx)
            if 400 <= response.status_code < 500:
                return response
            
            # Retry server errors (5xx)
            if response.status_code >= 500:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    print(f"Server error. Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
            
            return response
            
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                print(f"Request failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)
            else:
                raise
    
    raise Exception("Max retries exceeded")

# Usage
response = retry_with_backoff(
    lambda: requests.get(
        'https://api.vdb.vulnetix.com/v1/info/CVE-2024-1234',
        headers={'Authorization': f'Bearer {token}'}
    )
)
```

---

### Best Practices for Error Handling

#### 1. **Always Check HTTP Status Codes**

```javascript
const response = await fetch(url, {
  headers: { 'Authorization': `Bearer ${token}` }
});

if (!response.ok) {
  const error = await response.json();
  console.error(`API Error [${response.status}]:`, error);
  
  // Handle specific status codes
  switch (response.status) {
    case 401:
      // Refresh token
      token = await refreshToken();
      break;
    case 429:
      // Rate limited - wait and retry
      const resetTime = response.headers.get('RateLimit-Reset');
      await sleep(parseInt(resetTime) * 1000);
      break;
    case 500:
      // Server error - retry with backoff
      await retryWithBackoff();
      break;
    default:
      throw new Error(error.error);
  }
}

const data = await response.json();
```

#### 2. **Monitor Rate Limit Headers**

Always check rate limit headers on successful responses to avoid hitting limits:

```python
import requests

def check_rate_limits(response):
    """Monitor rate limit headers"""
    remaining = response.headers.get('RateLimit-Remaining')
    reset = response.headers.get('RateLimit-Reset')
    
    if remaining != 'unlimited':
        remaining_count = int(remaining)
        
        if remaining_count < 10:
            print(f"⚠️  Warning: Only {remaining_count} requests remaining")
            print(f"   Resets in {reset} seconds")
        
        # Implement adaptive rate limiting
        if remaining_count < 5:
            time.sleep(2)  # Slow down requests
```

#### 3. **Implement Token Refresh**

Tokens expire after 15 minutes. Implement automatic refresh:

```typescript
class VDBClient {
  private token: string | null = null;
  private tokenExpiry: number = 0;

  async getValidToken(): Promise<string> {
    // Refresh if expired or expires in <1 minute
    if (!this.token || Date.now() / 1000 > this.tokenExpiry - 60) {
      await this.refreshToken();
    }
    return this.token!;
  }

  async refreshToken(): Promise<void> {
    const response = await this.requestTokenWithSigV4();
    const data = await response.json();
    
    this.token = data.token;
    this.tokenExpiry = data.exp;
  }

  async apiRequest(endpoint: string): Promise<Response> {
    const token = await this.getValidToken();
    
    const response = await fetch(`https://api.vdb.vulnetix.com${endpoint}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    // Handle token expiration
    if (response.status === 401) {
      const error = await response.json();
      if (error.error.includes('expired')) {
        // Force refresh and retry
        await this.refreshToken();
        return this.apiRequest(endpoint);
      }
    }

    return response;
  }
}
```

#### 4. **Cache Responses**

Reduce API calls and avoid rate limits by caching responses:

```python
from functools import lru_cache
from datetime import datetime, timedelta

class VDBCache:
    def __init__(self):
        self.cache = {}
    
    def get(self, key):
        if key in self.cache:
            data, expiry = self.cache[key]
            if datetime.now() < expiry:
                return data
            del self.cache[key]
        return None
    
    def set(self, key, value, ttl_seconds=900):
        expiry = datetime.now() + timedelta(seconds=ttl_seconds)
        self.cache[key] = (value, expiry)

cache = VDBCache()

def get_cve_info(cve_id):
    # Check cache first
    cached = cache.get(f'cve:{cve_id}')
    if cached:
        return cached
    
    # Fetch from API
    response = requests.get(
        f'https://api.vdb.vulnetix.com/v1/info/{cve_id}',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    if response.status_code == 200:
        data = response.json()
        cache.set(f'cve:{cve_id}', data, ttl_seconds=900)
        return data
    
    raise Exception(f"API error: {response.status_code}")
```

#### 5. **Log Errors with Context**

Include request details in error logs for debugging:

```go
func handleAPIError(resp *http.Response, endpoint string) error {
    var errResponse struct {
        Success bool   `json:"success"`
        Error   string `json:"error"`
        Details string `json:"details,omitempty"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&errResponse); err != nil {
        return fmt.Errorf("failed to decode error response: %w", err)
    }
    
    // Log with context
    log.Printf("[API Error] Status: %d, Endpoint: %s, Error: %s, Details: %s",
        resp.StatusCode,
        endpoint,
        errResponse.Error,
        errResponse.Details,
    )
    
    return fmt.Errorf("API error (%d): %s", resp.StatusCode, errResponse.Error)
}
```

---

### Error Reference by Endpoint

#### `/v1/auth/token`

| Status | Error | Cause | Solution |
|--------|-------|-------|----------|
| 401 | Missing or invalid Authorization header | No `Authorization` header or wrong format | Use `AWS4-HMAC-SHA512` SigV4 signature |
| 401 | Invalid credentials | Access key not found | Verify access key ID |
| 401 | Credentials are inactive | Organization disabled | Contact support |
| 401 | Invalid signature | SigV4 signature mismatch | Check secret key and signature calculation |
| 500 | Server configuration error | `JWT_SECRET` not set | Contact support |

#### `/v1/info/:identifier`

| Status | Error | Cause | Solution |
|--------|-------|-------|----------|
| 401 | Authentication errors | See Authentication Errors | Provide valid Bearer token |
| 429 | Rate limit exceeded | Too many requests | Wait for rate limit reset |
| 500 | Failed to fetch CVE information | Database or processing error | Retry with backoff |

#### `/v1/vuln/:identifier`

| Status | Error | Cause | Solution |
|--------|-------|-------|----------|
| 400 | Missing vulnerability ID | No identifier in path | Include CVE ID in URL |
| 404 | Vulnerability not found | CVE doesn't exist or no data | Verify CVE ID exists |
| 401 | Authentication errors | See Authentication Errors | Provide valid Bearer token |
| 429 | Rate limit exceeded | Too many requests | Wait for rate limit reset |
| 500 | Failed to generate CVEListV5 format | Processing error | Retry with backoff |

#### `/v1/exploits/:identifier`

| Status | Error | Cause | Solution |
|--------|-------|-------|----------|
| 400 | Missing vulnerability identifier | No identifier in path | Include identifier in URL |
| 401 | Authentication errors | See Authentication Errors | Provide valid Bearer token |
| 429 | Rate limit exceeded | Too many requests | Wait for rate limit reset |
| 500 | Failed to fetch exploit information | Database error | Retry with backoff |

#### `/v1/product/:name`

| Status | Error | Cause | Solution |
|--------|-------|-------|----------|
| 401 | Authentication errors | See Authentication Errors | Provide valid Bearer token |
| 429 | Rate limit exceeded | Too many requests | Wait for rate limit reset |
| 500 | Internal Server Error | Database error | Retry with backoff |

---

## Configuration

### Wrangler Configuration (`wrangler.toml`)

The project uses separate configurations for development and production:

**Development (default):**
- Local PostgreSQL via Hyperdrive
- Local KV and R2 bindings
- `LOG_LEVEL=DEBUG`

**Production (`--env production`):**
- Production Hyperdrive connection
- Production KV, R2, and Queue bindings
- Custom domain: `api.vdb.vulnetix.com`
- `LOG_LEVEL=WARNING`

### Environment Variables

Key environment variables (set in `wrangler.toml` or `.env`):

- `DATABASE_URL` - PostgreSQL connection string (local dev only)
- `LOG_LEVEL` - Logging verbosity (`TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`)
- `REDIS_URL` - Redis URL (dev only, not used in production)

Production-specific variables are configured in Cloudflare dashboard as secrets.

## Database

The project uses **Prisma** with **PostgreSQL** via Cloudflare Hyperdrive for connection pooling:

```bash
# Generate Prisma Client
npx prisma generate

# Run migrations (local)
npx prisma migrate dev

# Apply migrations (production)
npx prisma migrate deploy

# Open Prisma Studio
npx prisma studio
```

### Hyperdrive Configuration

Hyperdrive is configured in `wrangler.toml`:

```toml
[[hyperdrive]]
binding = "vdb"
id = "5f6d92ae237b4cfab6e4e004682212ec"
localConnectionString = "postgresql://postgres:postgres@127.0.0.1:5432/vdb"
```

## Testing

The project includes a comprehensive integration test suite organized by API endpoint.

### Quick Start

```bash
# Install test dependencies
just test-install

# Configure test credentials in tests/test.config.http
# Edit and set: @orgId, @orgSecret, @token

# Run all integration tests
just test

# Run tests with verbose output
just test-verbose

# Run tests against production
just test-prod
```

### Test Structure

```
tests/
├── test.config.http          # Shared configuration
├── oas/openapi.http         # OpenAPI spec tests
├── v1/
│   ├── auth/token.http      # Authentication tests
│   ├── info/cve-info.http   # CVE info tests
│   ├── vuln/vulnerability.http  # Vulnerability data tests
│   └── exploits/exploit-intel.http  # Exploit intel tests
├── scripts/
│   ├── run-tests.sh         # Test runner
│   └── generate-from-oas.sh # OAS test generator
└── README.md                # Detailed test documentation
```

### Using VS Code Extensions

**Option 1: REST Client Extension**

```bash
# Install REST Client extension
code --install-extension humao.rest-client

# Open any .http file in tests/ directory
# Click "Send Request" above each test
# Or use: Ctrl+Alt+R (Windows/Linux), Cmd+Alt+R (Mac)
```

**Option 2: Postman Extension**

```bash
# Install Postman extension
code --install-extension Postman.postman-for-vscode

# Import OpenAPI spec:
# 1. Open Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
# 2. Select "Postman: Import API Specification"
# 3. Choose "Import from URL"
# 4. Enter: http://localhost:8778/v1/spec
# 5. Tests auto-generated with collection
```

### Generating Tests from OpenAPI

```bash
# Generate test suite from local server OAS
just test-generate

# Generate from production OAS
just test-generate-prod

# Custom OAS URL
./tests/scripts/generate-from-oas.sh https://custom-url/v1/spec
```

This generates:
- Postman collection (`tests/generated/postman-collection.json`)
- HTTP request files (`tests/generated/generated-requests.http`)
- OpenAPI spec snapshot (`tests/generated/openapi.json`)

### Manual Testing with cURL

```bash
# Start development server
just dev

# Test authentication endpoint (requires SigV4 signature)
curl http://localhost:8778/v1/auth/token \
  -H "Authorization: AWS4-HMAC-SHA512 Credential=..." \
  -H "X-Amz-Date: 20250115T120000Z"

# Test CVE info endpoint (requires JWT)
curl http://localhost:8778/v1/info/CVE-2024-1234 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test vulnerability data endpoint
curl http://localhost:8778/v1/vuln/CVE-2024-1234 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test exploits endpoint
curl http://localhost:8778/v1/exploits/CVE-2024-1234 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test product endpoints
curl http://localhost:8778/v1/product/express \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

curl http://localhost:8778/v1/product/express/4.18.2 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

curl http://localhost:8778/v1/product/express/4.18.2/npm \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test ecosystems endpoint
curl http://localhost:8778/v1/ecosystems \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test package versions endpoint
curl http://localhost:8778/v1/express/versions?limit=20 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test package vulnerabilities endpoint
curl http://localhost:8778/v1/express/vulns \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Production Testing

```bash
# Tail production logs
just logs

# Or use wrangler directly
npx wrangler tail --format pretty

# Run integration tests against production
just test-prod
```

### Test Automation (CI/CD)

The test suite can be automated in GitHub Actions or other CI systems:

```yaml
# .github/workflows/test.yml
- name: Run integration tests
  run: |
    npm install -g httpyac
    ./tests/scripts/run-tests.sh
```

See `tests/README.md` for detailed testing documentation including:
- Writing new tests
- Test assertions and validation
- Environment configuration
- Troubleshooting guide
- CI/CD integration examples

## Deployment

### GitOps (Recommended)

The project uses GitOps for deployments. Push to the `main` branch to trigger automatic deployment to production.

### Manual Deployment

Only use manual deployment if GitOps is unavailable:

```bash
# Deploy to production
just deploy

# Or use wrangler directly
npx wrangler deploy --env production
```

## Troubleshooting

### Common Issues

**Build Errors:**
- Run `just types` to regenerate TypeScript types
- Ensure all dependencies are installed: `just install`
- Check that PostgreSQL is running locally

**Authentication Errors:**
- Verify `wrangler whoami` shows correct Cloudflare account
- Check that Hyperdrive, KV, R2, and Queue bindings are configured
- Ensure secrets are set in Cloudflare dashboard for production

**Database Connection Issues:**
- Verify `DATABASE_URL` in `.env` for local development
- Check Hyperdrive configuration in `wrangler.toml`
- Ensure PostgreSQL is accessible on `127.0.0.1:5432` (or your configured host)

### Getting Help

- Check the [Cloudflare Workers documentation](https://developers.cloudflare.com/workers/)
- Review [Hono documentation](https://hono.dev/)
- See [Prisma with Cloudflare Workers guide](https://www.prisma.io/docs/orm/overview/databases/cloudflare-d1)

## Architecture Notes

This project was originally a full-stack application with a Vue.js frontend. It has been streamlined to be an **API-only Cloudflare Workers project**:

- ✅ No frontend code (removed Vite, Vue, component libraries)
- ✅ Pure Cloudflare Workers API using Wrangler
- ✅ TypeScript with full type safety
- ✅ Prisma ORM with PostgreSQL via Hyperdrive
- ✅ Hono web framework for routing
- ✅ AWS SigV4 authentication with JWT

The original `_worker.ts` with unused routes has been backed up to `_worker.ts.backup`.

## Contributing

This is an internal Vulnetix project. For access or questions, please contact the maintainers.

## License

Proprietary - Vulnetix
