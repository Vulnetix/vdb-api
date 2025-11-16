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
- `GET /v1/swagger` - Swagger UI (interactive documentation)

### Authentication

- `GET /v1/auth/token` - Exchange SigV4-signed request for JWT token

### Protected Endpoints (Require JWT)

- `GET /v1/info/{identifier}` - CVE metadata and data source information
- `GET /v1/vuln/{identifier}` - Vulnerability records in CVEListV5 format
- `GET /v1/exploits/{identifier}` - Exploit intelligence and sightings

### Legacy Redirects

Unversioned endpoints redirect to `/v1` with HTTP 301:
- `/info/*` → `/v1/info/*`
- `/vuln/*` → `/v1/vuln/*`
- `/exploits/*` → `/v1/exploits/*`

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

# Test info endpoint (requires JWT)
curl http://localhost:8778/v1/info/CVE-2024-1234 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test vuln endpoint
curl http://localhost:8778/v1/vuln/CVE-2024-1234 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test exploits endpoint
curl http://localhost:8778/v1/exploits/CVE-2024-1234 \
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
