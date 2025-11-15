/**
 * OpenAPI Specification Route
 * Serves the OpenAPI 3.1 specification for the VDB Manager API
 */
import type { HonoEnv } from '@worker'
import { OpenAPIHono } from '@hono/zod-openapi'

// Create OpenAPI-enabled Hono app
const app = new OpenAPIHono<HonoEnv>()

/**
 * GET /v1/spec
 * Returns the OpenAPI 3.1 specification document
 */
app.get('/', (c) => {
    const openAPISpec = {
        openapi: '3.1.0',
        info: {
            title: 'VDB Manager API',
            version: '1.0.0',
            description: `# Vulnerability Database Manager API

Unified access to CVE metadata and vulnerability data from multiple authoritative sources including MITRE, NIST NVD, VulnCheck, CISA KEV, GitHub Security Advisories, OSV, and EUVD.

## Authentication Model

This API uses a **simplified Organization-based credential model** for enterprise authentication:

### Credential Structure
- **Organization UUID** = Your unique access key identifier
- **Organization Secret** = Your secret key for signing requests
- **No separate credential objects** - credentials are inherent to your Organization

### Authentication Flow
1. **Sign requests** using AWS Signature Version 4 (SigV4 SHA-512)
2. **Exchange signed request** for a JWT token at \`/auth/token\`
3. **Use JWT Bearer token** for all subsequent API calls
4. **Token expires** in 15 minutes - repeat steps 1-2 to refresh

### AWS SigV4 Signing
Your requests to \`/auth/token\` must be signed using:
- **Algorithm**: AWS4-HMAC-SHA512
- **Access Key**: Your Organization UUID (e.g., \`123e4567-e89b-12d3-a456-426614174000\`)
- **Secret Key**: Your Organization Secret (64-character alphanumeric string)
- **Region**: \`us-east-1\`
- **Service**: \`vdb\`

### Example Bash Script
\`\`\`bash
#!/bin/bash
# Set your Organization credentials as environment variables
export VVD_ORG="123e4567-e89b-12d3-a456-426614174000"  # Organization UUID
export VVD_SECRET="your-64-char-secret-key-here"      # Organization Secret
export VVD_ACCESS_KEY="\${VVD_ORG}"                     # UUID is the access key

# Generate timestamp and signature
AMZ_DATE=$(date -u +"%Y%m%dT%H%M%SZ")
DATE_STAMP=$(date -u +"%Y%m%d")

# Step 1: Get JWT token (requires SigV4 signature - see full script in API docs)
# ... SigV4 signing logic ...

# Step 2: Use JWT for API requests
curl -X GET "https://vdb.vulnetix.com/info/CVE-2024-1234" \\
  -H "Authorization: Bearer \${VVD_JWT}" \\
  -H "Content-Type: application/json" | jq
\`\`\`

### Rate Limiting
- **Per-minute limit**: Configurable per organization (default: 5 requests/minute)
- **Weekly limit**: Configurable per organization (default: 1000 requests/week)
- **Limit = 0**: Unlimited access for that dimension
- **Headers**: Rate limit info included in every response

### Access Logging
All API requests are logged for:
- Usage analytics and reporting
- Rate limit enforcement
- Security auditing`,
            contact: {
                name: 'API Support',
                url: 'https://github.com/Vulnetix/vdb-manager'
            },
            license: {
                name: 'MIT',
                url: 'https://opensource.org/licenses/MIT'
            }
        },
        servers: [
            {
                url: '/',
                description: 'API Base URL'
            }
        ],
        paths: {
            '/auth/token': {
                get: {
                    summary: 'Get JWT authentication token',
                    description: `Exchange Organization credentials for a JWT token using AWS Signature Version 4 (SigV4 SHA-512) request signing.

**Credential Model:**
- Your **Organization UUID** serves as the access key (e.g., \`123e4567-e89b-12d3-a456-426614174000\`)
- Your **Organization Secret** (64-char string) is the secret key
- No separate credential objects - credentials are inherent to your Organization

**Signing Requirements:**
- Algorithm: AWS4-HMAC-SHA512
- Region: us-east-1
- Service: vdb
- Signed Headers: x-amz-date

**Note:** Only \`x-amz-date\` is signed for browser compatibility. Browsers block JavaScript from setting the \`host\` header, so we exclude it from the signature to ensure consistent behavior across all clients.

The request must be signed using AWS SigV4 with the SHA-512 algorithm. Upon successful authentication, a JWT token is returned with a 15-minute expiration.`,
                    tags: ['Authentication'],
                    parameters: [
                        {
                            name: 'Authorization',
                            in: 'header',
                            required: true,
                            schema: { type: 'string' },
                            description: 'AWS SigV4 Authorization header with SHA-512 signature. Use your Organization UUID as the access key.',
                            example: 'AWS4-HMAC-SHA512 Credential=123e4567-e89b-12d3-a456-426614174000/20240101/us-east-1/vdb/aws4_request, SignedHeaders=x-amz-date, Signature=...'
                        },
                        {
                            name: 'X-Amz-Date',
                            in: 'header',
                            required: true,
                            schema: { type: 'string' },
                            description: 'ISO8601 timestamp in format YYYYMMDDTHHMMSSZ',
                            example: '20240101T120000Z'
                        }
                    ],
                    responses: {
                        '200': {
                            description: 'Successfully authenticated and JWT token issued',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        required: ['token', 'iss', 'sub', 'exp'],
                                        properties: {
                                            token: {
                                                type: 'string',
                                                description: 'JWT token (expires in 15 minutes)',
                                                example: 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46dnVsbmV0aXg6dmRiIiwic3ViIjoidXJuOnV1aWQ6MTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwib3JnSWQiOiIxMjNlNDU2Ny1lODliLTEyZDMtYTQ1Ni00MjY2MTQxNzQwMDAiLCJhY2Nlc3NLZXkiOiJ2dWxuZXRpeF9hY2Nlc3NrZXkxMjMiLCJpYXQiOjE3MDQxMDk1MDAsImV4cCI6MTcwNDExMDQwMH0.signature'
                                            },
                                            iss: {
                                                type: 'string',
                                                description: 'Token issuer (always "urn:vulnetix:vdb")',
                                                example: 'urn:vulnetix:vdb'
                                            },
                                            sub: {
                                                type: 'string',
                                                description: 'Token subject - your Organization UUID in URN format (this is the same UUID used as your access key)',
                                                example: 'urn:uuid:123e4567-e89b-12d3-a456-426614174000'
                                            },
                                            exp: {
                                                type: 'integer',
                                                description: 'Token expiration time (Unix timestamp)',
                                                example: 1704110400
                                            }
                                        }
                                    },
                                    example: {
                                        token: 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46dnVsbmV0aXg6dmRiIiwic3ViIjoidXJuOnV1aWQ6MTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwib3JnSWQiOiIxMjNlNDU2Ny1lODliLTEyZDMtYTQ1Ni00MjY2MTQxNzQwMDAiLCJhY2Nlc3NLZXkiOiJ2dWxuZXRpeF9hY2Nlc3NrZXkxMjMiLCJpYXQiOjE3MDQxMDk1MDAsImV4cCI6MTcwNDExMDQwMH0.signature',
                                        iss: 'urn:vulnetix:vdb',
                                        sub: 'urn:uuid:123e4567-e89b-12d3-a456-426614174000',
                                        exp: 1704110400
                                    }
                                }
                            }
                        },
                        '401': {
                            description: 'Authentication failed - invalid credentials or signature',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string', example: 'Invalid signature' }
                                        }
                                    }
                                }
                            }
                        },
                        '403': {
                            description: 'Access denied - IP not whitelisted or credentials inactive/expired',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string', example: 'Access denied from this IP address' }
                                        }
                                    }
                                }
                            }
                        },
                        '500': {
                            description: 'Internal server error',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string' },
                                            details: { type: 'string' }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    security: []
                }
            },
            '/info/{identifier}': {
                get: {
                    summary: 'Get CVE information',
                    description: 'Returns comprehensive CVE metadata including data source coverage, R2 file tracking, aggregated counts, and resource links. Supports lookups by CVE ID (e.g., CVE-2024-1234). Requires JWT authentication via Bearer token.',
                    tags: ['CVE Information'],
                    security: [{ BearerAuth: [] }],
                    parameters: [
                        {
                            name: 'identifier',
                            in: 'path',
                            required: true,
                            schema: { type: 'string' },
                            description: 'CVE identifier (e.g., CVE-2024-1234 or 2024-1234)',
                            example: 'CVE-2024-1234'
                        }
                    ],
                    responses: {
                        '200': {
                            description: 'Successful response with CVE information',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        required: ['_identifier', '_timestamp', 'cache_hit', 'matched', 'gcve', 'sources', 'aliases', 'references', 'problemTypes', 'metrics', 'affected', 'impacts', 'descriptions', 'scorecards', 'links'],
                                        properties: {
                                            _identifier: {
                                                type: 'string',
                                                description: 'The CVE identifier that was queried',
                                                example: 'CVE-2024-1234'
                                            },
                                            _timestamp: {
                                                type: 'integer',
                                                description: 'Current Unix timestamp when response was generated',
                                                example: 1704067200
                                            },
                                            cache_hit: {
                                                type: 'boolean',
                                                description: 'Whether the response was served from KV cache (false if database was queried)',
                                                example: false
                                            },
                                            matched: {
                                                type: 'boolean',
                                                description: 'Whether any CVE record or R2 file was found for this identifier',
                                                example: true
                                            },
                                            gcve: {
                                                type: 'boolean',
                                                description: 'Whether any data source has a GCVE (Global CVE) issuance record',
                                                example: false
                                            },
                                            lastFetchedAt: {
                                                type: 'integer',
                                                nullable: true,
                                                description: 'Latest fetch timestamp across all sources (Unix timestamp)',
                                                example: 1704000000
                                            },
                                            lastEnrichedAt: {
                                                type: 'integer',
                                                nullable: true,
                                                description: 'Latest enrichment timestamp across all sources (Unix timestamp)',
                                                example: 1704010000
                                            },
                                            sources: {
                                                type: 'array',
                                                description: 'List of data sources that have information about this CVE',
                                                items: {
                                                    type: 'object',
                                                    required: ['name', 'processing'],
                                                    properties: {
                                                        name: {
                                                            type: 'string',
                                                            description: 'Data source name',
                                                            enum: ['mitre', 'nist-nvd', 'vulncheck-nvd', 'vulncheck-kev', 'cisa-kev', 'ghsa', 'osv', 'euvd'],
                                                            example: 'mitre'
                                                        },
                                                        processing: {
                                                            type: 'boolean',
                                                            description: 'True if only R2 file exists (still processing), false if CVE metadata is available',
                                                            example: false
                                                        }
                                                    }
                                                },
                                                example: [
                                                    { name: 'mitre', processing: false },
                                                    { name: 'nist-nvd', processing: false }
                                                ]
                                            },
                                            aliases: {
                                                type: 'array',
                                                description: 'List of alias identifiers for this CVE',
                                                items: { type: 'string' },
                                                example: ['GHSA-xxxx-xxxx-xxxx', 'PYSEC-2024-1234']
                                            },
                                            references: {
                                                type: 'integer',
                                                description: 'Total number of reference URLs across all sources',
                                                example: 42
                                            },
                                            problemTypes: {
                                                type: 'integer',
                                                description: 'Total number of problem type/CWE associations across all sources',
                                                example: 3
                                            },
                                            metrics: {
                                                type: 'integer',
                                                description: 'Total number of metrics (CVSS scores, SSVC, etc.) across all sources',
                                                example: 5
                                            },
                                            affected: {
                                                type: 'integer',
                                                description: 'Total number of affected product records across all sources',
                                                example: 8
                                            },
                                            impacts: {
                                                type: 'integer',
                                                description: 'Total number of impact records (CAPEC-based) across all sources',
                                                example: 2
                                            },
                                            descriptions: {
                                                type: 'integer',
                                                description: 'Total number of description records across all sources',
                                                example: 4
                                            },
                                            scorecards: {
                                                type: 'integer',
                                                description: 'Total number of OpenSSF Scorecard associations across all sources',
                                                example: 1
                                            },
                                            links: {
                                                type: 'array',
                                                description: 'Resource links for accessing CVE data',
                                                items: {
                                                    type: 'object',
                                                    required: ['type', 'format', 'url'],
                                                    properties: {
                                                        type: {
                                                            type: 'string',
                                                            description: 'Link type - "page" for web UI, or source name for R2 downloads',
                                                            example: 'mitre'
                                                        },
                                                        format: {
                                                            type: 'string',
                                                            description: 'Data format/schema (e.g., "http", "cvelistV5", "osv", "nvd-json-2.0")',
                                                            example: 'cvelistV5',
                                                            default: 'http'
                                                        },
                                                        url: {
                                                            type: 'string',
                                                            format: 'uri',
                                                            description: 'Full URL to the resource',
                                                            example: 'https://artifacts.vulnetix.com/mitre-cve/files/abc123/CVE-2024-1234.json'
                                                        }
                                                    }
                                                },
                                                example: [
                                                    {
                                                        type: 'page',
                                                        format: 'http',
                                                        url: 'https://vdb.vulnetix.com/CVE-2024-1234'
                                                    },
                                                    {
                                                        type: 'mitre',
                                                        format: 'cvelistV5',
                                                        url: 'https://artifacts.vulnetix.com/mitre-cve/files/abc123/CVE-2024-1234.json'
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    example: {
                                        _identifier: 'CVE-2024-1234',
                                        _timestamp: 1704067200,
                                        cache_hit: false,
                                        matched: true,
                                        gcve: false,
                                        lastFetchedAt: 1704000000,
                                        lastEnrichedAt: 1704010000,
                                        sources: [
                                            { name: 'mitre', processing: false },
                                            { name: 'nist-nvd', processing: false }
                                        ],
                                        aliases: ['GHSA-xxxx-xxxx-xxxx'],
                                        references: 42,
                                        problemTypes: 3,
                                        metrics: 5,
                                        affected: 8,
                                        impacts: 2,
                                        descriptions: 4,
                                        scorecards: 1,
                                        links: [
                                            {
                                                type: 'page',
                                                format: 'http',
                                                url: 'https://vdb.vulnetix.com/CVE-2024-1234'
                                            },
                                            {
                                                type: 'mitre',
                                                format: 'cvelistV5',
                                                url: 'https://artifacts.vulnetix.com/mitre-cve/files/abc123/CVE-2024-1234.json'
                                            }
                                        ]
                                    }
                                }
                            }
                        },
                        '404': {
                            description: 'CVE not found in any data source',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string', example: 'CVE not found' }
                                        }
                                    }
                                }
                            }
                        },
                        '401': {
                            description: 'Authentication required - missing or invalid JWT token',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string', example: 'Missing Authorization header. Please provide a Bearer token.' }
                                        }
                                    }
                                }
                            }
                        },
                        '500': {
                            description: 'Internal server error',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string' },
                                            details: { type: 'string' }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            '/vuln/{identifier}': {
                get: {
                    summary: 'Get vulnerability data in CVEListV5 format (per source)',
                    description: `Returns an array of CVEListV5 format records, one for each distinct data source that has information about the vulnerability.

Each record follows the official CVE Record Format schema (CVEListV5) and includes:
- Core CVE metadata (cveId, state, dates)
- CNA (CVE Numbering Authority) container with descriptions, affected products, references, CVSS metrics, and problem types
- ADP (Authorized Data Publisher) containers if available
- Vulnetix enrichment container with EPSS, CESS, KEV data, AI analyses, aliases, and impacts

This endpoint is useful for:
- Understanding how different sources describe the same vulnerability
- Comparing CVSS scores across sources
- Accessing source-specific affected product information
- Getting the most comprehensive view of a vulnerability

Requires JWT authentication via Bearer token.`,
                    tags: ['Vulnerability Data'],
                    security: [{ BearerAuth: [] }],
                    parameters: [
                        {
                            name: 'identifier',
                            in: 'path',
                            required: true,
                            schema: { type: 'string' },
                            description: 'Vulnerability identifier. Supports all identifiers stored in CVEMetadata including: CVE-* (Common Vulnerabilities and Exposures), GHSA-* (GitHub Security Advisory), PYSEC-* (Python Security), RUSTSEC-* (Rust Security), GO-* (Go vulnerabilities), OSV-* (Open Source Vulnerabilities), EUVD-* (EU Vulnerability Database), and any other ecosystem-specific identifiers.',
                            example: 'CVE-2024-1234'
                        }
                    ],
                    responses: {
                        '200': {
                            description: 'Successful response with array of CVEListV5 format records',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'array',
                                        items: {
                                            type: 'object',
                                            required: ['dataType', 'dataVersion', 'cveMetadata', 'containers'],
                                            properties: {
                                                dataType: {
                                                    type: 'string',
                                                    enum: ['CVE_RECORD'],
                                                    description: 'Type of record (always CVE_RECORD)',
                                                    example: 'CVE_RECORD'
                                                },
                                                dataVersion: {
                                                    type: 'string',
                                                    description: 'CVE schema version',
                                                    example: '5.1'
                                                },
                                                cveMetadata: {
                                                    type: 'object',
                                                    required: ['cveId', 'assignerOrgId', 'state'],
                                                    properties: {
                                                        cveId: {
                                                            type: 'string',
                                                            description: 'CVE identifier',
                                                            example: 'CVE-2024-1234'
                                                        },
                                                        assignerOrgId: {
                                                            type: 'string',
                                                            description: 'UUID of the assigning CNA',
                                                            example: '8254265b-2729-46b6-b9e3-3dfca2d5bfca'
                                                        },
                                                        state: {
                                                            type: 'string',
                                                            enum: ['PUBLISHED', 'REJECTED'],
                                                            example: 'PUBLISHED'
                                                        },
                                                        datePublished: {
                                                            type: 'string',
                                                            format: 'date-time',
                                                            description: 'ISO 8601 date when CVE was published',
                                                            example: '2024-01-15T10:30:00Z'
                                                        },
                                                        dateUpdated: {
                                                            type: 'string',
                                                            format: 'date-time',
                                                            description: 'ISO 8601 date when CVE was last updated',
                                                            example: '2024-01-20T14:22:00Z'
                                                        }
                                                    }
                                                },
                                                containers: {
                                                    type: 'object',
                                                    required: ['cna'],
                                                    properties: {
                                                        cna: {
                                                            type: 'object',
                                                            description: 'CNA (CVE Numbering Authority) container with core vulnerability information',
                                                            properties: {
                                                                providerMetadata: {
                                                                    type: 'object',
                                                                    properties: {
                                                                        orgId: { type: 'string' },
                                                                        shortName: { type: 'string' }
                                                                    }
                                                                },
                                                                title: { type: 'string' },
                                                                descriptions: {
                                                                    type: 'array',
                                                                    items: {
                                                                        type: 'object',
                                                                        properties: {
                                                                            lang: { type: 'string', example: 'en' },
                                                                            value: { type: 'string' }
                                                                        }
                                                                    }
                                                                },
                                                                affected: {
                                                                    type: 'array',
                                                                    description: 'Affected products and version ranges',
                                                                    items: { type: 'object' }
                                                                },
                                                                references: {
                                                                    type: 'array',
                                                                    description: 'Reference URLs and advisories',
                                                                    items: {
                                                                        type: 'object',
                                                                        properties: {
                                                                            url: { type: 'string', format: 'uri' },
                                                                            name: { type: 'string' },
                                                                            tags: {
                                                                                type: 'array',
                                                                                items: { type: 'string' }
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                problemTypes: {
                                                                    type: 'array',
                                                                    description: 'CWE classifications',
                                                                    items: { type: 'object' }
                                                                },
                                                                metrics: {
                                                                    type: 'array',
                                                                    description: 'CVSS scores (v2.0, v3.0, v3.1, v4.0)',
                                                                    items: { type: 'object' }
                                                                }
                                                            }
                                                        },
                                                        adp: {
                                                            type: 'array',
                                                            description: 'ADP (Authorized Data Publisher) containers with additional enrichment',
                                                            items: { type: 'object' }
                                                        },
                                                        vulnetixEnrichment: {
                                                            type: 'object',
                                                            description: 'Vulnetix-specific enrichment data',
                                                            properties: {
                                                                generatorVersion: { type: 'string', example: '0.2.0' },
                                                                generatedAt: { type: 'string', format: 'date-time' },
                                                                enrichmentSource: { type: 'string', example: 'Vulnetix Vulnerability Database' },
                                                                dataSource: {
                                                                    type: 'string',
                                                                    description: 'The specific source this record came from',
                                                                    example: 'nist-nvd'
                                                                },
                                                                dataCollected: {
                                                                    type: 'array',
                                                                    description: 'List of data types included in this record',
                                                                    items: { type: 'string' },
                                                                    example: ['descriptions', 'metrics', 'affected', 'references', 'epss', 'cess', 'kev']
                                                                },
                                                                epss: {
                                                                    type: 'object',
                                                                    description: 'EPSS (Exploit Prediction Scoring System) data',
                                                                    properties: {
                                                                        score: { type: 'number' },
                                                                        percentile: { type: 'number' },
                                                                        date: { type: 'string' },
                                                                        modelVersion: { type: 'string' }
                                                                    }
                                                                },
                                                                cess: {
                                                                    type: 'object',
                                                                    description: 'CESS (Cybersecurity Exploit Scoring System) data',
                                                                    properties: {
                                                                        score: { type: 'number' },
                                                                        probabilityExploitUsage: { type: 'number' },
                                                                        date: { type: 'string' },
                                                                        modelVersion: { type: 'string' }
                                                                    }
                                                                },
                                                                kev: {
                                                                    type: 'object',
                                                                    description: 'CISA KEV (Known Exploited Vulnerability) data',
                                                                    properties: {
                                                                        source: { type: 'string' },
                                                                        vendorProject: { type: 'string' },
                                                                        product: { type: 'string' },
                                                                        vulnerabilityName: { type: 'string' },
                                                                        dateAdded: { type: 'string', format: 'date-time' },
                                                                        shortDescription: { type: 'string' },
                                                                        requiredAction: { type: 'string' }
                                                                    }
                                                                },
                                                                aliases: {
                                                                    type: 'array',
                                                                    description: 'Alternative identifiers (GHSA, PYSEC, etc.)',
                                                                    items: { type: 'string' },
                                                                    example: ['GHSA-xxxx-xxxx-xxxx', 'PYSEC-2024-1234']
                                                                },
                                                                impacts: {
                                                                    type: 'array',
                                                                    description: 'CAPEC-based impact descriptions',
                                                                    items: { type: 'object' }
                                                                },
                                                                affectedFunctions: {
                                                                    type: 'array',
                                                                    description: 'AI-identified affected function names',
                                                                    items: { type: 'string' }
                                                                },
                                                                advisory: {
                                                                    type: 'string',
                                                                    description: 'AI-generated advisory text'
                                                                },
                                                                aiAnalyses: {
                                                                    type: 'array',
                                                                    description: 'AI-generated analyses',
                                                                    items: { type: 'object' }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    example: [
                                        {
                                            dataType: 'CVE_RECORD',
                                            dataVersion: '5.1',
                                            cveMetadata: {
                                                cveId: 'CVE-2024-1234',
                                                assignerOrgId: '8254265b-2729-46b6-b9e3-3dfca2d5bfca',
                                                state: 'PUBLISHED',
                                                datePublished: '2024-01-15T10:30:00Z',
                                                dateUpdated: '2024-01-20T14:22:00Z'
                                            },
                                            containers: {
                                                cna: {
                                                    providerMetadata: {
                                                        orgId: '8254265b-2729-46b6-b9e3-3dfca2d5bfca',
                                                        shortName: 'mitre'
                                                    },
                                                    title: 'Buffer overflow in Example Library',
                                                    descriptions: [
                                                        {
                                                            lang: 'en',
                                                            value: 'A buffer overflow vulnerability in Example Library 1.2.3 allows remote attackers to execute arbitrary code.'
                                                        }
                                                    ],
                                                    affected: [],
                                                    references: [
                                                        {
                                                            url: 'https://example.com/advisory',
                                                            name: 'Vendor Advisory',
                                                            tags: ['vendor-advisory']
                                                        }
                                                    ],
                                                    problemTypes: [
                                                        {
                                                            descriptions: [
                                                                {
                                                                    type: 'CWE',
                                                                    cweId: 'CWE-119',
                                                                    lang: 'en',
                                                                    description: 'Improper Restriction of Operations within the Bounds of a Memory Buffer'
                                                                }
                                                            ]
                                                        }
                                                    ],
                                                    metrics: [
                                                        {
                                                            cvssV3_1: {
                                                                version: '3.1',
                                                                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                                                                baseScore: 9.8,
                                                                baseSeverity: 'CRITICAL'
                                                            }
                                                        }
                                                    ]
                                                },
                                                vulnetixEnrichment: {
                                                    generatorVersion: '0.2.0',
                                                    generatedAt: '2024-01-21T09:15:00Z',
                                                    enrichmentSource: 'Vulnetix Vulnerability Database',
                                                    dataSource: 'mitre',
                                                    dataCollected: ['descriptions', 'metrics', 'references', 'epss'],
                                                    epss: {
                                                        score: 0.02456,
                                                        percentile: 0.86234,
                                                        date: '2024-01-20',
                                                        modelVersion: 'v2023.03.01'
                                                    },
                                                    aliases: ['GHSA-xxxx-yyyy-zzzz']
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        },
                        '400': {
                            description: 'Invalid request - missing identifier',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            error: { type: 'string', example: 'Missing vulnerability ID' }
                                        }
                                    }
                                }
                            }
                        },
                        '404': {
                            description: 'Vulnerability not found in any data source',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            error: { type: 'string', example: 'Vulnerability not found' },
                                            identifier: { type: 'string', example: 'CVE-2024-1234' }
                                        }
                                    }
                                }
                            }
                        },
                        '401': {
                            description: 'Authentication required - missing or invalid JWT token',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string', example: 'Missing Authorization header. Please provide a Bearer token.' }
                                        }
                                    }
                                }
                            }
                        },
                        '500': {
                            description: 'Internal server error',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            error: { type: 'string' },
                                            details: { type: 'string' }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            '/exploits/{identifier}': {
                get: {
                    summary: 'Get exploit and sighting data',
                    description: `Returns enriched exploit records for a given vulnerability identifier including:

- **ExploitDB** - Verified proof-of-concept exploits with raw exploit code
- **Metasploit** - Weaponized exploitation modules from Metasploit Framework
- **Nuclei Templates** - Detection and exploitation templates from ProjectDiscovery
- **VulnerabilityLab** - Research-grade exploit publications
- **VulnCheck XDB** - Known exploited vulnerabilities database
- **CrowdSec** - Real-world attack sightings and IP intelligence
- **GitHub PoCs** - Community-contributed proof-of-concept code

Each exploit record includes full details, metadata, and raw templates/code when available from R2 storage.

Supports lookups by CVE ID (e.g., CVE-2024-1234) and other vulnerability identifiers. Requires JWT authentication via Bearer token.`,
                    tags: ['Exploit Intelligence'],
                    security: [{ BearerAuth: [] }],
                    parameters: [
                        {
                            name: 'identifier',
                            in: 'path',
                            required: true,
                            schema: { type: 'string' },
                            description: 'Vulnerability identifier (e.g., CVE-2024-1234, 2024-1234, GHSA-xxxx-xxxx-xxxx)',
                            example: 'CVE-2024-1234'
                        }
                    ],
                    responses: {
                        '200': {
                            description: 'Successful response with exploit data',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        required: ['identifier', 'timestamp', 'count', 'summary', 'exploits'],
                                        properties: {
                                            identifier: {
                                                type: 'string',
                                                description: 'Normalized vulnerability identifier',
                                                example: 'CVE-2024-1234'
                                            },
                                            timestamp: {
                                                type: 'integer',
                                                description: 'Unix timestamp when response was generated',
                                                example: 1704067200
                                            },
                                            count: {
                                                type: 'integer',
                                                description: 'Total number of exploit records found',
                                                example: 15
                                            },
                                            summary: {
                                                type: 'object',
                                                description: 'Count breakdown by exploit source',
                                                properties: {
                                                    exploitDb: { type: 'integer', description: 'ExploitDB records', example: 3 },
                                                    metasploit: { type: 'integer', description: 'Metasploit modules', example: 2 },
                                                    nuclei: { type: 'integer', description: 'Nuclei templates', example: 1 },
                                                    vulnerabilityLab: { type: 'integer', description: 'VulnerabilityLab records', example: 1 },
                                                    vulnCheckXDB: { type: 'integer', description: 'VulnCheck XDB records', example: 1 },
                                                    crowdSec: { type: 'integer', description: 'CrowdSec sightings', example: 5 },
                                                    github: { type: 'integer', description: 'GitHub PoCs', example: 2 },
                                                    other: { type: 'integer', description: 'Other exploit references', example: 0 }
                                                }
                                            },
                                            exploits: {
                                                type: 'array',
                                                description: 'Array of enriched exploit records (sorted by date, most recent first)',
                                                items: {
                                                    type: 'object',
                                                    properties: {
                                                        uuid: { type: 'string', description: 'Unique identifier for this record' },
                                                        cveId: { type: 'string', description: 'CVE identifier' },
                                                        source: { type: 'string', description: 'Data source name' },
                                                        url: { type: 'string', description: 'Reference URL' },
                                                        type: { type: 'string', description: 'Reference type (exploit, poc, sighting)' },
                                                        referenceSource: { type: 'string', description: 'Reference source attribution' },
                                                        title: { type: 'string', description: 'Exploit title or description' },
                                                        createdAt: { type: 'integer', description: 'Unix timestamp when created' },
                                                        exploitDb: {
                                                            type: 'object',
                                                            description: 'ExploitDB enrichment data',
                                                            properties: {
                                                                id: { type: 'string', description: 'ExploitDB ID', example: '51234' },
                                                                author: { type: 'string', description: 'Exploit author' },
                                                                date: { type: 'integer', description: 'Publication date (Unix timestamp)' },
                                                                platform: { type: 'string', description: 'Target platform', example: 'linux' },
                                                                type: { type: 'string', description: 'Exploit type', example: 'remote' },
                                                                port: { type: 'integer', description: 'Target port number', example: 80 },
                                                                verified: { type: 'boolean', description: 'Verified exploit flag' },
                                                                rawUrl: { type: 'string', description: 'URL to raw exploit code' },
                                                                rawContent: { type: 'string', description: 'Raw exploit code (from R2 cache)' },
                                                                r2Path: { type: 'string', description: 'R2 storage path' }
                                                            }
                                                        },
                                                        metasploit: {
                                                            type: 'object',
                                                            description: 'Metasploit module enrichment',
                                                            properties: {
                                                                modulePath: { type: 'string', description: 'Module file path', example: '/modules/exploits/linux/http/apache_exploit.rb' },
                                                                moduleUrl: { type: 'string', description: 'GitHub module URL' },
                                                                rawUrl: { type: 'string', description: 'Raw module content URL' },
                                                                moduleContent: { type: 'string', description: 'Module source code (from R2 cache)' },
                                                                r2Path: { type: 'string', description: 'R2 storage path' }
                                                            }
                                                        },
                                                        nuclei: {
                                                            type: 'object',
                                                            description: 'Nuclei template enrichment',
                                                            properties: {
                                                                path: { type: 'string', description: 'Template file path' },
                                                                commitSha: { type: 'string', description: 'Git commit SHA' },
                                                                commitAuthorName: { type: 'string', description: 'Commit author name' },
                                                                commitCommitterName: { type: 'string', description: 'Commit committer name' },
                                                                commitCommitterEmail: { type: 'string', description: 'Committer email' },
                                                                commitMessage: { type: 'string', description: 'Commit message' },
                                                                commentCount: { type: 'integer', description: 'Number of comments' },
                                                                templateUrl: { type: 'string', description: 'GitHub template URL' },
                                                                rawUrl: { type: 'string', description: 'Raw template URL' }
                                                            }
                                                        },
                                                        vulnerabilityLab: {
                                                            type: 'object',
                                                            description: 'VulnerabilityLab enrichment',
                                                            properties: {
                                                                id: { type: 'string', description: 'VulnerabilityLab ID' },
                                                                title: { type: 'string', description: 'Document title' },
                                                                createdAt: { type: 'integer', description: 'Release date (Unix timestamp)' },
                                                                updatedAt: { type: 'integer', description: 'Last update date' },
                                                                exploitationTechnique: { type: 'string', description: 'Exploitation technique', example: 'Remote' },
                                                                authenticationType: { type: 'string', description: 'Authentication type' },
                                                                userInteraction: { type: 'string', description: 'User interaction required' },
                                                                author: { type: 'string', description: 'Research author' },
                                                                url: { type: 'string', description: 'VulnerabilityLab URL' }
                                                            }
                                                        },
                                                        vulnCheckXDB: {
                                                            type: 'object',
                                                            description: 'VulnCheck XDB enrichment',
                                                            properties: {
                                                                id: { type: 'string', description: 'XDB exploit ID' },
                                                                url: { type: 'string', description: 'Exploit URL' },
                                                                dateAdded: { type: 'integer', description: 'Date added to XDB' },
                                                                exploitType: { type: 'string', description: 'Exploit type' },
                                                                cloneSshUrl: { type: 'string', description: 'Git clone SSH URL' },
                                                                kevId: { type: 'string', description: 'Associated KEV ID' }
                                                            }
                                                        },
                                                        crowdSec: {
                                                            type: 'object',
                                                            description: 'CrowdSec sighting data',
                                                            properties: {
                                                                ip: { type: 'string', description: 'IP address', example: '192.168.1.100' },
                                                                reputation: { type: 'string', description: 'IP reputation', example: 'malicious' },
                                                                confidence: { type: 'string', description: 'Confidence level' },
                                                                backgroundNoiseScore: { type: 'integer', description: 'Background noise score' },
                                                                firstSeen: { type: 'integer', description: 'First seen Unix timestamp' },
                                                                lastSeen: { type: 'integer', description: 'Last seen Unix timestamp' },
                                                                asName: { type: 'string', description: 'AS name' },
                                                                asNum: { type: 'integer', description: 'AS number' },
                                                                country: { type: 'string', description: 'Country code', example: 'US' },
                                                                city: { type: 'string', description: 'City name' },
                                                                latitude: { type: 'number', description: 'Latitude' },
                                                                longitude: { type: 'number', description: 'Longitude' },
                                                                behaviors: { type: 'array', items: { type: 'string' }, description: 'Attack behaviors' },
                                                                attackDetails: { type: 'array', items: { type: 'string' }, description: 'Attack details' },
                                                                mitreTechniques: { type: 'array', items: { type: 'string' }, description: 'MITRE ATT&CK techniques' },
                                                                reverseDns: { type: 'string', description: 'Reverse DNS' },
                                                                targetCountries: { type: 'object', description: 'Target countries JSON object' }
                                                            }
                                                        },
                                                        githubPR: {
                                                            type: 'object',
                                                            description: 'GitHub Pull Request enrichment'
                                                        },
                                                        githubCommit: {
                                                            type: 'object',
                                                            description: 'GitHub Commit enrichment'
                                                        },
                                                        githubGist: {
                                                            type: 'object',
                                                            description: 'GitHub Gist enrichment'
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    example: {
                                        identifier: 'CVE-2024-1234',
                                        timestamp: 1704067200,
                                        count: 3,
                                        summary: {
                                            exploitDb: 2,
                                            metasploit: 1,
                                            nuclei: 0,
                                            vulnerabilityLab: 0,
                                            vulnCheckXDB: 0,
                                            crowdSec: 0,
                                            github: 0,
                                            other: 0
                                        },
                                        exploits: [
                                            {
                                                uuid: 'abc123',
                                                cveId: 'CVE-2024-1234',
                                                source: 'mitre',
                                                url: 'https://www.exploit-db.com/exploits/51234',
                                                type: 'exploit',
                                                referenceSource: 'ExploitDB',
                                                title: 'Apache 2.4.50 - Remote Code Execution',
                                                createdAt: 1704000000,
                                                exploitDb: {
                                                    id: '51234',
                                                    author: 'John Doe',
                                                    date: 1704000000,
                                                    platform: 'linux',
                                                    type: 'remote',
                                                    port: 80,
                                                    verified: true,
                                                    rawUrl: 'https://www.exploit-db.com/raw/51234'
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        },
                        '404': {
                            description: 'Vulnerability not found or no exploit data available',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string', example: 'No exploit data found' }
                                        }
                                    }
                                }
                            }
                        },
                        '401': {
                            description: 'Authentication required - missing or invalid JWT token',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean', example: false },
                                            error: { type: 'string', example: 'Missing Authorization header. Please provide a Bearer token.' }
                                        }
                                    }
                                }
                            }
                        },
                        '500': {
                            description: 'Internal server error',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            error: { type: 'string' },
                                            details: { type: 'string' }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        tags: [
            {
                name: 'Authentication',
                description: 'Enterprise authentication using AWS Signature Version 4 (SigV4) with SHA-512 algorithm for Organization credential exchange to JWT tokens. Your Organization UUID serves as the access key, and your Organization Secret is the signing key. Tokens expire in 15 minutes and must be refreshed via this endpoint.',
                externalDocs: {
                    description: 'AWS Signature Version 4 Signing Process',
                    url: 'https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html'
                }
            },
            { name: 'CVE Information', description: 'Unified CVE metadata and data source information' },
            { name: 'Vulnerability Data', description: 'CVEListV5 format vulnerability records per data source' },
            { name: 'Exploit Intelligence', description: 'Enriched exploit records from multiple sources including ExploitDB, Metasploit, Nuclei, VulnCheck XDB, CrowdSec sightings, and GitHub PoCs' }
        ],
        components: {
            securitySchemes: {
                BearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                    description: 'JWT token obtained from /auth/token endpoint using AWS SigV4 signed request with your Organization credentials (Organization UUID + Secret)'
                },
                SigV4: {
                    type: 'apiKey',
                    in: 'header',
                    name: 'Authorization',
                    description: 'AWS Signature Version 4 (SHA-512) authentication. Use your Organization UUID as the access key in the credential scope. Format: AWS4-HMAC-SHA512 Credential=<org-uuid>/YYYYMMDD/us-east-1/vdb/aws4_request, SignedHeaders=x-amz-date, Signature=<hex-signature>'
                }
            },
            schemas: {
                JWTToken: {
                    type: 'object',
                    required: ['token', 'iss', 'sub', 'exp'],
                    properties: {
                        token: {
                            type: 'string',
                            description: 'JWT token string (HS512 signed, 15 minute expiration)'
                        },
                        iss: {
                            type: 'string',
                            description: 'Token issuer URN'
                        },
                        sub: {
                            type: 'string',
                            description: 'Organization UUID URN for client validation'
                        },
                        exp: {
                            type: 'integer',
                            description: 'Token expiration Unix timestamp'
                        }
                    }
                },
                Error: {
                    type: 'object',
                    properties: {
                        success: { type: 'boolean', example: false },
                        error: { type: 'string' }
                    }
                },
                Success: {
                    type: 'object',
                    properties: {
                        success: { type: 'boolean', example: true },
                        message: { type: 'string' }
                    }
                }
            }
        }
    }

    return c.json(openAPISpec)
})

export default app
