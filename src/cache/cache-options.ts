import type { PrismaModelName } from './generated/prisma-metadata'
import type { KeyGenFunction } from './cache-key-generator'
import { DEFAULT_KEY_GENERATORS } from './cache-key-generator'

/**
 * TTL configuration for a model
 */
export interface TtlConfig {
  /** TTL for primary key lookups (in seconds) */
  primaryKey: number
  /** TTL for query-based lookups (in seconds) */
  query: number
}

/**
 * Cache options configuration
 */
export interface CacheOptions {
  /** TTL configuration per model */
  ttlConfig: Record<PrismaModelName, TtlConfig>
  /** Key generator functions per model */
  keyGen: Record<PrismaModelName, KeyGenFunction>
  /** Enable cache metrics logging */
  enableMetrics?: boolean
  /** Default TTL for unconfigured models (in seconds) */
  defaultTtl?: number
}

/**
 * Default TTL values
 */
const DEFAULT_TTL = {
  /** For relation/mapping tables - 24 hours */
  RELATION_TABLE_PK: 86400,
  /** For main data tables - 1 hour */
  MAIN_TABLE_PK: 3600,
  /** For query-based lookups - 15 minutes */
  QUERY: 900,
  /** For volatile data - 5 minutes */
  VOLATILE: 300,
} as const

/**
 * Default TTL configuration for all models
 * Categorizes models as relation tables or main tables and assigns appropriate TTLs
 */
export const DEFAULT_TTL_CONFIG: Record<PrismaModelName, TtlConfig> = {
  // GitHub relation tables (24h for PK, 15min for queries)
  GitHubUserEmail: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  GitHubRepoDependency: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  GitHubRepoContributor: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  GitHubRepoLanguage: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  GitHubRepoPackageManager: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // CVE relation tables (24h for PK, 15min for queries)
  CVEMetadataReferences: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEAlias: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEADP: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEProblemType: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEMetric: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEAffected: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEAffectedVersion: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  PackageVersionCVE: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEDescription: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEImpact: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVEImpactDescription: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  GcveAlias: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // VulnCheck relation tables (24h for PK, 15min for queries)
  VulnCheckKEVCVE: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },
  VulnCheckKEVCWE: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // Main GitHub data (1h for PK, 15min for queries)
  GitHubUser: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  GitHubOrganization: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  GitHubRepository: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // Dependencies (1h for PK, 15min for queries)
  Dependency: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  DependencySLSAProvenance: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  DependencyAttestation: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  PackageVersion: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // Main CVE data (1h for PK, 15min for queries)
  CVEMetadata: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CVENumberingAuthority: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  AuthorizedDataPublisher: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  GcveIssuance: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // Languages (24h for PK, 15min for queries - static data)
  Languages: { primaryKey: DEFAULT_TTL.RELATION_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // PIX data (1h for PK, 15min for queries)
  Pix: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  PixLog: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // Scores (5min for PK and queries - volatile, updated frequently)
  EpssScore: { primaryKey: DEFAULT_TTL.VOLATILE, query: DEFAULT_TTL.VOLATILE },
  CessScore: { primaryKey: DEFAULT_TTL.VOLATILE, query: DEFAULT_TTL.VOLATILE },

  // CrowdSec data (1h for PK, 15min for queries)
  CrowdSecLog: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  CrowdSecSighting: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // KEV data (1h for PK, 15min for queries)
  Kev: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  VulnCheckKEV: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  VulnCheckXDB: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  VulnCheckReportedExploitation: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // Trackers (5min - volatile, updated frequently)
  BulkDataDumpTracker: { primaryKey: DEFAULT_TTL.VOLATILE, query: DEFAULT_TTL.VOLATILE },

  // OpenSSF data (1h for PK, 15min for queries)
  OpenSSFScorecard: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
  OpenSSFScorecardCheck: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },

  // SSVC decisions (1h for PK, 15min for queries)
  SSVCDecision: { primaryKey: DEFAULT_TTL.MAIN_TABLE_PK, query: DEFAULT_TTL.QUERY },
}

/**
 * Default cache options
 */
export const DEFAULT_CACHE_OPTIONS: CacheOptions = {
  ttlConfig: DEFAULT_TTL_CONFIG,
  keyGen: DEFAULT_KEY_GENERATORS,
  enableMetrics: false,
  defaultTtl: DEFAULT_TTL.QUERY,
}

/**
 * Get TTL for a specific model and query type
 */
export function getTtl(
  modelName: PrismaModelName,
  isPrimaryKeyLookup: boolean,
  options: CacheOptions = DEFAULT_CACHE_OPTIONS
): number {
  const ttlConfig = options.ttlConfig[modelName]
  if (!ttlConfig) {
    return options.defaultTtl || DEFAULT_TTL.QUERY
  }
  return isPrimaryKeyLookup ? ttlConfig.primaryKey : ttlConfig.query
}
