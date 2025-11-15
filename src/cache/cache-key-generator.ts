import { createHash } from 'node:crypto'
import type { PrismaModelName } from './generated/prisma-metadata'
import { getPrimaryKeyFields, isCompositeKey } from './generated/prisma-metadata'

/**
 * Type for Prisma query parameters (where clause, etc.)
 */
export type QueryParams = {
  where?: Record<string, any>
  select?: Record<string, any>
  include?: Record<string, any>
  orderBy?: any
  skip?: number
  take?: number
  [key: string]: any
}

/**
 * Generate a SHA1 hash from an object
 */
function hashObject(obj: any): string {
  const str = JSON.stringify(obj, Object.keys(obj).sort())
  return createHash('sha1').update(str).digest('hex')
}

/**
 * Extract primary key values from query parameters
 * Returns null if primary key fields are not all present in the where clause
 */
export function extractPrimaryKeyValues(
  modelName: PrismaModelName,
  params: QueryParams
): Record<string, any> | null {
  const where = params.where
  if (!where) return null

  const pkFields = getPrimaryKeyFields(modelName)
  const pkValues: Record<string, any> = {}

  // Check if all primary key fields are present in where clause
  for (const field of pkFields) {
    if (!(field in where)) {
      return null
    }
    pkValues[field] = where[field]
  }

  return pkValues
}

/**
 * Generate cache key for a primary key lookup
 * Format: {ModelName}/{field1}/{value1}/{field2}/{value2}...
 */
export function generatePrimaryKeyCacheKey(
  modelName: PrismaModelName,
  pkValues: Record<string, any>
): string {
  const pkFields = getPrimaryKeyFields(modelName)

  // Sort fields alphabetically for consistency
  const sortedFields = [...pkFields].sort()

  // Build cache key with field/value pairs
  const parts: string[] = [modelName]
  for (const field of sortedFields) {
    parts.push(field, String(pkValues[field]))
  }

  return parts.join('/')
}

/**
 * Generate cache key for a query (non-primary key lookup)
 * Format: {ModelName}/q/{sha1-hash-of-params}
 */
export function generateQueryCacheKey(
  modelName: PrismaModelName,
  params: QueryParams
): string {
  // Create a normalized version of params for hashing
  const normalizedParams: any = {}

  // Include relevant query parameters in the hash
  if (params.where) normalizedParams.where = params.where
  if (params.select) normalizedParams.select = params.select
  if (params.include) normalizedParams.include = params.include
  if (params.orderBy) normalizedParams.orderBy = params.orderBy
  if (params.skip !== undefined) normalizedParams.skip = params.skip
  if (params.take !== undefined) normalizedParams.take = params.take

  const hash = hashObject(normalizedParams)
  return `${modelName}/q/${hash}`
}

/**
 * Main cache key generation function
 * Determines whether to use primary key or query-based cache key
 */
export function generateCacheKey(
  modelName: PrismaModelName,
  params: QueryParams
): string {
  // Try to extract primary key values
  const pkValues = extractPrimaryKeyValues(modelName, params)

  if (pkValues) {
    // Use primary key-based cache key
    return generatePrimaryKeyCacheKey(modelName, pkValues)
  } else {
    // Use query-based cache key with hash
    return generateQueryCacheKey(modelName, params)
  }
}

/**
 * Key generator function type
 */
export type KeyGenFunction = (params: QueryParams) => string

/**
 * Create a key generator function for a specific model
 */
export function createKeyGenerator(modelName: PrismaModelName): KeyGenFunction {
  return (params: QueryParams) => generateCacheKey(modelName, params)
}

/**
 * Default key generators for all models (will be populated from generated metadata)
 * This is a type-safe map of model names to key generator functions
 */
export const DEFAULT_KEY_GENERATORS: Record<PrismaModelName, KeyGenFunction> = {
  GitHubUser: createKeyGenerator('GitHubUser'),
  GitHubUserEmail: createKeyGenerator('GitHubUserEmail'),
  GitHubOrganization: createKeyGenerator('GitHubOrganization'),
  GitHubRepository: createKeyGenerator('GitHubRepository'),
  Dependency: createKeyGenerator('Dependency'),
  DependencySLSAProvenance: createKeyGenerator('DependencySLSAProvenance'),
  DependencyAttestation: createKeyGenerator('DependencyAttestation'),
  GitHubRepoDependency: createKeyGenerator('GitHubRepoDependency'),
  CVEMetadataReferences: createKeyGenerator('CVEMetadataReferences'),
  CVEMetadata: createKeyGenerator('CVEMetadata'),
  CVEAlias: createKeyGenerator('CVEAlias'),
  CVENumberingAuthority: createKeyGenerator('CVENumberingAuthority'),
  CVEADP: createKeyGenerator('CVEADP'),
  AuthorizedDataPublisher: createKeyGenerator('AuthorizedDataPublisher'),
  CVEProblemType: createKeyGenerator('CVEProblemType'),
  CVEMetric: createKeyGenerator('CVEMetric'),
  CVEAffected: createKeyGenerator('CVEAffected'),
  CVEAffectedVersion: createKeyGenerator('CVEAffectedVersion'),
  PackageVersion: createKeyGenerator('PackageVersion'),
  PackageVersionCVE: createKeyGenerator('PackageVersionCVE'),
  CVEDescription: createKeyGenerator('CVEDescription'),
  CVEImpact: createKeyGenerator('CVEImpact'),
  CVEImpactDescription: createKeyGenerator('CVEImpactDescription'),
  GcveIssuance: createKeyGenerator('GcveIssuance'),
  GcveAlias: createKeyGenerator('GcveAlias'),
  GitHubRepoContributor: createKeyGenerator('GitHubRepoContributor'),
  Languages: createKeyGenerator('Languages'),
  GitHubRepoLanguage: createKeyGenerator('GitHubRepoLanguage'),
  GitHubRepoPackageManager: createKeyGenerator('GitHubRepoPackageManager'),
  Pix: createKeyGenerator('Pix'),
  PixLog: createKeyGenerator('PixLog'),
  EpssScore: createKeyGenerator('EpssScore'),
  CessScore: createKeyGenerator('CessScore'),
  CrowdSecLog: createKeyGenerator('CrowdSecLog'),
  CrowdSecSighting: createKeyGenerator('CrowdSecSighting'),
  Kev: createKeyGenerator('Kev'),
  BulkDataDumpTracker: createKeyGenerator('BulkDataDumpTracker'),
  VulnCheckKEV: createKeyGenerator('VulnCheckKEV'),
  VulnCheckKEVCVE: createKeyGenerator('VulnCheckKEVCVE'),
  VulnCheckKEVCWE: createKeyGenerator('VulnCheckKEVCWE'),
  VulnCheckXDB: createKeyGenerator('VulnCheckXDB'),
  VulnCheckReportedExploitation: createKeyGenerator('VulnCheckReportedExploitation'),
  OpenSSFScorecard: createKeyGenerator('OpenSSFScorecard'),
  OpenSSFScorecardCheck: createKeyGenerator('OpenSSFScorecardCheck'),
  SSVCDecision: createKeyGenerator('SSVCDecision'),
} as const
