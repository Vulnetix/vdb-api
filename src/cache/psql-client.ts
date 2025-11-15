import type { PrismaClient } from '@prisma/client'
import type { PrismaModelName } from './generated/prisma-metadata'
import type { CacheOptions } from './cache-options'
import { DEFAULT_CACHE_OPTIONS, getTtl } from './cache-options'
import { generateCacheKey, extractPrimaryKeyValues, type QueryParams } from './cache-key-generator'
import { createCacheInvalidator, type InvalidationParams } from './cache-invalidator'

/**
 * Cache metrics for monitoring cache performance
 */
export interface CacheMetrics {
  hits: number
  misses: number
  errors: number
  invalidations: number
}

/**
 * Options for raw query caching
 */
export interface RawQueryCacheOptions {
  /** Custom cache key for the raw query */
  cacheKey: string
  /** TTL in seconds */
  ttl?: number
  /** Whether to cache the result */
  cache?: boolean
}

/**
 * Main psql client that wraps Prisma with KV caching
 */
export class PsqlClient {
  private invalidator: ReturnType<typeof createCacheInvalidator>
  private metrics: CacheMetrics = {
    hits: 0,
    misses: 0,
    errors: 0,
    invalidations: 0,
  }

  constructor(
    private prisma: PrismaClient,
    private kv: KVNamespace,
    private options: CacheOptions = DEFAULT_CACHE_OPTIONS
  ) {
    this.invalidator = createCacheInvalidator(kv)
  }

  /**
   * Get cache metrics
   */
  getMetrics(): CacheMetrics {
    return { ...this.metrics }
  }

  /**
   * Reset cache metrics
   */
  resetMetrics(): void {
    this.metrics = {
      hits: 0,
      misses: 0,
      errors: 0,
      invalidations: 0,
    }
  }

  /**
   * Get value from cache
   */
  private async getFromCache<T>(cacheKey: string): Promise<T | null> {
    try {
      const cached = await this.kv.get(cacheKey, 'json')
      if (cached !== null) {
        this.metrics.hits++
        if (this.options.enableMetrics) {
          console.log(`Cache HIT: ${cacheKey}`)
        }
        return cached as T
      }
      this.metrics.misses++
      if (this.options.enableMetrics) {
        console.log(`Cache MISS: ${cacheKey}`)
      }
      return null
    } catch (error) {
      this.metrics.errors++
      console.error(`Cache read error for ${cacheKey}:`, error)
      return null
    }
  }

  /**
   * Set value in cache
   */
  private async setInCache<T>(cacheKey: string, value: T, ttl: number): Promise<void> {
    try {
      await this.kv.put(cacheKey, JSON.stringify(value), {
        expirationTtl: ttl,
      })
      if (this.options.enableMetrics) {
        console.log(`Cache SET: ${cacheKey} (TTL: ${ttl}s)`)
      }
    } catch (error) {
      this.metrics.errors++
      console.error(`Cache write error for ${cacheKey}:`, error)
    }
  }

  /**
   * Execute a read operation with caching
   */
  private async executeRead<T>(
    modelName: PrismaModelName,
    operation: string,
    params: QueryParams,
    executor: () => Promise<T>
  ): Promise<T> {
    // Generate cache key
    const cacheKey = generateCacheKey(modelName, params)

    // Check if this is a primary key lookup
    const pkValues = extractPrimaryKeyValues(modelName, params)
    const isPrimaryKeyLookup = pkValues !== null

    // Get TTL for this operation
    const ttl = getTtl(modelName, isPrimaryKeyLookup, this.options)

    // Try to get from cache
    const cached = await this.getFromCache<T>(cacheKey)
    if (cached !== null) {
      return cached
    }

    // Execute the query
    const result = await executor()

    // Only cache non-null results (as per user requirement)
    if (result !== null && result !== undefined) {
      // For arrays, only cache if not empty
      if (Array.isArray(result)) {
        if (result.length > 0) {
          await this.setInCache(cacheKey, result, ttl)
        }
      } else {
        await this.setInCache(cacheKey, result, ttl)
      }
    }

    return result
  }

  /**
   * Execute a write operation with cache invalidation
   */
  private async executeWrite<T>(
    modelName: PrismaModelName,
    operation: 'create' | 'update' | 'delete' | 'upsert' | 'createMany' | 'updateMany' | 'deleteMany',
    params: InvalidationParams,
    executor: () => Promise<T>
  ): Promise<T> {
    // Execute the write operation
    const result = await executor()

    // Invalidate cache
    try {
      const invalidationResult = await this.invalidator.invalidate(modelName, operation, params)
      if (invalidationResult.success) {
        this.metrics.invalidations += invalidationResult.keysInvalidated.length
        if (this.options.enableMetrics && invalidationResult.keysInvalidated.length > 0) {
          console.log(`Cache invalidated: ${invalidationResult.keysInvalidated.join(', ')}`)
        }
      }
    } catch (error) {
      this.metrics.errors++
      console.error(`Cache invalidation error for ${modelName}:`, error)
    }

    return result
  }

  /**
   * Generic method wrapper for type-safe operations
   */
  async findFirst<T>(modelName: PrismaModelName, params: QueryParams = {}): Promise<T | null> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeRead(
      modelName,
      'findFirst',
      params,
      () => model.findFirst(params)
    )
  }

  async findUnique<T>(modelName: PrismaModelName, params: QueryParams): Promise<T | null> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeRead(
      modelName,
      'findUnique',
      params,
      () => model.findUnique(params)
    )
  }

  async findMany<T>(modelName: PrismaModelName, params: QueryParams = {}): Promise<T[]> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeRead(
      modelName,
      'findMany',
      params,
      () => model.findMany(params)
    )
  }

  async count(modelName: PrismaModelName, params: QueryParams = {}): Promise<number> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeRead(
      modelName,
      'count',
      params,
      () => model.count(params)
    )
  }

  async aggregate<T>(modelName: PrismaModelName, params: QueryParams): Promise<T> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeRead(
      modelName,
      'aggregate',
      params,
      () => model.aggregate(params)
    )
  }

  async groupBy<T>(modelName: PrismaModelName, params: QueryParams): Promise<T[]> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeRead(
      modelName,
      'groupBy',
      params,
      () => model.groupBy(params)
    )
  }

  // Write operations

  async create<T>(modelName: PrismaModelName, params: InvalidationParams): Promise<T> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeWrite(
      modelName,
      'create',
      params,
      () => model.create(params)
    )
  }

  async createMany<T>(modelName: PrismaModelName, params: InvalidationParams): Promise<T> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeWrite(
      modelName,
      'createMany',
      params,
      () => model.createMany(params)
    )
  }

  async update<T>(modelName: PrismaModelName, params: InvalidationParams): Promise<T> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeWrite(
      modelName,
      'update',
      params,
      () => model.update(params)
    )
  }

  async updateMany<T>(modelName: PrismaModelName, params: InvalidationParams): Promise<T> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeWrite(
      modelName,
      'updateMany',
      params,
      () => model.updateMany(params)
    )
  }

  async delete<T>(modelName: PrismaModelName, params: InvalidationParams): Promise<T> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeWrite(
      modelName,
      'delete',
      params,
      () => model.delete(params)
    )
  }

  async deleteMany<T>(modelName: PrismaModelName, params: InvalidationParams): Promise<T> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeWrite(
      modelName,
      'deleteMany',
      params,
      () => model.deleteMany(params)
    )
  }

  async upsert<T>(modelName: PrismaModelName, params: InvalidationParams): Promise<T> {
    const model = (this.prisma as any)[modelName.charAt(0).toLowerCase() + modelName.slice(1)]
    return this.executeWrite(
      modelName,
      'upsert',
      params,
      () => model.upsert(params)
    )
  }

  // Raw query support

  async $queryRaw<T>(
    query: TemplateStringsArray | string,
    options?: RawQueryCacheOptions,
    ...values: any[]
  ): Promise<T> {
    // If caching is disabled or no cache key provided, execute directly
    if (!options || !options.cache || !options.cacheKey) {
      if (typeof query === 'string') {
        return this.prisma.$queryRawUnsafe<T>(query, ...values)
      }
      return this.prisma.$queryRaw<T>(query as TemplateStringsArray, ...values)
    }

    // Use custom cache key
    const cacheKey = `raw/${options.cacheKey}`
    const ttl = options.ttl || this.options.defaultTtl || 900

    // Try to get from cache
    const cached = await this.getFromCache<T>(cacheKey)
    if (cached !== null) {
      return cached
    }

    // Execute the query
    const result = typeof query === 'string'
      ? await this.prisma.$queryRawUnsafe<T>(query, ...values)
      : await this.prisma.$queryRaw<T>(query as TemplateStringsArray, ...values)

    // Cache the result if not null
    if (result !== null && result !== undefined) {
      await this.setInCache(cacheKey, result, ttl)
    }

    return result
  }

  async $executeRaw(
    query: TemplateStringsArray | string,
    ...values: any[]
  ): Promise<number> {
    // Execute operations don't cache, they just execute
    if (typeof query === 'string') {
      return this.prisma.$executeRawUnsafe(query, ...values)
    }
    return this.prisma.$executeRaw(query as TemplateStringsArray, ...values)
  }

  /**
   * Direct access to Prisma client for complex operations
   */
  get raw(): PrismaClient {
    return this.prisma
  }

  /**
   * Transaction support - delegates to Prisma's transaction method
   * Note: Transactions bypass caching
   */
  async $transaction<T>(callback: (tx: PrismaClient) => Promise<T>): Promise<T> {
    return this.prisma.$transaction(callback)
  }
}

/**
 * Create a new PsqlClient instance
 */
export function createPsqlClient(
  prisma: PrismaClient,
  kv: KVNamespace,
  options?: CacheOptions
): PsqlClient {
  return new PsqlClient(prisma, kv, options)
}
