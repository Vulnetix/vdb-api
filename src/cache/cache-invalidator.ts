import type { PrismaModelName } from './generated/prisma-metadata'
import { extractPrimaryKeyValues, generatePrimaryKeyCacheKey } from './cache-key-generator'

/**
 * Parameters that can be used for cache invalidation
 */
export type InvalidationParams = {
  where?: Record<string, any>
  data?: Record<string, any>
  [key: string]: any
}

/**
 * Result of invalidation operation
 */
export interface InvalidationResult {
  success: boolean
  keysInvalidated: string[]
  errors?: string[]
}

/**
 * Cache invalidator class for managing cache invalidation on write operations
 */
export class CacheInvalidator {
  constructor(private kv: KVNamespace) {}

  /**
   * Invalidate cache entry by exact cache key
   */
  async invalidateKey(cacheKey: string): Promise<boolean> {
    try {
      await this.kv.delete(cacheKey)
      return true
    } catch (error) {
      console.error(`Failed to invalidate cache key ${cacheKey}:`, error)
      return false
    }
  }

  /**
   * Invalidate cache entries by primary key values
   * Only invalidates the specific primary key-based cache entry
   */
  async invalidatePrimaryKey(
    modelName: PrismaModelName,
    pkValues: Record<string, any>
  ): Promise<InvalidationResult> {
    const keysInvalidated: string[] = []
    const errors: string[] = []

    try {
      // Generate primary key cache key
      const cacheKey = generatePrimaryKeyCacheKey(modelName, pkValues)

      // Delete the cache entry
      const success = await this.invalidateKey(cacheKey)

      if (success) {
        keysInvalidated.push(cacheKey)
      } else {
        errors.push(`Failed to invalidate ${cacheKey}`)
      }
    } catch (error) {
      errors.push(`Error during invalidation: ${error}`)
    }

    return {
      success: errors.length === 0,
      keysInvalidated,
      errors: errors.length > 0 ? errors : undefined,
    }
  }

  /**
   * Invalidate cache for a create operation
   * Creates don't have a "where" clause, so we extract PK from the data
   */
  async invalidateForCreate(
    modelName: PrismaModelName,
    params: InvalidationParams
  ): Promise<InvalidationResult> {
    // For creates, we typically don't need to invalidate anything
    // because the record didn't exist before
    // However, if we're caching null results, we might want to invalidate query caches
    // For now, we'll just return success with no keys invalidated
    return {
      success: true,
      keysInvalidated: [],
    }
  }

  /**
   * Invalidate cache for an update operation
   * Updates have a where clause to identify which record(s) to update
   */
  async invalidateForUpdate(
    modelName: PrismaModelName,
    params: InvalidationParams
  ): Promise<InvalidationResult> {
    // Extract primary key from where clause
    const pkValues = extractPrimaryKeyValues(modelName, { where: params.where })

    if (pkValues) {
      // Invalidate the specific primary key cache
      return await this.invalidatePrimaryKey(modelName, pkValues)
    }

    // If we can't determine the primary key, we can't invalidate
    // This might happen with updateMany or complex where clauses
    return {
      success: true,
      keysInvalidated: [],
    }
  }

  /**
   * Invalidate cache for a delete operation
   * Deletes have a where clause to identify which record(s) to delete
   */
  async invalidateForDelete(
    modelName: PrismaModelName,
    params: InvalidationParams
  ): Promise<InvalidationResult> {
    // Extract primary key from where clause
    const pkValues = extractPrimaryKeyValues(modelName, { where: params.where })

    if (pkValues) {
      // Invalidate the specific primary key cache
      return await this.invalidatePrimaryKey(modelName, pkValues)
    }

    // If we can't determine the primary key, we can't invalidate
    // This might happen with deleteMany or complex where clauses
    return {
      success: true,
      keysInvalidated: [],
    }
  }

  /**
   * Invalidate cache for an upsert operation
   * Upserts have both where and create/update data
   */
  async invalidateForUpsert(
    modelName: PrismaModelName,
    params: InvalidationParams
  ): Promise<InvalidationResult> {
    // For upsert, we need to invalidate based on the where clause
    // since it might be an update
    const pkValues = extractPrimaryKeyValues(modelName, { where: params.where })

    if (pkValues) {
      // Invalidate the specific primary key cache
      return await this.invalidatePrimaryKey(modelName, pkValues)
    }

    // If we can't determine the primary key, we can't invalidate
    return {
      success: true,
      keysInvalidated: [],
    }
  }

  /**
   * General invalidation method that determines the operation type
   */
  async invalidate(
    modelName: PrismaModelName,
    operation: 'create' | 'update' | 'delete' | 'upsert' | 'createMany' | 'updateMany' | 'deleteMany',
    params: InvalidationParams
  ): Promise<InvalidationResult> {
    switch (operation) {
      case 'create':
      case 'createMany':
        return await this.invalidateForCreate(modelName, params)

      case 'update':
      case 'updateMany':
        return await this.invalidateForUpdate(modelName, params)

      case 'delete':
      case 'deleteMany':
        return await this.invalidateForDelete(modelName, params)

      case 'upsert':
        return await this.invalidateForUpsert(modelName, params)

      default:
        return {
          success: false,
          keysInvalidated: [],
          errors: [`Unknown operation: ${operation}`],
        }
    }
  }
}

/**
 * Create a cache invalidator instance
 */
export function createCacheInvalidator(kv: KVNamespace): CacheInvalidator {
  return new CacheInvalidator(kv)
}
