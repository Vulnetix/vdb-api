/**
 * R2-based caching utility for external API responses
 * Caches responses using date-based keys to ensure daily freshness
 */

interface CacheOptions {
    r2bucket: any;
    logger?: any;
}

export class ApiCache {
    private r2bucket: any;
    private logger: any;

    constructor(options: CacheOptions) {
        this.r2bucket = options.r2bucket;
        this.logger = options.logger || console;
    }

    /**
     * Generate cache key with date-based versioning
     */
    private generateCacheKey(apiName: string, identifier: string): string {
        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
        return `api-cache/${apiName}/${encodeURIComponent(identifier)}/${today}.json`;
    }

    /**
     * Attempt to retrieve cached response from R2
     */
    async getFromCache(apiName: string, identifier: string): Promise<any> {
        // Validate r2bucket has required methods
        if (!this.r2bucket || typeof this.r2bucket.get !== 'function') {
            this.logger?.debug?.(`R2 bucket not available or invalid for cache reads`);
            return null;
        }

        try {
            const cacheKey = this.generateCacheKey(apiName, identifier);

            const cachedResponse = await this.r2bucket.get(cacheKey);
            if (cachedResponse) {
                const data = await cachedResponse.json();
                this.logger?.debug?.(`Cache hit for ${apiName}/${identifier}`);
                return data;
            }

            this.logger?.debug?.(`Cache miss for ${apiName}/${identifier}`);
            return null;
        } catch (error) {
            this.logger?.warn?.(`Failed to read from cache for ${apiName}/${identifier}:`, error.message);
            return null;
        }
    }

    /**
     * Store response in R2 cache
     */
    async storeInCache(apiName: string, identifier: string, data: any): Promise<void> {
        // Validate r2bucket has required methods
        if (!this.r2bucket || typeof this.r2bucket.put !== 'function') {
            this.logger?.debug?.(`R2 bucket not available or invalid for cache writes`);
            return;
        }

        try {
            const cacheKey = this.generateCacheKey(apiName, identifier);

            await this.r2bucket.put(cacheKey, JSON.stringify({
                data,
                cachedAt: new Date().toISOString(),
                cacheKey
            }));

            this.logger?.debug?.(`Cached response for ${apiName}/${identifier}`);
        } catch (error) {
            this.logger?.warn?.(`Failed to store in cache for ${apiName}/${identifier}:`, error.message);
            // Don't throw - caching failures shouldn't break the API call
        }
    }

    /**
     * Wrapper function to handle caching for API calls
     * First checks cache, if miss then calls the provided function and caches result
     */
    async withCache<T>(
        apiName: string,
        identifier: string,
        apiCall: () => Promise<T>
    ): Promise<T> {
        // Try to get from cache first
        const cached = await this.getFromCache(apiName, identifier);
        if (cached?.data) {
            return cached.data;
        }

        // Cache miss - make the API call
        const result = await apiCall();

        // Store in cache if we got a valid result
        if (result) {
            await this.storeInCache(apiName, identifier, result);
        }

        return result;
    }
}