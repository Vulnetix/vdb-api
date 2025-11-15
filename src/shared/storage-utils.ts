export interface StorageHelper {
    get<T>(key: string, defaultValue: T): T
    set(key: string, value: any): void
    remove(key: string): void
    clear(): void
}

export interface Logger {
    warn(...args: any[]): void
    error(...args: any[]): void
    info(...args: any[]): void
    log(...args: any[]): void
}

/**
 * Creates a storage helper object for interacting with a Storage API (e.g., localStorage, sessionStorage).
 * @param storage - The Storage object to use (defaults to localStorage).
 * @param keyPrefix - A prefix to add to all keys (defaults to an empty string).
 * @param logger - A logger instance for warning and error messages (defaults to console).
 * @returns A StorageHelper object.
 * @example
 * const myStorage = createStorageHelper(localStorage, 'myAppPrefix:');
 * myStorage.set('username', 'testuser');
 * const username = myStorage.get('username', '');
 */
export const createStorageHelper = (
    storage: Storage = localStorage,
    keyPrefix: string = '',
    logger: Logger = console
): StorageHelper => ({
    /**
     * Retrieves a value from storage.
     * @template T
     * @param key - The key of the item to retrieve.
     * @param defaultValue - The value to return if the key is not found or parsing fails.
     * @returns The retrieved value or the default value.
     * @example
     * const userSettings = myStorage.get('settings', { theme: 'dark' });
     */
    get<T>(key: string, defaultValue: T): T {
        try {
            const fullKey = keyPrefix ? `${keyPrefix}${key}` : key
            const stored = storage.getItem(fullKey)
            if (stored === null) return defaultValue
            
            // Handle plain string values (for backward compatibility)
            // If the stored value is a plain string without JSON structure,
            // return it as-is if the default value is also a string
            if (typeof defaultValue === 'string' && stored !== '') {
                // Try to parse as JSON first
                try {
                    return JSON.parse(stored)
                } catch {
                    // If parsing fails and defaultValue is a string, return the plain string
                    return stored as T
                }
            }
            
            return JSON.parse(stored)
        } catch (e) {
            logger.warn(`Failed to parse stored value for key: ${key}`, e)
            return defaultValue
        }
    },

    /**
     * Stores a value in storage.
     * @param key - The key under which to store the value.
     * @param value - The value to store. Will be JSON.stringified.
     * @example
     * myStorage.set('lastLogin', new Date().getTime());
     */
    set(key: string, value: any): void {
        try {
            const fullKey = keyPrefix ? `${keyPrefix}${key}` : key
            storage.setItem(fullKey, JSON.stringify(value))
        } catch (e) {
            logger.warn(`Failed to save value for key: ${key}`, e)
        }
    },

    /**
     * Removes a value from storage.
     * @param key - The key of the item to remove.
     * @example
     * myStorage.remove('authToken');
     */
    remove(key: string): void {
        try {
            const fullKey = keyPrefix ? `${keyPrefix}${key}` : key
            storage.removeItem(fullKey)
        } catch (e) {
            logger.warn(`Failed to remove key: ${key}`, e)
        }
    },

    /**
     * Clears all items from storage, or only items with the configured prefix if a prefix is set.
     * @example
     * myStorage.clear(); // Clears all items with the prefix
     * // or if no prefix was set, clears all items in the storage instance
     */
    clear(): void {
        try {
            if (keyPrefix) {
                const keysToRemove: string[] = []
                for (let i = 0; i < storage.length; i++) {
                    const key = storage.key(i)
                    if (key && key.startsWith(keyPrefix)) {
                        keysToRemove.push(key)
                    }
                }
                keysToRemove.forEach(key => storage.removeItem(key))
            } else {
                storage.clear()
            }
        } catch (e) {
            logger.warn('Failed to clear storage', e)
        }
    }
})

export interface CacheHelper {
    isDataFresh(lastUpdated: Date | number | null, ttl?: number): boolean
    createCacheEntry<T>(data: T): { data: T; timestamp: number }
    isValidCacheEntry<T>(entry: any): entry is { data: T; timestamp: number }
}

export const createCacheHelper = (defaultTTL: number = 5 * 60 * 1000): CacheHelper => ({
    isDataFresh(lastUpdated: Date | number | null, ttl: number = defaultTTL): boolean {
        if (!lastUpdated) return false
        const timestamp = typeof lastUpdated === 'number' ? lastUpdated : lastUpdated.getTime()
        return (new Date().getTime() - timestamp) < ttl
    },

    createCacheEntry<T>(data: T): { data: T; timestamp: number } {
        return {
            data,
            timestamp: new Date().getTime()
        }
    },

    isValidCacheEntry<T>(entry: any): entry is { data: T; timestamp: number } {
        return entry && typeof entry === 'object' && 'data' in entry && 'timestamp' in entry && typeof entry.timestamp === 'number'
    }
})
