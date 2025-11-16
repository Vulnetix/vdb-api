-- Product View - Aggregates package/product names across all tables
-- This view provides normalized access to product information from multiple sources
-- Use this instead of querying individual tables directly for product lookups
--
-- Installation:
--   psql $DATABASE_URL -f sql/views/product_view.sql
--
-- Usage Examples:
--   -- Find all sources for a package
--   SELECT * FROM v_product_index WHERE package_name = 'express';
--
--   -- Find packages in specific ecosystem
--   SELECT DISTINCT package_name FROM v_product_index WHERE ecosystem = 'npm';
--
--   -- Count packages per ecosystem
--   SELECT ecosystem, COUNT(DISTINCT package_name) FROM v_product_index GROUP BY ecosystem;

-- Drop existing view if it exists
DROP VIEW IF EXISTS v_product_index CASCADE;
-- DROP MATERIALIZED VIEW IF EXISTS v_product_index CASCADE;

-- Create the product index view
CREATE OR REPLACE VIEW v_product_index AS
WITH all_products AS (
    -- GitHub Repositories
    SELECT 
        LOWER(COALESCE("packageName", name, SPLIT_PART("fullName", '/', 2))) AS package_name,
        LOWER(COALESCE("packageEcosystem", 'unknown')) AS ecosystem,
        'github_repository' AS source_table,
        id::TEXT AS source_id,
        "packageVersion" AS version
    FROM "GitHubRepository"
    WHERE "packageName" IS NOT NULL OR name IS NOT NULL
    
    UNION ALL
    
    -- CVE Affected Products
    SELECT 
        LOWER(COALESCE("packageName", product)) AS package_name,
        'unknown' AS ecosystem,
        'cve_affected' AS source_table,
        uuid AS source_id,
        NULL AS version
    FROM "CVEAffected"
    WHERE product IS NOT NULL OR "packageName" IS NOT NULL
    
    UNION ALL
    
    -- Package Versions
    SELECT 
        LOWER("packageName") AS package_name,
        LOWER(ecosystem) AS ecosystem,
        'package_version' AS source_table,
        uuid AS source_id,
        version
    FROM "PackageVersion"
    WHERE "packageName" IS NOT NULL
    
    UNION ALL
    
    -- Dependencies
    SELECT 
        LOWER(name) AS package_name,
        LOWER(COALESCE("packageEcosystem", 'unknown')) AS ecosystem,
        'dependency' AS source_table,
        key AS source_id,
        version
    FROM "Dependency"
    WHERE name IS NOT NULL
    
    UNION ALL
    
    -- CISA KEV Entries
    SELECT 
        LOWER(product) AS package_name,
        'unknown' AS ecosystem,
        'kev' AS source_table,
        "cveID" AS source_id,
        NULL AS version
    FROM "Kev"
    WHERE product IS NOT NULL
    
    UNION ALL
    
    -- VulnCheck KEV
    SELECT 
        LOWER(product) AS package_name,
        'unknown' AS ecosystem,
        'vulncheck_kev' AS source_table,
        uuid AS source_id,
        NULL AS version
    FROM "VulnCheckKEV"
    WHERE product IS NOT NULL
    
    UNION ALL
    
    -- CVE Metadata (legacy fields - being deprecated but still in use)
    SELECT 
        LOWER("affectedProduct") AS package_name,
        'unknown' AS ecosystem,
        'cve_metadata' AS source_table,
        "cveId" AS source_id,
        NULL AS version
    FROM "CVEMetadata"
    WHERE "affectedProduct" IS NOT NULL
    
    UNION ALL
    
    -- OpenSSF Scorecard repositories (repository names often match package names)
    SELECT 
        LOWER(SPLIT_PART("repositoryName", '/', 2)) AS package_name,
        'unknown' AS ecosystem,
        'openssf_scorecard' AS source_table,
        uuid AS source_id,
        NULL AS version
    FROM "OpenSSFScorecard"
    WHERE "repositoryName" IS NOT NULL
        AND "repositoryName" LIKE '%/%' -- Ensure it's a valid org/repo format
)
SELECT DISTINCT
    package_name,
    ecosystem,
    source_table,
    source_id,
    version
FROM all_products
WHERE package_name IS NOT NULL
    AND package_name != '' -- Exclude empty strings
    AND LENGTH(package_name) > 0; -- Extra safety check

-- Note: Regular views cannot have indexes created directly on them
-- The view will use indexes from the underlying base tables
-- Make sure the following indexes exist on the base tables for optimal query performance:

-- Suggested indexes for base tables (uncomment and run if not already present):
CREATE INDEX IF NOT EXISTS idx_github_repo_package_name ON "GitHubRepository"(LOWER("packageName"));
CREATE INDEX IF NOT EXISTS idx_github_repo_name ON "GitHubRepository"(LOWER(name));
CREATE INDEX IF NOT EXISTS idx_github_repo_ecosystem ON "GitHubRepository"(LOWER("packageEcosystem"));
CREATE INDEX IF NOT EXISTS idx_cve_affected_package ON "CVEAffected"(LOWER("packageName"));
CREATE INDEX IF NOT EXISTS idx_cve_affected_product ON "CVEAffected"(LOWER(product));
CREATE INDEX IF NOT EXISTS idx_package_version_name ON "PackageVersion"(LOWER("packageName"));
CREATE INDEX IF NOT EXISTS idx_package_version_eco ON "PackageVersion"(LOWER(ecosystem));
CREATE INDEX IF NOT EXISTS idx_dependency_name ON "Dependency"(LOWER(name));
CREATE INDEX IF NOT EXISTS idx_dependency_ecosystem ON "Dependency"(LOWER("packageEcosystem"));
CREATE INDEX IF NOT EXISTS idx_kev_product ON "Kev"(LOWER(product));
CREATE INDEX IF NOT EXISTS idx_vulncheck_kev_product ON "VulnCheckKEV"(LOWER(product));
CREATE INDEX IF NOT EXISTS idx_cve_metadata_product ON "CVEMetadata"(LOWER("affectedProduct"));
CREATE INDEX IF NOT EXISTS idx_scorecard_repo_name ON "OpenSSFScorecard"(LOWER("repositoryName"));

-- Performance Note:
-- This is a regular view, so it queries the underlying tables in real-time
-- Benefits:
--   - Always shows current data (no refresh needed)
--   - No storage overhead
--   - Automatically reflects changes in source tables
-- 
-- The view performance depends on:
--   1. Indexes on the base tables (created above)
--   2. Query result caching via the psql client (automatic in the application)
--   3. PostgreSQL's query optimizer
-- 
-- For very large datasets, consider using the cached psql client which provides
-- automatic KV-based caching of query results with configurable TTL.
