-- PostgreSQL Migration: Sync with D1 Schema
-- Purpose: Add missing columns from vulnetix-saas D1 schema to vdb-api PostgreSQL
-- Date: 2025-11-28
-- Apply with: psql -d vdb -f sync_with_d1_schema.sql

BEGIN;

-- ============================================================================
-- CVEMetadata: Add malicious package tracking
-- ============================================================================
ALTER TABLE "CVEMetadata"
ADD COLUMN IF NOT EXISTS "isMaliciousPackage" INTEGER DEFAULT 0;

CREATE INDEX IF NOT EXISTS "CVEMetadata_isMaliciousPackage_idx"
ON "CVEMetadata"("isMaliciousPackage");

COMMENT ON COLUMN "CVEMetadata"."isMaliciousPackage" IS 'OpenSSF malicious package flag: 0 = false, 1 = true';

-- ============================================================================
-- CVEAffected: Add deduplication hash field
-- ============================================================================
ALTER TABLE "CVEAffected"
ADD COLUMN IF NOT EXISTS "affectedHash" TEXT;

-- Update existing rows with hash (MD5 of vendor|product|collectionURL|packageName)
-- This is a placeholder - actual hash generation should be done via application code
UPDATE "CVEAffected"
SET "affectedHash" = MD5(
    COALESCE("vendor", '') || '|' ||
    COALESCE("product", '') || '|' ||
    COALESCE("collectionURL", '') || '|' ||
    COALESCE("packageName", '')
)
WHERE "affectedHash" IS NULL;

-- Make affectedHash NOT NULL after population
ALTER TABLE "CVEAffected"
ALTER COLUMN "affectedHash" SET NOT NULL;

-- Add unique constraint for deduplication
CREATE UNIQUE INDEX IF NOT EXISTS "CVEAffected_cveId_source_containerType_affectedHash_key"
ON "CVEAffected"("cveId", "source", "containerType", "affectedHash");

CREATE INDEX IF NOT EXISTS "CVEAffected_affectedHash_idx"
ON "CVEAffected"("affectedHash");

COMMENT ON COLUMN "CVEAffected"."affectedHash" IS 'MD5 hash of vendor|product|collectionURL|packageName for efficient deduplication';

-- ============================================================================
-- GitHubRepository: Add avatarUrl field
-- ============================================================================
ALTER TABLE "GitHubRepository"
ADD COLUMN IF NOT EXISTS "avatarUrl" TEXT;

COMMENT ON COLUMN "GitHubRepository"."avatarUrl" IS 'Avatar URL for the repository owner (user or organization)';

-- ============================================================================
-- CVEMetric: Add unique constraint to prevent duplicate metrics
-- ============================================================================
CREATE UNIQUE INDEX IF NOT EXISTS "CVEMetric_composite_unique_key"
ON "CVEMetric"("cveId", "source", "containerType", "adpOrgId", "metricType", "vectorString");

COMMENT ON INDEX "CVEMetric_composite_unique_key" IS 'Prevents duplicate CVSS/SSVC metrics for the same CVE';

COMMIT;

-- ============================================================================
-- Verification Queries
-- ============================================================================

-- Verify new columns exist
SELECT
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_name IN ('CVEMetadata', 'CVEAffected', 'GitHubRepository')
    AND column_name IN ('isMaliciousPackage', 'affectedHash', 'avatarUrl')
ORDER BY table_name, column_name;

-- Verify new indexes exist
SELECT
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE indexname IN (
    'CVEMetadata_isMaliciousPackage_idx',
    'CVEAffected_cveId_source_containerType_affectedHash_key',
    'CVEAffected_affectedHash_idx',
    'CVEMetric_composite_unique_key'
)
ORDER BY tablename, indexname;

-- ============================================================================
-- Notes
-- ============================================================================
/*
IMPORTANT: After running this migration:

1. Update vdb-api/prisma/schema.prisma to include the new fields:
   - CVEMetadata.isMaliciousPackage
   - CVEAffected.affectedHash
   - GitHubRepository.avatarUrl

2. Regenerate Prisma client:
   cd /home/chris/GitHub/vdb-api
   npx prisma generate

3. Update any application code that creates CVEAffected records to calculate affectedHash

4. Test that all API endpoints still work with the new schema
*/
