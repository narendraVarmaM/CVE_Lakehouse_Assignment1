-- ============================================================================
-- CVE DATA LAKEHOUSE - INFRASTRUCTURE SETUP
-- Unity Catalog Configuration
-- ============================================================================
-- Purpose: Create catalog, schema, and volume for CVE data lakehouse
-- Target Environment: Databricks with Unity Catalog enabled
-- Author: [Your Name]
-- Date: November 2024
-- ============================================================================

-- NOTE: This setup uses the "workspace" catalog and "default" schema
-- with a volume named "assignment1" for data storage

-- Step 1: Verify workspace catalog exists (typically pre-created in Databricks)
SHOW CATALOGS LIKE 'workspace';

-- Step 2: Use the workspace catalog
USE CATALOG workspace;

-- Step 3: Verify or create default schema
CREATE SCHEMA IF NOT EXISTS default
COMMENT 'Default schema for CVE lakehouse tables';

-- Step 4: Use the default schema
USE SCHEMA default;

-- Step 5: Create volume for data storage (if not exists)
-- Volumes provide managed storage for Delta Lake tables
CREATE VOLUME IF NOT EXISTS assignment1
COMMENT 'Storage volume for CVE lakehouse data - Bronze, Silver, and Gold layers';

-- Step 6: Verify setup
SHOW SCHEMAS IN workspace;

-- Step 7: Display current configuration
SELECT
  current_catalog() as active_catalog,
  current_schema() as active_schema,
  current_user() as current_user,
  'Setup completed successfully!' as status;

-- ============================================================================
-- SETUP VALIDATION
-- ============================================================================

-- Check that catalog and schema are accessible
DESCRIBE CATALOG workspace;
DESCRIBE SCHEMA workspace.default;

-- ============================================================================
-- NEXT STEPS
-- ============================================================================
-- 1. Run 01_ingest_cvelist.py to create Bronze layer
-- 2. Run 02_bronze_to_silver.py to create Silver layer
-- 3. Run 03_gold_analysis.sql for analytical insights
-- ============================================================================