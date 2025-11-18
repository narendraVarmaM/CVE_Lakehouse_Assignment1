# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CVE Data Lakehouse - A data engineering assignment implementing a medallion architecture (Bronze-Silver-Gold) for analyzing Common Vulnerabilities and Exposures (CVE) data using Databricks, Apache Spark, and Delta Lake.

**University**: University at Buffalo
**Course**: Data Intensive Computing
**Data Source**: GitHub CVE Project (cvelistV5)

## Technology Stack

- **Platform**: Databricks (Serverless Compute)
- **Storage**: Delta Lake with ACID transactions
- **Catalog**: Unity Catalog (`workspace.default`)
- **Volume**: `assignment1`
- **Languages**: Python (PySpark) and SQL

## Configuration

```python
WORKSPACE_CATALOG = "workspace"
BRONZE_SCHEMA = "default"
DATA_VOLUME = "assignment1"

# Storage paths
BRONZE_DELTA_LOCATION = "/Volumes/workspace/default/assignment1/cve_data/bronze"
SILVER_CORE_LOCATION = "/Volumes/workspace/default/assignment1/cve_data/silver/core_cves"
SILVER_AFFECTED_LOCATION = "/Volumes/workspace/default/assignment1/cve_data/silver/affected_products"
```

## Project Structure

```
CVE_Lakehouse_Assignment1/
├── 00_setup_create_catalog.sql     # Unity Catalog setup
├── 01_ingest_cvelist.py             # Bronze layer (raw ingestion)
├── 02_bronze_to_silver.py           # Silver layer (transformation)
├── 03_gold_analysis.sql             # Gold layer (analytics)
├── README.md                        # Project documentation
└── CLAUDE.md                        # This file
```

## Execution Sequence for Databricks

### Step 1: Infrastructure Setup (SQL)
**File**: `00_setup_create_catalog.sql`
**Environment**: Databricks SQL Editor or SQL Notebook

```sql
-- Creates/verifies workspace catalog
-- Creates default schema
-- Creates assignment1 volume
```

### Step 2: Bronze Layer - Data Ingestion (Python)
**File**: `01_ingest_cvelist.py`
**Environment**: Databricks Python Notebook
**Runtime**: 10-15 minutes

**Process**:
1. Downloads CVE repository as ZIP archive (faster than git clone)
2. Extracts to `/tmp/cve_assignment/cvelistV5-main`
3. Processes ~38,000 JSON files from `cves/2024/` directory
4. Converts nested JSON to Pandas DataFrame
5. Handles Arrow serialization by converting nested structures to JSON strings
6. Creates Spark DataFrame with metadata columns
7. Writes to Delta Lake at bronze location

**Key Code Patterns**:
```python
# Nested structure handling for Arrow compatibility
pandas_df["containers"] = pandas_df["containers"].apply(
    lambda x: json.dumps(x) if x is not None else None
)

# Add metadata columns
enriched_df = (
    spark_df
    .withColumn("_ingestion_timestamp", current_timestamp())
    .withColumn("_source_year", lit(year))
)
```

### Step 3: Silver Layer - Transformation (Python)
**File**: `02_bronze_to_silver.py`
**Environment**: Databricks Python Notebook
**Runtime**: 3-5 minutes

**Transformations**:

**A. Core CVE Table**:
1. Extract base metadata (CVE ID, state, dates)
2. Parse English descriptions from nested arrays using explode_outer
3. Extract CVSS scores with coalesce logic (prefer v3.1 → v3.0)
4. Add quality indicators and risk categories

**B. Affected Products Table**:
1. Extract affected products array
2. Apply explode_outer for one-to-many transformation
3. Extract vendor, product, version information

**Important Patterns**:

```python
# CVSS version coalescing
coalesce(max(col("cvss31_score")), max(col("cvss30_score"))).alias("cvss_base_score")

# English description extraction
.withColumn("desc_array", expr("container_data.cna.descriptions"))
.withColumn("desc_item", explode_outer(col("desc_array")))
.withColumn("english_desc",
    when(col("desc_item.lang") == "en", col("desc_item.value")).otherwise(None))

# Explode products
affected_exploded = (
    affected_raw.select(
        col("cve_id"),
        explode_outer(col("affected_products_array")).alias("product_entry")
    )
)
```

**Tables Created**:
- `workspace.default.core_cves` (~33,000 records)
- `workspace.default.affected_products` (~38,000 records)

### Step 4: Gold Layer - Analytics (SQL)
**File**: `03_gold_analysis.sql`
**Environment**: Databricks SQL Editor or SQL Notebook

**Query Sections**:
1. Data overview and summary statistics
2. Temporal analysis (daily/monthly/day-of-week)
3. CVSS score analysis and risk assessment
4. Vendor and product vulnerability analysis
5. Integrated CVE-Product analysis
6. Publication patterns and batch detection
7. Time-based risk trending
8. Data validation and integrity checks
9. Executive summary dashboard

## Data Architecture

### Bronze Layer Schema
```
cveMetadata: string (JSON)
containers: string (JSON)
dataType: string
dataVersion: string
_ingestion_timestamp: timestamp
_ingestion_date: date
_source_year: int
_record_id: bigint
```

### Silver Layer - core_cves Schema
```
cve_id: string
publication_state: string
assigning_org_id: string
assigning_org_name: string
published_timestamp: timestamp
reserved_timestamp: timestamp
updated_timestamp: timestamp
cve_description: string
cvss_base_score: double
cvss_severity_rating: string
cvss_vector: string
cvss_version_used: string
risk_category: string (CRITICAL/HIGH/MEDIUM/LOW/UNSCORED)
has_description: boolean
has_cvss: boolean
silver_transform_timestamp: timestamp
bronze_ingestion_ts: timestamp
data_year: int
```

### Silver Layer - affected_products Schema
```
cve_id: string
vendor_name: string
product_name: string
vulnerability_status: string
affected_version_info: array
affected_platforms: array
vendor_url: string
package_identifier: string
silver_transform_timestamp: timestamp
```

## Key Technical Patterns

### 1. Serverless Compatibility
- Convert nested structures to JSON strings for Arrow serialization
- Use `.saveAsTable()` or `.save()` instead of `.persist()`
- Avoid operations that require driver memory accumulation

### 2. CVSS Version Handling
```python
# Preference hierarchy: v3.1 → v3.0
coalesce(
    max(col("cvss31_score")),
    max(col("cvss30_score"))
).alias("cvss_base_score")
```

### 3. Nested Array Processing
```python
# Extract English descriptions
.withColumn("desc_array", expr("container_data.cna.descriptions"))
.withColumn("desc_item", explode_outer(col("desc_array")))
.filter(col("desc_item.lang") == "en")
```

### 4. Explode Operation
```python
# One-to-many transformation
explode_outer(col("affected_products_array")).alias("product_entry")
# Handles nulls gracefully (doesn't drop rows with empty arrays)
```

### 5. Defensive Programming
```python
# Null handling with meaningful defaults
.fillna({
    "cve_description": "[No description provided]",
    "cvss_severity_rating": "UNKNOWN"
})

# Quality indicators
.withColumn("has_cvss", col("cvss_base_score").isNotNull())
```

## Expected Results

- **Total CVE Records**: 38,000+
- **Unique CVEs**: 33,000+
- **Publication Success Rate**: 99.97%
- **CVSS Coverage**: ~80%
- **Description Coverage**: ~85%
- **Vendors**: 1,000+
- **Products**: 5,000+
- **Temporal Range**: September - November 2024

## Common Issues and Solutions

### Issue: Arrow Serialization Error
**Cause**: Nested dictionaries/lists in DataFrame
**Solution**: Convert to JSON strings before creating Spark DataFrame
```python
pandas_df["containers"] = pandas_df["containers"].apply(
    lambda x: json.dumps(x) if x is not None else None
)
```

### Issue: Volume Not Found
**Cause**: Setup not run
**Solution**: Execute `00_setup_create_catalog.sql` first

### Issue: Distinct on Map Columns
**Cause**: Serverless doesn't support distinct on complex types
**Solution**: Extract scalar values before applying distinct operations

### Issue: CVSS Scores Missing
**Cause**: Not all CVEs have CVSS scores
**Solution**: This is expected (~20% missing). Use has_cvss flag for filtering

## Data Quality Checks

After each layer, verify:

```sql
-- Bronze verification
SELECT COUNT(*) FROM delta.`/Volumes/workspace/default/assignment1/cve_data/bronze`;

-- Silver verification
SELECT COUNT(*) FROM workspace.default.core_cves;
SELECT COUNT(*) FROM workspace.default.affected_products;

-- Referential integrity
SELECT COUNT(*) FROM workspace.default.affected_products ap
LEFT ANTI JOIN workspace.default.core_cves cc ON ap.cve_id = cc.cve_id;

-- Data quality
SELECT
    COUNT(*) as total,
    SUM(CASE WHEN has_cvss THEN 1 ELSE 0 END) as with_cvss,
    SUM(CASE WHEN has_description THEN 1 ELSE 0 END) as with_description
FROM workspace.default.core_cves;
```

## Performance Optimization

- **Bronze Layer**: Batch processing with progress indicators
- **Silver Layer**: Single-pass transformations with window functions
- **Delta Lake**: Automatic optimization and schema evolution enabled
- **Serverless**: Auto-scaling eliminates manual cluster management

## Assignment Requirements Checklist

✅ Bronze Layer: Raw data ingestion with flexible schema
✅ Silver Layer: Normalized CVE metadata table
✅ Silver Layer: Affected products table with explode_outer
✅ CVSS Handling: Multiple versions (v3.1, v3.0) with coalesce
✅ Timestamp Normalization: to_timestamp() conversion
✅ Description Extraction: English descriptions from nested arrays
✅ Defensive Programming: Null handling and quality indicators
✅ Referential Integrity: CVE ID foreign key relationships
✅ Gold Layer: Analytical queries (30+)
✅ Data Validation: Integrity and quality checks

## Notes

- All code uses consistent naming: `_df` suffix for DataFrames, `_count` for counts
- Comments explain "why" not "what" (code is self-documenting)
- Progress logging at each major step for debugging
- Error handling with meaningful messages
- Schema evolution enabled for flexibility
