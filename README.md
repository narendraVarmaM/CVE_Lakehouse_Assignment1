# CVE Data Lakehouse - Data Engineering Assignment

**University at Buffalo - Data Intensive Computing**
**Course**: CSE 587 - Data Intensive Computing
**Semester**: Fall 2025
**Author**: Narendra Varma Muppala
**UB Person Number**: 50602268

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Design](#architecture-design)
3. [Technology Stack](#technology-stack)
4. [Project Structure](#project-structure)
5. [Setup & Execution](#setup--execution)
6. [Expected Results](#expected-results)
7. [Technical Implementation](#technical-implementation)
8. [Troubleshooting](#troubleshooting)
9. [Screenshots & Evidence](#screenshots--evidence)
10. [Assignment Requirements](#assignment-requirements)

---

## 🎯 Project Overview

This project implements a **production-grade data lakehouse architecture** for analyzing Common Vulnerabilities and Exposures (CVE) data from 2024. Using **Databricks**, **Apache Spark**, and **Delta Lake**, the solution processes over **38,000 cybersecurity vulnerability records** through a three-tier medallion architecture (Bronze → Silver → Gold).

### Business Context
- **Domain**: Cybersecurity vulnerability intelligence
- **Data Source**: Official CVE Program (cvelistV5 repository)
- **Volume**: ~38,000 CVE records from 2024
- **Use Case**: Risk assessment, vendor analysis, temporal trend detection

### Key Objectives
✅ Ingest raw CVE data from GitHub
✅ Transform nested JSON into normalized analytics tables
✅ Implement CVSS scoring with version handling
✅ Demonstrate explode operations for one-to-many relationships
✅ Provide business intelligence queries for vulnerability analysis

---

## 🏗️ Architecture Design

The implementation follows the **Medallion Architecture** pattern with three layers:

### Bronze Layer (Raw Data Ingestion)
```
Purpose:     Ingest raw CVE data with minimal transformation
Method:      ZIP download → Extract → Store as Delta Lake
Storage:     /Volumes/workspace/default/assignment1/cve_data/bronze
Format:      Delta Lake (JSON strings for nested structures)
Records:     ~38,000+ CVE JSON documents from 2024
```

**Key Features**:
- ZIP download (faster than git clone)
- JSON string storage for Arrow compatibility
- Metadata enrichment (_ingestion_timestamp, _source_year)
- Idempotent processing with overwrite mode

### Silver Layer (Curated & Normalized)
```
Purpose:     Transform raw data into analytics-ready tables
Storage:     /Volumes/workspace/default/assignment1/cve_data/silver/
Tables:      core_cves, affected_products
Format:      Delta Lake with registered Unity Catalog tables
```

**Transformations**:
- ✅ Extract CVE metadata (ID, dates, publication state)
- ✅ Parse CVSS scores (v3.1 preferred over v3.0 via coalesce)
- ✅ Extract English descriptions from nested arrays
- ✅ Explode affected products (one-to-many transformation)
- ✅ Add quality indicators (has_cvss, has_description, risk_category)

**Output Tables**:
1. **core_cves**: Normalized CVE metadata (~33,000 records)
   - CVE ID, publication timestamps, CVSS scores, descriptions
   - Risk categories: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN

2. **affected_products**: Vendor/product relationships (~38,000 records)
   - Vendor name, product name, CVE ID (foreign key)
   - Versions and platforms stored as JSON strings

### Gold Layer (Analytics & Insights)
```
Purpose:     Business intelligence and exploratory analysis
Storage:     SQL queries (no materialized tables)
Queries:     analytical queries across 9 categories
```

**Analysis Sections**:
1. Data overview and summary statistics
2. Temporal analysis and publication trends
3. CVSS score analysis and risk assessment
4. Vendor and product vulnerability profiling
5. Integrated CVE-Product analysis
6. Publication patterns and batch detection
7. Time-based risk trending
8. Data validation and integrity checks
9. Executive summary dashboard

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Platform** | Databricks (Serverless) | Unified analytics platform |
| **Storage** | Delta Lake | ACID-compliant data lake |
| **Catalog** | Unity Catalog | Metadata & governance |
| **Compute** | Apache Spark (PySpark) | Distributed data processing |
| **Languages** | Python, SQL | Transformation & analytics |
| **Data Format** | JSON → Delta Lake | CVE 5.0 specification |
| **Source Control** | Git | Version management |

**Configuration**:
- Catalog: `workspace`
- Schema: `default`
- Volume: `assignment1`

---

## 📁 Project Structure

```
CVE_Lakehouse_Assignment1/
│
├── 00_setup_create_catalog.sql          # Unity Catalog infrastructure setup
├── 01_ingest_cvelist.py                 # Bronze layer - Data ingestion (238 lines)
├── 02_bronze_to_silver.py               # Silver layer - Transformation (422 lines)
├── 03_gold_analysis.sql                 # Gold layer - Analytics (queries)
├── 03_exploratory_analysis.sql          # Additional exploratory queries
│
├── README.md                            # This file - Project documentation
├── CLAUDE.md                            # Development notes and troubleshooting
│
├── bronze_layer_record_count.png        # Evidence - Bronze layer verification
├── bronze_layer_decribe.png             # Evidence - Bronze schema structure
├── silver_layer_statistics.png          # Evidence - Silver layer statistics
├── 03_gold_analysis_sql.csv             # Gold layer query results
└── 03_exploratory_analysis.sql.html     # HTML export of analysis queries
```

---

## 🚀 Setup & Execution

### Prerequisites

Before starting, ensure you have:
- ✅ Databricks workspace with Unity Catalog enabled
- ✅ Serverless compute cluster or shared cluster
- ✅ Permissions to create catalogs, schemas, volumes, and tables
- ✅ Internet access for GitHub repository download (~200 MB)

---

### Step 1: Infrastructure Setup (SQL)

**File**: `00_setup_create_catalog.sql`
**Runtime**: < 1 minute
**Location**: Databricks SQL Editor

```sql
-- Run this entire file in Databricks SQL Editor
-- Creates:
--   - workspace catalog (verify exists)
--   - default schema
--   - assignment1 volume for data storage
```

**Execution**:
1. Open Databricks SQL Editor
2. Copy entire contents of `00_setup_create_catalog.sql`
3. Run all statements
4. Verify output shows "Setup completed successfully!"

**Expected Output**:
```
active_catalog: workspace
active_schema: default
status: Setup completed successfully!
```

---

### Step 2: Bronze Layer - Data Ingestion (Python)

**File**: `01_ingest_cvelist.py`
**Runtime**: 10-15 minutes
**Location**: Databricks Python Notebook

**What It Does**:
- Downloads CVE repository as ZIP (~200 MB)
- Extracts and processes ~38,000 JSON files
- Converts nested JSON to strings for Arrow compatibility
- Stores in Delta Lake format

**Execution**:
1. Create new **Python Notebook** in Databricks
2. Copy entire contents of `01_ingest_cvelist.py`
3. Paste into notebook cell
4. Run the cell (⌘+Enter or Shift+Enter)
5. Monitor progress (shows updates every 1,000 files)

**Expected Output**:
```
[STEP 1/5] Downloading CVE repository archive...
Download complete: 200.45 MB

[STEP 2/5] Extracting archive...
Extraction complete

[STEP 3/5] Processing CVE JSON files for 2024...
   Processed 1,000 files...
   Processed 2,000 files...
   ...
Successfully loaded 38,XXX CVE records from 2024

[STEP 4/5] Creating Delta Lake table...
DataFrame created with 38,XXX rows
Delta table created successfully

[STEP 5/5] Verifying Bronze layer...
Records: 38,XXX
Columns: XX

BRONZE LAYER INGESTION COMPLETE
```

**Verification**:
```python
# Run this in a new cell to verify
bronze_df = spark.read.format("delta").load(
    "/Volumes/workspace/default/assignment1/cve_data/bronze"
)
print(f"Record count: {bronze_df.count():,}")
bronze_df.printSchema()
```

---

### Step 3: Silver Layer - Data Transformation (Python)

**File**: `02_bronze_to_silver.py`
**Runtime**: 3-5 minutes
**Location**: Databricks Python Notebook

**What It Does**:
- Reads Bronze layer Delta files
- Parses JSON strings to extract structured data
- Implements CVSS v3.1/v3.0 coalesce logic
- Extracts English descriptions from nested arrays
- **Explodes** affected products (one-to-many transformation)
- Creates two Delta tables in the volume

**Execution**:
1. Create new **Python Notebook** in Databricks
2. Copy entire contents of `02_bronze_to_silver.py`
3. Paste into notebook cell
4. Run the cell
5. Wait for completion (~3-5 minutes)

**Expected Output**:
```
=============================================================================
CVE SILVER LAYER - DATA TRANSFORMATION PIPELINE
=============================================================================

[STEP 1/5] Loading Bronze layer data...
Loaded 38,XXX records from Bronze

[STEP 2/5] Extracting core CVE metadata...
Core metadata extracted: 38,XXX records

[STEP 3/5] Parsing CVSS scores with version handling...
CVSS extraction complete

[STEP 4/5] Creating core_cves table...
Final core_cves table: 33,XXX records
Writing to: /Volumes/.../silver/core_cves

[STEP 5/5] Creating affected_products table...
Affected products extracted: 38,XXX records
Writing to: /Volumes/.../silver/affected_products

SILVER LAYER TRANSFORMATION COMPLETE
Status: SUCCESS
Tables Created: 2
  - core_cves: 33,XXX records
  - affected_products: 38,XXX records
```

---

### Step 4: Register Silver Tables in Unity Catalog (SQL)

⚠️ **CRITICAL STEP** - The Silver layer script creates Delta files but doesn't register them as tables.

**Location**: Databricks SQL Editor
**Runtime**: < 1 minute

```sql
-- Register core_cves table
CREATE TABLE IF NOT EXISTS workspace.default.core_cves
USING DELTA
LOCATION '/Volumes/workspace/default/assignment1/cve_data/silver/core_cves';

-- Register affected_products table
CREATE TABLE IF NOT EXISTS workspace.default.affected_products
USING DELTA
LOCATION '/Volumes/workspace/default/assignment1/cve_data/silver/affected_products';

-- Verify tables were created
SHOW TABLES IN workspace.default;

-- Test queries
SELECT COUNT(*) as total_cves FROM workspace.default.core_cves;
SELECT COUNT(*) as total_products FROM workspace.default.affected_products;

-- Sample data inspection
SELECT * FROM workspace.default.core_cves LIMIT 5;
SELECT * FROM workspace.default.affected_products LIMIT 5;
```

**Expected Output**:
```
Table name: core_cves
Table name: affected_products

total_cves: 33,XXX
total_products: 38,XXX
```

---

### Step 5: Gold Layer - Analytics & Insights (SQL)

**File**: `03_gold_analysis.sql`
**Runtime**: Varies per query (seconds to minutes)
**Location**: Databricks SQL Editor

**What It Contains**:
- analytical queries across 9 sections
- Executive dashboards and KPIs
- Temporal trend analysis
- Risk assessment queries
- Vendor vulnerability profiling

**Execution**:
1. Open Databricks SQL Editor
2. Copy queries from `03_gold_analysis.sql`
3. Run queries individually or in sections
4. Export results as needed (CSV, visualizations)

**Sample Queries to Run First**:

```sql
-- Query 1.1: Overall CVE dataset summary
SELECT
    'Dataset Overview' as metric_category,
    COUNT(*) as total_cve_records,
    COUNT(DISTINCT cve_id) as unique_cve_identifiers,
    MIN(published_timestamp) as earliest_publication,
    MAX(published_timestamp) as latest_publication
FROM workspace.default.core_cves;

-- Query 3.1: Risk category distribution
SELECT
    risk_category,
    COUNT(*) as cve_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage
FROM workspace.default.core_cves
GROUP BY risk_category
ORDER BY cve_count DESC;

-- Query 4.1: Top 25 vendors by vulnerability count
SELECT
    vendor_name,
    COUNT(DISTINCT cve_id) as total_vulnerabilities
FROM workspace.default.affected_products
WHERE vendor_name IS NOT NULL
GROUP BY vendor_name
ORDER BY total_vulnerabilities DESC
LIMIT 25;
```

**Additional Analysis**:
- Use `03_exploratory_analysis.sql` for supplementary queries
- Export results to CSV for reporting

---

## 📊 Expected Results

### Data Volume Metrics

| Metric | Expected Value |
|--------|----------------|
| Total CVE Records (Bronze) | 38,000+ |
| Unique CVEs (Silver) | 33,000+ |
| Affected Product Records | 38,000+ |
| Unique Vendors | 1,000+ |
| Unique Products | 5,000+ |

### Data Quality Metrics

| Metric | Expected Value |
|--------|----------------|
| Publication Success Rate | 99.97% |
| CVSS Coverage | ~80% |
| Description Coverage | ~85% |
| Temporal Coverage | Sep-Nov 2024 |
| Average CVSS Score | 6.5-7.0 |

### Risk Distribution (Approximate)

| Risk Category | Percentage |
|---------------|------------|
| CRITICAL | 5-10% |
| HIGH | 20-30% |
| MEDIUM | 40-50% |
| LOW | 10-20% |
| UNKNOWN | 10-15% |

---

## 🔧 Technical Implementation

### Key Technical Achievements

#### 1. Flexible Schema Handling
```python
# Bronze layer: Convert nested JSON to strings for Arrow compatibility
pandas_df["containers"] = pandas_df["containers"].apply(
    lambda x: json.dumps(x) if x is not None else None
)
```

#### 2. CVSS Version Coalescing
```python
# Silver layer: Prefer v3.1 over v3.0
.agg(
    coalesce(max(col("cvss31_score")), max(col("cvss30_score"))).alias("cvss_base_score"),
    when(max(col("cvss31_score")).isNotNull(), lit("3.1"))
    .when(max(col("cvss30_score")).isNotNull(), lit("3.0"))
    .otherwise(lit("N/A")).alias("cvss_version_used")
)
```

#### 3. Explode Operation (One-to-Many)
```python
# Transform affected products array into individual rows
affected_parsed = (
    affected_raw
    .withColumn("affected_item", explode_outer(from_json(
        col("affected_json_string"),
        ArrayType(MapType(StringType(), StringType()))
    )))
)
```

#### 4. Defensive Null Handling
```python
# Risk categorization with comprehensive null handling
.withColumn("risk_category",
    when(col("cvss_base_score") >= 9.0, lit("CRITICAL"))
    .when(col("cvss_base_score") >= 7.0, lit("HIGH"))
    .when(col("cvss_base_score") >= 4.0, lit("MEDIUM"))
    .when(col("cvss_base_score").isNotNull(), lit("LOW"))
    .otherwise(lit("UNKNOWN"))
)
```

### Performance Optimizations

- **Delta Lake**: ACID transactions, time travel, schema evolution
- **Partition Strategy**: Year-based partitioning (_source_year)
- **Compression**: Parquet compression for Delta files
- **Broadcast Joins**: Automatic for small dimension tables
- **Processing Rate**: ~2,500 records/second

---

## 🔍 Troubleshooting

### Common Issues & Solutions

#### Issue 1: Volume Not Found
```
Error: [TABLE_OR_VIEW_NOT_FOUND] The volume assignment1 cannot be found
```
**Solution**: Run `00_setup_create_catalog.sql` first to create the volume

#### Issue 2: Arrow Serialization Error
```
Error: ArrowTypeError: Could not convert with type dict
```
**Solution**: Already handled in code - nested structures converted to JSON strings

#### Issue 3: Tables Not Found in SQL Queries
```
Error: [TABLE_OR_VIEW_NOT_FOUND] workspace.default.core_cves cannot be found
```
**Solution**: Run the CREATE TABLE statements in Step 4 to register the Delta files

#### Issue 4: Parquet Empty Schema Error
```
Error: Cannot write a schema with an empty group
```
**Solution**: Already fixed - using MapType instead of empty StructType

#### Issue 5: CVSS Scores Missing
```
Query shows ~20% of CVEs without CVSS scores
```
**Solution**: This is expected - not all CVEs have CVSS scores assigned yet

#### Issue 6: Explode Operation Fails
```
Error: explode() cannot be called on null values
```
**Solution**: Using `explode_outer()` instead of `explode()` handles nulls

### Validation Queries

```sql
-- Check Bronze layer files
LIST '/Volumes/workspace/default/assignment1/cve_data/bronze';

-- Check Silver layer files
LIST '/Volumes/workspace/default/assignment1/cve_data/silver';

-- Verify table registration
SHOW TABLES IN workspace.default;

-- Check record counts
SELECT
    'Bronze' as layer,
    COUNT(*) as records
FROM delta.`/Volumes/workspace/default/assignment1/cve_data/bronze`
UNION ALL
SELECT
    'Silver - Core CVEs' as layer,
    COUNT(*) as records
FROM workspace.default.core_cves
UNION ALL
SELECT
    'Silver - Products' as layer,
    COUNT(*) as records
FROM workspace.default.affected_products;
```

---

## 📸 Screenshots & Evidence

The project includes several screenshots for documentation:

1. **bronze_layer_record_count.png**
   - Shows total record count from Bronze layer
   - Verifies successful ingestion

2. **bronze_layer_decribe.png**
   - Displays Bronze layer schema structure
   - Shows column names and data types

3. **silver_layer_statistics.png**
   - Silver layer table statistics
   - Record counts for both tables

4. **03_gold_analysis_sql.csv**
   - Exported results from Gold layer queries
   - Sample analytical insights

---

## ✅ Assignment Requirements Met

### Bronze Layer Requirements
- ✅ Raw JSON ingestion from GitHub
- ✅ Minimal transformation (store as-is)
- ✅ Delta Lake storage format
- ✅ Metadata enrichment
- ✅ Idempotent processing

### Silver Layer Requirements
- ✅ **Two normalized tables** (core_cves, affected_products)
- ✅ **CVSS handling** with version coalesce (v3.1 preferred over v3.0)
- ✅ **Timestamp normalization** using to_timestamp()
- ✅ **Explode operation** for one-to-many transformation
- ✅ **English descriptions** extracted from nested arrays
- ✅ **Referential integrity** via CVE ID foreign key
- ✅ **Quality indicators** (has_cvss, has_description, risk_category)

### Gold Layer Requirements
- ✅ Comprehensive analytical queries
- ✅ Executive dashboards and KPIs
- ✅ Temporal trend analysis
- ✅ Risk assessment queries
- ✅ Data validation and integrity checks

### Additional Requirements
- ✅ Unity Catalog integration
- ✅ Delta Lake ACID transactions
- ✅ Proper error handling
- ✅ Documentation (README, CLAUDE.md)
- ✅ Code comments and structure

---

## 📚 Additional Resources

### Data Source
- **Repository**: https://github.com/CVEProject/cvelistV5
- **Format**: CVE JSON 5.0 specification
- **License**: CC0 1.0 Universal (Public Domain)
- **Documentation**: https://www.cve.org/

### Databricks Documentation
- Unity Catalog: https://docs.databricks.com/unity-catalog/
- Delta Lake: https://docs.databricks.com/delta/
- PySpark API: https://spark.apache.org/docs/latest/api/python/

### CVE & CVSS References
- CVE Program: https://www.cve.org/
- CVSS Specification: https://www.first.org/cvss/
- NVD Database: https://nvd.nist.gov/

---

## 📝 License

This project is submitted as academic coursework for University at Buffalo.
CVE data is public domain under CC0 1.0 Universal license.

---

## 👤 Contact

**Narendra Varma**
University at Buffalo
Data Intensive Computing (CSE 587)
Fall 2024

---

**Last Updated**: November 2024
**Version**: 1.0
