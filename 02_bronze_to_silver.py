"""
CVE DATA LAKEHOUSE - SILVER LAYER TRANSFORMATION
Data Engineering Assignment - University at Buffalo

Objectives:
1. Extract normalized CVE metadata with CVSS scores (v3.1/v3.0 handling)
2. Parse English descriptions from nested arrays
3. Transform affected products using explode_outer operation
4. Establish referential integrity between tables

Note: Bronze layer stores cveMetadata and containers as JSON strings
      This script parses those JSON strings using get_json_object and from_json
"""

from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from pyspark.sql.types import *

# Initialize Spark
spark = SparkSession.builder.appName("CVE_DataLake_Silver").getOrCreate()

# Configuration matching Bronze layer
WORKSPACE_CATALOG = "workspace"
SILVER_SCHEMA = "default"
DATA_VOLUME = "assignment1"

# Define paths
BRONZE_DELTA_LOCATION = f"/Volumes/{WORKSPACE_CATALOG}/{SILVER_SCHEMA}/{DATA_VOLUME}/cve_data/bronze"
SILVER_CORE_LOCATION = f"/Volumes/{WORKSPACE_CATALOG}/{SILVER_SCHEMA}/{DATA_VOLUME}/cve_data/silver/core_cves"
SILVER_AFFECTED_LOCATION = f"/Volumes/{WORKSPACE_CATALOG}/{SILVER_SCHEMA}/{DATA_VOLUME}/cve_data/silver/affected_products"

print("="*80)
print("CVE SILVER LAYER - DATA TRANSFORMATION PIPELINE")
print("="*80)
print(f"Catalog: {WORKSPACE_CATALOG}")
print(f"Bronze Source: {BRONZE_DELTA_LOCATION}")
print(f"Silver Core Target: {SILVER_CORE_LOCATION}")
print(f"Silver Affected Target: {SILVER_AFFECTED_LOCATION}")
print("="*80)

# PART 1: LOAD BRONZE DATA
print("\n[PART 1/4] Loading Bronze layer data...")

bronze_df = spark.read.format("delta").load(BRONZE_DELTA_LOCATION)
bronze_record_count = bronze_df.count()

print(f"Bronze records loaded: {bronze_record_count:,}")
print("\nBronze schema preview:")
bronze_df.select("cveMetadata", "containers").printSchema()

# PART 2: CREATE CORE CVE TABLE WITH CVSS AND DESCRIPTIONS
print("\n[PART 2/4] Creating Core CVE table...")
print("Extracting: CVE ID, dates, CVSS scores (v3.1/v3.0), descriptions")

# Step 2A: Extract base metadata using get_json_object
print("\nStep 2A: Extracting base CVE metadata from JSON strings...")

core_metadata_df = (
    bronze_df
    .select(
        # CVE identifiers - parse from JSON string
        get_json_object(col("cveMetadata"), "$.cveId").alias("cve_id"),
        get_json_object(col("cveMetadata"), "$.state").alias("publication_state"),
        get_json_object(col("cveMetadata"), "$.assignerOrgId").alias("assigning_org_id"),
        get_json_object(col("cveMetadata"), "$.assignerShortName").alias("assigning_org_name"),

        # Temporal fields - parse and convert to timestamps
        to_timestamp(get_json_object(col("cveMetadata"), "$.datePublished")).alias("published_timestamp"),
        to_timestamp(get_json_object(col("cveMetadata"), "$.dateReserved")).alias("reserved_timestamp"),
        to_timestamp(get_json_object(col("cveMetadata"), "$.dateUpdated")).alias("updated_timestamp"),

        # Keep containers JSON string for further processing
        col("containers").alias("container_data"),

        # Bronze metadata
        col("_ingestion_timestamp").alias("bronze_ingestion_ts"),
        col("_source_year").alias("data_year")
    )
)

metadata_count = core_metadata_df.count()
print(f"Base metadata extracted: {metadata_count:,} records")

# Step 2B: Extract English descriptions from nested JSON arrays
print("\nStep 2B: Extracting English descriptions from JSON arrays...")

# Schema for descriptions array
desc_schema = ArrayType(StructType([
    StructField("lang", StringType(), True),
    StructField("value", StringType(), True),
    StructField("supportingMedia", ArrayType(StringType()), True)
]))

descriptions_df = (
    core_metadata_df
    .withColumn(
        "desc_array",
        from_json(get_json_object(col("container_data"), "$.cna.descriptions"), desc_schema)
    )
    .withColumn("desc_item", explode_outer(col("desc_array")))
    .withColumn(
        "english_desc",
        when(col("desc_item.lang") == "en", col("desc_item.value")).otherwise(None)
    )
    # Aggregate back to CVE level - take first English description
    .groupBy(
        "cve_id", "publication_state", "assigning_org_id", "assigning_org_name",
        "published_timestamp", "reserved_timestamp", "updated_timestamp",
        "container_data", "bronze_ingestion_ts", "data_year"
    )
    .agg(
        first(col("english_desc"), ignorenulls=True).alias("cve_description")
    )
)

desc_available = descriptions_df.filter(col("cve_description").isNotNull()).count()
print(f"Descriptions found: {desc_available:,} CVEs ({desc_available/metadata_count*100:.1f}%)")

# Step 2C: Extract CVSS scores with version handling (v3.1 and v3.0)
print("\nStep 2C: Extracting CVSS scores with coalesce logic (prefer v3.1 → v3.0)...")

# Schema for metrics array
metrics_schema = ArrayType(StructType([
    StructField("cvssV3_1", StructType([
        StructField("baseScore", DoubleType(), True),
        StructField("baseSeverity", StringType(), True),
        StructField("vectorString", StringType(), True)
    ]), True),
    StructField("cvssV3_0", StructType([
        StructField("baseScore", DoubleType(), True),
        StructField("baseSeverity", StringType(), True),
        StructField("vectorString", StringType(), True)
    ]), True),
    StructField("other", StringType(), True)
]))

cvss_extracted_df = (
    descriptions_df
    .withColumn(
        "metrics_array",
        from_json(get_json_object(col("container_data"), "$.cna.metrics"), metrics_schema)
    )
    .withColumn("metric_entry", explode_outer(col("metrics_array")))

    # Extract CVSS v3.1 fields
    .withColumn("cvss31_score", col("metric_entry.cvssV3_1.baseScore"))
    .withColumn("cvss31_severity", col("metric_entry.cvssV3_1.baseSeverity"))
    .withColumn("cvss31_vector", col("metric_entry.cvssV3_1.vectorString"))

    # Extract CVSS v3.0 fields
    .withColumn("cvss30_score", col("metric_entry.cvssV3_0.baseScore"))
    .withColumn("cvss30_severity", col("metric_entry.cvssV3_0.baseSeverity"))
    .withColumn("cvss30_vector", col("metric_entry.cvssV3_0.vectorString"))

    # Group back and apply coalesce logic
    .groupBy(
        "cve_id", "publication_state", "assigning_org_id", "assigning_org_name",
        "published_timestamp", "reserved_timestamp", "updated_timestamp",
        "cve_description", "bronze_ingestion_ts", "data_year"
    )
    .agg(
        # Coalesce: use v3.1 if available, otherwise v3.0
        coalesce(max(col("cvss31_score")), max(col("cvss30_score"))).alias("cvss_base_score"),
        coalesce(max(col("cvss31_severity")), max(col("cvss30_severity"))).alias("cvss_severity_rating"),
        coalesce(max(col("cvss31_vector")), max(col("cvss30_vector"))).alias("cvss_vector"),

        # Track which version was used
        when(max(col("cvss31_score")).isNotNull(), lit("3.1"))
        .when(max(col("cvss30_score")).isNotNull(), lit("3.0"))
        .otherwise(lit("N/A")).alias("cvss_version_used")
    )
)

cvss_available = cvss_extracted_df.filter(col("cvss_base_score").isNotNull()).count()
print(f"CVSS scores found: {cvss_available:,} CVEs ({cvss_available/metadata_count*100:.1f}%)")

# Show CVSS version distribution
print("\nCVSS version distribution:")
cvss_extracted_df.groupBy("cvss_version_used").count().orderBy(col("count").desc()).show()

# Step 2D: Finalize Core CVE table
print("\nStep 2D: Finalizing Core CVE table with quality indicators...")

core_cve_final = (
    cvss_extracted_df
    .withColumn("silver_transform_timestamp", current_timestamp())

    # Quality flags
    .withColumn("has_description", col("cve_description").isNotNull())
    .withColumn("has_cvss", col("cvss_base_score").isNotNull())

    # Severity categorization
    .withColumn(
        "risk_category",
        when(col("cvss_base_score") >= 9.0, "CRITICAL")
        .when(col("cvss_base_score") >= 7.0, "HIGH")
        .when(col("cvss_base_score") >= 4.0, "MEDIUM")
        .when(col("cvss_base_score") > 0, "LOW")
        .otherwise("UNSCORED")
    )

    # Handle nulls
    .fillna({
        "cve_description": "[No description provided]",
        "cvss_severity_rating": "UNKNOWN",
        "cvss_version_used": "N/A"
    })
)

core_final_count = core_cve_final.count()
print(f"Core CVE table finalized: {core_final_count:,} records")

# Quality metrics
print("\nData quality summary:")
core_cve_final.select(
    count("*").alias("total"),
    sum(when(col("has_description"), 1).otherwise(0)).alias("with_description"),
    sum(when(col("has_cvss"), 1).otherwise(0)).alias("with_cvss"),
    round(avg("cvss_base_score"), 2).alias("avg_cvss")
).show()

# Sample display
print("\nSample Core CVE records:")
core_cve_final.select(
    "cve_id",
    "published_timestamp",
    "cvss_base_score",
    "cvss_severity_rating",
    "risk_category",
    "cvss_version_used",
    "cve_description"
).show(5, truncate=60)

# Write Core CVE table
print(f"\nWriting Core CVE table to: {SILVER_CORE_LOCATION}")
(
    core_cve_final.write
    .format("delta")
    .mode("overwrite")
    .option("mergeSchema", "true")
    .option("overwriteSchema", "true")
    .save(SILVER_CORE_LOCATION)
)
print("Core CVE table saved successfully")

# PART 3: CREATE AFFECTED PRODUCTS TABLE WITH EXPLODE
print("\n[PART 3/4] Creating Affected Products table using explode_outer...")

# Reload bronze for affected products processing
bronze_for_affected = spark.read.format("delta").load(BRONZE_DELTA_LOCATION)

# Extract affected products array from JSON string
# We'll parse the full affected array and extract what we can
print("\nParsing affected products from JSON...")

affected_raw = (
    bronze_for_affected
    .select(
        get_json_object(col("cveMetadata"), "$.cveId").alias("cve_id"),
        # Get the affected array as a string first
        get_json_object(col("containers"), "$.cna.affected").alias("affected_json_string")
    )
    .filter(col("affected_json_string").isNotNull())
)

# Parse the JSON string to extract vendor, product, and keep versions/platforms as JSON strings
affected_parsed = (
    affected_raw
    .withColumn("affected_item", explode_outer(from_json(
        col("affected_json_string"),
        ArrayType(MapType(StringType(), StringType()))  # Flexible map type
    )))
)

# EXPLODE_OUTER: Transform array into individual rows
print("\nApplying explode_outer transformation...")

# Extract product details, keeping versions and platforms as strings
affected_products_final = (
    affected_parsed
    .select(
        col("cve_id"),
        col("affected_item")["vendor"].alias("vendor_name"),
        col("affected_item")["product"].alias("product_name"),
        col("affected_item")["defaultStatus"].alias("vulnerability_status"),
        # Keep versions and platforms as JSON strings to avoid Parquet schema issues
        col("affected_item")["versions"].alias("affected_versions_json"),
        col("affected_item")["platforms"].alias("affected_platforms_json"),
        col("affected_item")["collectionURL"].alias("vendor_url"),
        col("affected_item")["packageName"].alias("package_identifier")
    )
    # Filter out entries with no vendor
    .filter(col("vendor_name").isNotNull())

    # Add processing metadata
    .withColumn("silver_transform_timestamp", current_timestamp())

    # Handle nulls
    .fillna({
        "product_name": "[Product name unavailable]",
        "vulnerability_status": "unknown"
    })
)

affected_final_count = affected_products_final.count()
original_cve_count = affected_raw.count()
expansion_ratio = affected_final_count / original_cve_count if original_cve_count > 0 else 0

print(f"\nEXPLODE Results:")
print(f"  Input CVEs: {original_cve_count:,}")
print(f"  Output rows: {affected_final_count:,}")
print(f"  Expansion ratio: {expansion_ratio:.2f}x")
print(f"  (Average {expansion_ratio:.1f} products per CVE)")

# Demonstrate explode with example
print("\nEXPLODE DEMONSTRATION:")
multi_product_example = (
    affected_products_final
    .groupBy("cve_id")
    .count()
    .filter(col("count") > 2)
    .orderBy(col("count").desc())
    .first()
)

if multi_product_example:
    example_cve = multi_product_example["cve_id"]
    example_count = multi_product_example["count"]
    print(f"\nExample: {example_cve} has {example_count} affected products:")
    affected_products_final.filter(col("cve_id") == example_cve).select(
        "cve_id", "vendor_name", "product_name", "vulnerability_status"
    ).show(truncate=False)
else:
    print("No multi-product CVEs found in sample")

# Write Affected Products table
print(f"\nWriting Affected Products table to: {SILVER_AFFECTED_LOCATION}")
(
    affected_products_final.write
    .format("delta")
    .mode("overwrite")
    .option("mergeSchema", "true")
    .option("overwriteSchema", "true")
    .save(SILVER_AFFECTED_LOCATION)
)
print("Affected Products table saved successfully")

# PART 4: VERIFICATION AND VALIDATION
print("\n[PART 4/4] Verification and validation...")

# Load saved tables
core_verification = spark.read.format("delta").load(SILVER_CORE_LOCATION)
affected_verification = spark.read.format("delta").load(SILVER_AFFECTED_LOCATION)

# Statistics
core_count = core_verification.count()
affected_count = affected_verification.count()
unique_vendors = affected_verification.select("vendor_name").distinct().count()
unique_products = affected_verification.select("product_name").distinct().count()

print("\n" + "="*80)
print("SILVER LAYER STATISTICS")
print("="*80)
print(f"\nCore CVE Table:")
print(f"  Total records: {core_count:,}")
print(f"  With CVSS: {core_verification.filter(col('has_cvss')).count():,}")
print(f"  With descriptions: {core_verification.filter(col('has_description')).count():,}")

print(f"\nAffected Products Table:")
print(f"  Total records: {affected_count:,}")
print(f"  Unique vendors: {unique_vendors:,}")
print(f"  Unique products: {unique_products:,}")

# Risk distribution
print(f"\nRisk category distribution:")
core_verification.groupBy("risk_category").count().orderBy(col("count").desc()).show()

# Referential integrity check
print("\nReferential integrity check:")
orphaned_products = (
    affected_verification
    .select("cve_id")
    .distinct()
    .join(core_verification.select("cve_id"), "cve_id", "left_anti")
)

orphan_count = orphaned_products.count()
if orphan_count == 0:
    print("PASSED: All affected products link to valid CVE IDs")
else:
    print(f"WARNING: Found {orphan_count} orphaned product records")

# Top vendors analysis
print("\nTop 15 vendors by vulnerability count:")
affected_verification.groupBy("vendor_name").agg(
    countDistinct("cve_id").alias("unique_vulnerabilities"),
    count("*").alias("total_entries")
).orderBy(col("unique_vulnerabilities").desc()).show(15, truncate=False)

# Final summary
print("\n" + "="*80)
print("SILVER LAYER TRANSFORMATION COMPLETE")
print("="*80)
print(f"\nTables created:")
print(f"  1. Core CVEs: {SILVER_CORE_LOCATION}")
print(f"     Records: {core_count:,}")
print(f"\n  2. Affected Products: {SILVER_AFFECTED_LOCATION}")
print(f"     Records: {affected_count:,}")

print(f"\nKey achievements:")
print(f"  - Parsed JSON strings from Bronze layer using get_json_object and from_json")
print(f"  - Extracted CVE metadata with normalized timestamps")
print(f"  - Implemented CVSS v3.1/v3.0 coalesce logic")
print(f"  - Parsed English descriptions from nested JSON arrays")
print(f"  - Applied explode_outer for product relationships")
print(f"  - Kept versions and platforms as JSON strings (Parquet-compatible)")
print(f"  - Established referential integrity via CVE ID")
print(f"  - Added data quality indicators and risk categories")

print(f"\nNext step: Run Gold layer analytics (03_gold_analysis.sql)")
print("="*80)
