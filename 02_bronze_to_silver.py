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
spark = SparkSession.builder.appName("CVE_Silver").getOrCreate()
WORKSPACE_CATALOG = "cse587"
# Define paths
SILVER_DB = "silver"
SILVER_CORE_TABLE = f"{WORKSPACE_CATALOG}.{SILVER_DB}.core_cves"
SILVER_AFFECTED_TABLE = f"{WORKSPACE_CATALOG}.{SILVER_DB}.affected_products"
BRONZE_DB = "bronze"
BRONZE_TABLE = f"{WORKSPACE_CATALOG}.{BRONZE_DB}.records"


# Drop old table
spark.sql("DROP TABLE IF EXISTS cse587.silver.core_cves")
print("Dropped old table")

# Drop old table
spark.sql("DROP TABLE IF EXISTS cse587.silver.affected_products")
print("Dropped old table")

print("="*80)
print("CVE SILVER LAYER - DATA TRANSFORMATION PIPELINE")
print("="*80)
print(f"Catalog: {WORKSPACE_CATALOG}")
print(f"Silver Core Target TABLE: {SILVER_CORE_TABLE}")
print(f"Silver Affected Target TABLE: {SILVER_AFFECTED_TABLE}")
print("="*80)

# ================================================================
# PART 1: LOAD BRONZE
# ================================================================
print("\n[PART 1/4] Loading Bronze layer data...")

bronze_df = spark.read.table(BRONZE_TABLE)
bronze_record_count = bronze_df.count()

print(f"Bronze records loaded: {bronze_record_count:,}")
print("\nBronze schema preview:")
bronze_df.select("cveMetadata", "containers").printSchema()

# ================================================================
# PART 2: CORE CVE TABLE
# ================================================================
print("\n[PART 2/4] Creating Core CVE table...")
print("Extracting: CVE ID, dates, CVSS scores (v3.1/v3.0), descriptions")

# ----------------------------------------------------------------
# STEP 2A — EXTRACT BASE METADATA
# ----------------------------------------------------------------
print("\nStep 2A: Extracting base CVE metadata from JSON strings...")

core_metadata_df = (
    bronze_df
    .select(
        get_json_object(col("cveMetadata"), "$.cveId").alias("cve_id"),
        get_json_object(col("cveMetadata"), "$.state").alias("publication_state"),
        get_json_object(col("cveMetadata"), "$.assignerOrgId").alias("assigning_org_id"),
        get_json_object(col("cveMetadata"), "$.assignerShortName").alias("assigning_org_name"),

        to_timestamp(get_json_object(col("cveMetadata"), "$.datePublished")).alias("published_timestamp"),
        to_timestamp(get_json_object(col("cveMetadata"), "$.dateReserved")).alias("reserved_timestamp"),
        to_timestamp(get_json_object(col("cveMetadata"), "$.dateUpdated")).alias("updated_timestamp"),

        col("containers").alias("container_data"),
        col("_ingestion_timestamp").alias("bronze_ingestion_ts"),
        col("_source_year").alias("data_year")
    )
)

metadata_count = core_metadata_df.count()
print(f"Base metadata extracted: {metadata_count:,} records")

# ----------------------------------------------------------------
# STEP 2B — EXTRACT DESCRIPTIONS
# ----------------------------------------------------------------
print("\nStep 2B: Extracting English descriptions from JSON arrays...")

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
        when(col("desc_item.lang") == "en", col("desc_item.value"))
    )
    .groupBy(
        "cve_id", "publication_state", "assigning_org_id", "assigning_org_name",
        "published_timestamp", "reserved_timestamp", "updated_timestamp",
        "container_data", "bronze_ingestion_ts", "data_year"
    )
    .agg(first(col("english_desc"), ignorenulls=True).alias("cve_description"))
)

desc_available = descriptions_df.filter(col("cve_description").isNotNull()).count()
print(f"Descriptions found: {desc_available:,} CVEs ({desc_available/metadata_count*100:.1f}%)")

# ----------------------------------------------------------------
# STEP 2C — EXTRACT CVSS SCORES
# ----------------------------------------------------------------
print("\nStep 2C: Extracting CVSS scores with version handling (3.1 → 3.0)...")

metrics_schema = ArrayType(StructType([
    StructField("cvssV3_1", StructType([
        StructField("baseScore", DoubleType(), True),
        StructField("baseSeverity", StringType(), True),
        StructField("vectorString", StringType(), True)
    ])),
    StructField("cvssV3_0", StructType([
        StructField("baseScore", DoubleType(), True),
        StructField("baseSeverity", StringType(), True),
        StructField("vectorString", StringType(), True)
    ])),
    StructField("other", StringType(), True)
]))

cvss_extracted_df = (
    descriptions_df
    .withColumn(
        "metrics_array",
        from_json(get_json_object(col("container_data"), "$.cna.metrics"), metrics_schema)
    )
    .withColumn("metric_entry", explode_outer(col("metrics_array")))
    .withColumn("cvss31_score", col("metric_entry.cvssV3_1.baseScore"))
    .withColumn("cvss31_severity", col("metric_entry.cvssV3_1.baseSeverity"))
    .withColumn("cvss31_vector", col("metric_entry.cvssV3_1.vectorString"))
    .withColumn("cvss30_score", col("metric_entry.cvssV3_0.baseScore"))
    .withColumn("cvss30_severity", col("metric_entry.cvssV3_0.baseSeverity"))
    .withColumn("cvss30_vector", col("metric_entry.cvssV3_0.vectorString"))
    .groupBy(
        "cve_id", "publication_state", "assigning_org_id", "assigning_org_name",
        "published_timestamp", "reserved_timestamp", "updated_timestamp",
        "cve_description", "bronze_ingestion_ts", "data_year"
    )
    .agg(
        coalesce(max(col("cvss31_score")), max(col("cvss30_score"))).alias("cvss_base_score"),
        coalesce(max(col("cvss31_severity")), max(col("cvss30_severity"))).alias("cvss_severity_rating"),
        coalesce(max(col("cvss31_vector")), max(col("cvss30_vector"))).alias("cvss_vector"),

        when(max(col("cvss31_score")).isNotNull(), "3.1")
        .when(max(col("cvss30_score")).isNotNull(), "3.0")
        .otherwise("N/A").alias("cvss_version_used")
    )
)

cvss_available = cvss_extracted_df.filter(col("cvss_base_score").isNotNull()).count()
print(f"CVSS scores found: {cvss_available:,} CVEs ({cvss_available/metadata_count*100:.1f}%)")

print("\nCVSS version distribution:")
cvss_extracted_df.groupBy("cvss_version_used").count().show()

# ----------------------------------------------------------------
# STEP 2D — FINAL CORE TABLE
# ----------------------------------------------------------------
print("\nStep 2D: Finalizing Core CVE table with quality indicators...")

core_cve_final = (
    cvss_extracted_df
    .withColumn("silver_transform_timestamp", current_timestamp())
    .withColumn("has_description", col("cve_description").isNotNull())
    .withColumn("has_cvss", col("cvss_base_score").isNotNull())
    .withColumn(
        "risk_category",
        when(col("cvss_base_score") >= 9, "CRITICAL")
        .when(col("cvss_base_score") >= 7, "HIGH")
        .when(col("cvss_base_score") >= 4, "MEDIUM")
        .when(col("cvss_base_score") > 0, "LOW")
        .otherwise("UNSCORED")
    )
    .fillna({
        "cve_description": "[No description provided]",
        "cvss_severity_rating": "UNKNOWN",
        "cvss_version_used": "N/A"
    })
)

core_final_count = core_cve_final.count()
print(f"Core CVE table finalized: {core_final_count:,} records")

# ----------------------------------------------------------------
# WRITE CORE TABLE (THIS IS WHERE THE CHANGE IS)
# ----------------------------------------------------------------
print(f"\nWriting Core CVE table to: {SILVER_CORE_TABLE}")

(
    core_cve_final.write
    .format("delta")
    .mode("overwrite")
    .option("mergeSchema", "true")
    .saveAsTable(SILVER_CORE_TABLE)
)

print("Core CVE table saved successfully.")

# ================================================================
# PART 3: AFFECTED PRODUCTS TABLE
# ================================================================
print("\n[PART 3/4] Creating Affected Products table using explode_outer...")

bronze_for_affected = spark.read.table(BRONZE_TABLE)

print("\nParsing affected products from JSON...")

affected_raw = (
    bronze_for_affected
    .select(
        get_json_object(col("cveMetadata"), "$.cveId").alias("cve_id"),
        get_json_object(col("containers"), "$.cna.affected").alias("affected_json_string")
    )
    .filter(col("affected_json_string").isNotNull())
)

affected_parsed = (
    affected_raw
    .withColumn(
        "affected_item",
        explode_outer(
            from_json(
                col("affected_json_string"),
                ArrayType(MapType(StringType(), StringType()))
            )
        )
    )
)

print("\nApplying explode_outer transformation...")

affected_products_final = (
    affected_parsed
    .select(
        col("cve_id"),
        col("affected_item")["vendor"].alias("vendor_name"),
        col("affected_item")["product"].alias("product_name"),
        col("affected_item")["defaultStatus"].alias("vulnerability_status"),
        col("affected_item")["versions"].alias("affected_versions_json"),
        col("affected_item")["platforms"].alias("affected_platforms_json"),
        col("affected_item")["collectionURL"].alias("vendor_url"),
        col("affected_item")["packageName"].alias("package_identifier")
    )
    .filter(col("vendor_name").isNotNull())
    .withColumn("silver_transform_timestamp", current_timestamp())
    .fillna({
        "product_name": "[Product name unavailable]",
        "vulnerability_status": "unknown"
    })
)

affected_final_count = affected_products_final.count()
original_cve_count = affected_raw.count()
ratio = affected_final_count / original_cve_count if original_cve_count > 0 else 0

print("\nEXPLODE Results:")
print(f"  Input CVEs: {original_cve_count:,}")
print(f"  Output rows: {affected_final_count:,}")
print(f"  Expansion ratio: {ratio:.2f}x")

# ----------------------------------------------------------------
# WRITE AFFECTED PRODUCTS TABLE (THIS IS WHERE THE CHANGE IS)
# ----------------------------------------------------------------
print(f"\nWriting Affected Products table to: {SILVER_AFFECTED_TABLE}")

(
    affected_products_final.write
    .format("delta")
    .mode("overwrite")
    .option("mergeSchema", "true")
    .saveAsTable(SILVER_AFFECTED_TABLE)
)

print("Affected Products table saved successfully.")

# ================================================================
# PART 4: VERIFICATION
# ================================================================
print("\n[PART 4/4] Verification and validation...")

core_verification = spark.table(SILVER_CORE_TABLE)
affected_verification = spark.table(SILVER_AFFECTED_TABLE)

core_count = core_verification.count()
affected_count = affected_verification.count()
unique_vendors = affected_verification.select("vendor_name").distinct().count()
unique_products = affected_verification.select("product_name").distinct().count()

print("\n" + "="*80)
print("SILVER LAYER STATISTICS")
print("="*80)
print(f"\nCore CVE Table: {core_count:,} rows")
print(f"With CVSS: {core_verification.filter(col('has_cvss')).count():,}")
print(f"With Description: {core_verification.filter(col('has_description')).count():,}")

print(f"\nAffected Products Table: {affected_count:,} rows")
print(f"Unique vendors: {unique_vendors:,}")
print(f"Unique products: {unique_products:,}")

print("\nRisk category distribution:")
core_verification.groupBy("risk_category").count().show()

print("\nReferential integrity check:")
orphaned = (
    affected_verification
    .select("cve_id").distinct()
    .join(core_verification.select("cve_id"), "cve_id", "left_anti")
)

orphan_count = orphaned.count()
if orphan_count == 0:
    print("PASSED: All affected products link to valid CVE IDs")
else:
    print(f"WARNING: {orphan_count} orphan records detected")

print("\nTop 15 vendors by vulnerability count:")
affected_verification.groupBy("vendor_name").agg(
    countDistinct("cve_id").alias("unique_vulnerabilities"),
    count("*").alias("total_entries")
).orderBy(col("unique_vulnerabilities").desc()).show(15, truncate=False)

print("\n" + "="*80)
print("SILVER LAYER TRANSFORMATION COMPLETE")
print("="*80)
print("\nTables created:")
print(f"  1. Core CVEs: {SILVER_CORE_TABLE}")
print(f"  2. Affected Products: {SILVER_AFFECTED_TABLE}")
print("="*80)
