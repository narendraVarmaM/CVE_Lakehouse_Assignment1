"""
CVE DATA LAKEHOUSE - BRONZE LAYER INGESTION
Data Engineering Assignment - University at Buffalo

Approach: Download and process CVE data from official GitHub repository
Method: ZIP download → Extract → Parse JSON → Store in Delta Lake
Target: 2024 CVE records with flexible schema handling

Author: [Your Name]
Date: November 2024
"""

import os
import json
import zipfile
import urllib.request
from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from pyspark.sql.types import *
import pandas as pd

# Initialize Spark
spark = SparkSession.builder.appName("CVE_DataLake_Bronze").getOrCreate()

# Workspace Configuration (using Unity Catalog volumes)
WORKSPACE_CATALOG = "workspace"
BRONZE_SCHEMA = "default"
DATA_VOLUME = "assignment1"

# Define storage locations
BRONZE_DELTA_LOCATION = f"/Volumes/{WORKSPACE_CATALOG}/{BRONZE_SCHEMA}/{DATA_VOLUME}/cve_data/bronze"
TEMP_EXTRACTION_PATH = "/tmp/cve_assignment"

print("="*80)
print("CVE BRONZE LAYER - DATA INGESTION PIPELINE")
print("="*80)
print(f"Catalog: {WORKSPACE_CATALOG}")
print(f"Schema: {BRONZE_SCHEMA}")
print(f"Volume: {DATA_VOLUME}")
print(f"Delta Path: {BRONZE_DELTA_LOCATION}")
print(f"Temp Path: {TEMP_EXTRACTION_PATH}")
print("="*80)

# Step 1: Download CVE Repository as ZIP
print("\n[STEP 1/5] Downloading CVE repository archive...")

zip_file_path = f"{TEMP_EXTRACTION_PATH}/cvelistV5.zip"
extraction_folder = f"{TEMP_EXTRACTION_PATH}/cvelistV5-main"
repository_url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"

# Create temp directory
os.makedirs(TEMP_EXTRACTION_PATH, exist_ok=True)
print(f"Created temporary directory: {TEMP_EXTRACTION_PATH}")

# Download repository archive
print(f"Downloading from: {repository_url}")
try:
    with urllib.request.urlopen(repository_url) as response:
        archive_data = response.read()
        with open(zip_file_path, "wb") as output_file:
            output_file.write(archive_data)

    download_size_mb = len(archive_data) / (1024 * 1024)
    print(f"Download complete: {download_size_mb:.2f} MB")

except Exception as download_error:
    print(f"ERROR during download: {download_error}")
    raise

# Step 2: Extract ZIP Archive
print("\n[STEP 2/5] Extracting archive...")
try:
    with zipfile.ZipFile(zip_file_path) as zip_ref:
        zip_ref.extractall(TEMP_EXTRACTION_PATH)
    print(f"Extraction complete: {extraction_folder}")
except Exception as extract_error:
    print(f"ERROR during extraction: {extract_error}")
    raise

# Step 3: Process CVE JSON Files
print("\n[STEP 3/5] Processing CVE JSON files for 2024...")

def load_cve_records(year, max_records=100000):
    """
    Load CVE records for a specific year
    Args:
        year: Target year (e.g., 2024)
        max_records: Maximum number of files to process
    Returns:
        List of parsed JSON objects
    """
    cve_directory = f"{extraction_folder}/cves/{year}"
    parsed_records = []

    print(f"Scanning: {cve_directory}")

    if not os.path.exists(cve_directory):
        print(f"WARNING: Directory not found: {cve_directory}")
        return []

    processed_count = 0
    failed_count = 0

    # Walk through directory structure
    for root_dir, subdirs, files in os.walk(cve_directory):
        for filename in files:
            # Process JSON files matching CVE pattern
            if filename.endswith('.json') and f'CVE-{year}-' in filename and processed_count < max_records:
                file_full_path = os.path.join(root_dir, filename)

                try:
                    with open(file_full_path, 'r', encoding='utf-8') as json_file:
                        file_content = json_file.read()
                        parsed_json = json.loads(file_content)
                        parsed_records.append(parsed_json)

                    processed_count += 1

                    # Progress indicator
                    if processed_count % 1000 == 0:
                        print(f"   Processed {processed_count:,} files...")

                except Exception as parse_error:
                    failed_count += 1
                    if failed_count <= 5:  # Show first 5 errors
                        print(f"   WARNING: Failed to parse {filename}: {parse_error}")

    print(f"Successfully loaded {len(parsed_records):,} CVE records from {year}")
    if failed_count > 0:
        print(f"Skipped {failed_count} files due to parsing errors")

    return parsed_records

# Load 2024 CVE data
cve_records_2024 = load_cve_records(2024, max_records=100000)
print(f"\nTotal records loaded: {len(cve_records_2024):,}")

# Step 4: Convert to DataFrame and Save
print("\n[STEP 4/5] Creating Delta Lake table...")

def create_bronze_delta_table(records_list, year, storage_path):
    """
    Convert JSON records to Delta Lake format
    Handles nested structures by converting to JSON strings
    """
    if not records_list:
        print("WARNING: No records to save")
        return None

    print(f"Converting {len(records_list):,} records to DataFrame...")

    # Create Pandas DataFrame first
    pandas_df = pd.DataFrame(records_list)

    # Handle nested structures - convert to JSON strings for Arrow compatibility
    if "containers" in pandas_df.columns:
        pandas_df["containers"] = pandas_df["containers"].apply(
            lambda x: json.dumps(x) if x is not None else None
        )

    # Convert other nested columns
    for column_name in pandas_df.columns:
        if pandas_df[column_name].dtype == 'object':
            first_value = pandas_df[column_name].dropna().iloc[0] if not pandas_df[column_name].dropna().empty else None
            if isinstance(first_value, (dict, list)):
                print(f"Converting nested column '{column_name}' to JSON string")
                pandas_df[column_name] = pandas_df[column_name].apply(
                    lambda x: json.dumps(x) if x is not None else None
                )

    # Create Spark DataFrame
    spark_df = spark.createDataFrame(pandas_df)

    # Add metadata columns
    enriched_df = (
        spark_df
        .withColumn("_ingestion_timestamp", current_timestamp())
        .withColumn("_ingestion_date", current_date())
        .withColumn("_source_year", lit(year))
        .withColumn("_record_id", monotonically_increasing_id())
    )

    record_count = enriched_df.count()
    print(f"DataFrame created with {record_count:,} rows")

    # Write to Delta Lake
    print(f"Writing to Delta Lake: {storage_path}")
    (
        enriched_df.write
        .format("delta")
        .mode("overwrite")
        .option("mergeSchema", "true")
        .option("overwriteSchema", "true")
        .option("delta.columnMapping.mode", "name")
        .save(storage_path)
    )

    print("Delta table created successfully")
    return enriched_df

# Create Delta table
bronze_dataframe = create_bronze_delta_table(cve_records_2024, 2024, BRONZE_DELTA_LOCATION)

# Step 5: Verification
print("\n[STEP 5/5] Verifying Bronze layer...")

# Load and verify
verification_df = spark.read.format("delta").load(BRONZE_DELTA_LOCATION)
final_count = verification_df.count()
column_count = len(verification_df.columns)

print(f"\nVerification Results:")
print(f"  Records: {final_count:,}")
print(f"  Columns: {column_count}")

# Show schema
print("\nSchema structure:")
verification_df.printSchema()

# Extract and display sample CVE information
print("\nSample CVE records:")
from pyspark.sql.functions import get_json_object

verification_df.select(
    get_json_object(col("cveMetadata"), "$.cveId").alias("cve_id"),
    get_json_object(col("cveMetadata"), "$.datePublished").alias("published_date"),
    col("_source_year").alias("year"),
    col("_ingestion_timestamp").alias("ingested_at")
).show(5, truncate=False)

print("\n" + "="*80)
print("BRONZE LAYER INGESTION COMPLETE")
print("="*80)
print(f"Status: SUCCESS")
print(f"Records Ingested: {final_count:,}")
print(f"Storage Location: {BRONZE_DELTA_LOCATION}")
print(f"Next Step: Run Silver layer transformation (02_bronze_to_silver.py)")
print("="*80)