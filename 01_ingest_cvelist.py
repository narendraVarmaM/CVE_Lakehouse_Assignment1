import os
import json
import zipfile
import urllib.request
from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from pyspark.sql.types import *
import pandas as pd

# Initialize Spark
spark = SparkSession.builder.appName("CVE_Bronze").getOrCreate()

# Verify catalog
try:
    spark.sql("SHOW CATALOGS").collect()
except:
    raise Exception("Run 00_setup_create_catalog.sql first!")

# Drop old table
spark.sql("DROP TABLE IF EXISTS cse587.bronze.records")
print("Dropped old table")

# This is the fully-qualified table you'll create
BRONZE_TABLE = "cse587.bronze.records"
# (Optional) you can also set a physical location path if you prefer; not required for saveAsTable:
# BRONZE_DELTA_LOCATION = "/Volumes/.../bronze/records"  

TEMP_EXTRACTION_PATH = "/tmp"

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

# ---------- Step 1: Download ZIP ----------
os.makedirs(TEMP_EXTRACTION_PATH, exist_ok=True)
print(f"\n[STEP 1/5] Downloading CVE repo to {zip_file_path}")
try:
    with urllib.request.urlopen(repository_url) as response:
        archive_data = response.read()
        with open(zip_file_path, "wb") as out_f:
            out_f.write(archive_data)
    print("Download complete: {:.2f} MB".format(len(archive_data) / (1024*1024)))
except Exception as download_error:
    print("ERROR during download:", download_error)
    raise

# ---------- Step 2: Extract ----------
print("\n[STEP 2/5] Extracting archive...")
try:
    with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
        zip_ref.extractall(TEMP_EXTRACTION_PATH)
    print(f"Extraction complete -> {extraction_folder}")
except Exception as extract_error:
    print("ERROR during extraction:", extract_error)
    raise

# ---------- Step 3: Load CVE JSON files (2024) ----------
print("\n[STEP 3/5] Reading CVE JSON files for 2024...")

def load_cve_records(year, max_records=100000):
    cve_directory = f"{extraction_folder}/cves/{year}"
    parsed_records = []
    if not os.path.exists(cve_directory):
        print(f"WARNING: Directory not found: {cve_directory}")
        return []
    processed_count = 0
    failed_count = 0

    for root_dir, subdirs, files in os.walk(cve_directory):
        for filename in files:
            if filename.endswith('.json') and f'CVE-{year}-' in filename and processed_count < max_records:
                file_full_path = os.path.join(root_dir, filename)
                try:
                    with open(file_full_path, 'r', encoding='utf-8') as json_file:
                        parsed_json = json.load(json_file)
                        parsed_records.append(parsed_json)
                    processed_count += 1
                    if processed_count % 1000 == 0:
                        print(f"   Processed {processed_count:,} files...")
                except Exception as parse_error:
                    failed_count += 1
                    if failed_count <= 5:
                        print(f"   WARNING: Failed to parse {filename}: {parse_error}")
    print(f"Loaded {len(parsed_records):,} records (skipped {failed_count} errors)")
    return parsed_records

cve_records_2024 = load_cve_records(2024, max_records=100000)
print("Total records loaded:", len(cve_records_2024))

# ---------- Step 4: Convert & Write to Delta table using saveAsTable ----------
print("\n[STEP 4/5] Converting records and writing to Delta managed table:", BRONZE_TABLE)

def create_bronze_table(records_list, year, target_table):
    if not records_list:
        print("WARNING: No records to save")
        return None

    # Convert JSON list to pandas DataFrame (watch memory; for very large sets use Spark directly)
    pandas_df = pd.DataFrame(records_list)

    # Convert nested dict/list columns to JSON strings for compatibility
    def maybe_convert_to_json(x):
        if x is None:
            return None
        if isinstance(x, (dict, list)):
            return json.dumps(x)
        return x

    # Use safe operations: for all object dtype columns, convert nested structures
    for col_name in pandas_df.columns:
        if pandas_df[col_name].dtype == 'object':
            # If first non-null element is dict/list, convert whole column to strings
            non_null_series = pandas_df[col_name].dropna()
            if not non_null_series.empty:
                first_val = non_null_series.iloc[0]
                if isinstance(first_val, (dict, list)):
                    print(f"  Converting nested column '{col_name}' -> JSON string")
                    pandas_df[col_name] = pandas_df[col_name].apply(maybe_convert_to_json)

    # Create Spark DataFrame from pandas
    spark_df = spark.createDataFrame(pandas_df)

    # Add metadata columns
    enriched_df = (spark_df
                   .withColumn("_ingestion_timestamp", current_timestamp())
                   .withColumn("_ingestion_date", current_date())
                   .withColumn("_source_year", lit(year))
                   .withColumn("_record_id", monotonically_increasing_id())
                   )

    row_count = enriched_df.count()
    print(f"  Created Spark DataFrame with {row_count:,} rows and {len(enriched_df.columns)} columns")

    # Write to a managed Delta table in the metastore
    try:
        (enriched_df.write
         .format("delta")
         .mode("overwrite")             # overwrite existing content of the table
         .option("overwriteSchema", "true")
         .saveAsTable(target_table))
        print("  Successfully wrote Delta table:", target_table)
    except Exception as write_err:
        print("  ERROR writing Delta table:", write_err)
        raise

    return enriched_df

bronze_df = create_bronze_table(cve_records_2024, 2024, BRONZE_TABLE)

# ---------- Step 5: Verification ----------
print("\n[STEP 5/5] Verifying Bronze table and sample rows...")

try:
    verification_df = spark.table(BRONZE_TABLE)
    final_count = verification_df.count()
    column_count = len(verification_df.columns)
    print(f"Verification: Records = {final_count:,}, Columns = {column_count}")
    verification_df.printSchema()

    # Show sample row(s) - adjust field names to match what's actually in the JSON
    # Try to extract a common nested field (cveMetadata) if present; otherwise show full row
    sample_cols = verification_df.columns[:10]  # first few columns for quick preview
    verification_df.select(*sample_cols).show(5, truncate=200)

    # Example: if you have a nested cveMetadata JSON string, extract a key
    from pyspark.sql.functions import get_json_object
    if "cveMetadata" in verification_df.columns:
        verification_df.select(
            get_json_object(col("cveMetadata"), "$.cveId").alias("cve_id"),
            get_json_object(col("cveMetadata"), "$.datePublished").alias("published_date"),
            col("_source_year").alias("year"),
            col("_ingestion_timestamp").alias("ingested_at")
        ).show(5, truncate=False)
except Exception as v_err:
    print("ERROR verifying table:", v_err)
    raise

print("\n" + "="*60)
print("BRONZE LAYER INGESTION COMPLETE")
print("="*60)
print(f"Status: SUCCESS")
print(f"Records Ingested: {final_count:,}")
print(f"Table: {BRONZE_TABLE}")
print("Next Step: Run silver transformations (02_bronze_to_silver.py)")
print("="*60)