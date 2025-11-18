-- Databricks notebook source
-- Section 1: Executive Summary & Data Overview

-- Query 1.1: Dataset Overview and Summary Statistics
SELECT
    'Dataset Overview' as metric_category,
    COUNT(*) as total_cve_records,
    COUNT(DISTINCT cve_id) as unique_cve_identifiers,
    MIN(published_timestamp) as earliest_publication,
    MAX(published_timestamp) as latest_publication,
    DATEDIFF(MAX(published_timestamp), MIN(published_timestamp)) as coverage_days,
    COUNT(CASE WHEN publication_state = 'PUBLISHED' THEN 1 END) as published_cves,
    COUNT(CASE WHEN publication_state = 'REJECTED' THEN 1 END) as rejected_cves,
    ROUND(100.0 * COUNT(CASE WHEN publication_state = 'PUBLISHED' THEN 1 END) / COUNT(*), 2) as publish_rate_percent
FROM cse587.silver.core_cves;

-- COMMAND ----------

-- Query 1.2: Data Quality and Completeness Metrics
SELECT
    'Data Quality Metrics' as category,
    COUNT(*) as total_records,
    SUM(CASE WHEN cve_id IS NOT NULL THEN 1 ELSE 0 END) as cve_id_present,
    SUM(CASE WHEN has_cvss THEN 1 ELSE 0 END) as cvss_scores_available,
    SUM(CASE WHEN has_description THEN 1 ELSE 0 END) as descriptions_available,
    ROUND(100.0 * SUM(CASE WHEN has_cvss THEN 1 ELSE 0 END) / COUNT(*), 2) as cvss_coverage_percent,
    ROUND(100.0 * SUM(CASE WHEN has_description THEN 1 ELSE 0 END) / COUNT(*), 2) as description_coverage_percent,
    ROUND(AVG(cvss_base_score), 2) as overall_avg_cvss_score
FROM cse587.silver.core_cves;

-- COMMAND ----------

-- Query 1.3: Publication State Breakdown
SELECT
    publication_state,
    COUNT(*) as cve_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage,
    MIN(published_timestamp) as first_occurrence,
    MAX(published_timestamp) as last_occurrence
FROM cse587.silver.core_cves
WHERE publication_state IS NOT NULL
GROUP BY publication_state
ORDER BY cve_count DESC;

-- COMMAND ----------

-- Section 2: Temporal Analysis - Publication Trends

-- Query 2.1: Daily Publication Trends (Last 60 Days)
SELECT
    DATE(published_timestamp) as publication_date,
    COUNT(*) as daily_cve_count,
    COUNT(DISTINCT cve_id) as unique_cves_daily,
    SUM(CASE WHEN cvss_severity_rating = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN cvss_severity_rating = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN cvss_severity_rating = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
    ROUND(AVG(cvss_base_score), 2) as avg_daily_cvss
FROM cse587.silver.core_cves
WHERE published_timestamp IS NOT NULL
GROUP BY DATE(published_timestamp)
ORDER BY publication_date DESC
LIMIT 60;

-- COMMAND ----------

-- Query 2.2: Monthly Aggregation with Trends
SELECT
    DATE_FORMAT(published_timestamp, 'yyyy-MM') as publication_month,
    COUNT(*) as monthly_total,
    COUNT(DISTINCT cve_id) as unique_monthly_cves,
    ROUND(AVG(cvss_base_score), 2) as avg_monthly_cvss,
    MAX(cvss_base_score) as max_monthly_cvss,
    MIN(cvss_base_score) as min_monthly_cvss,
    COUNT(DISTINCT DATE(published_timestamp)) as active_days_in_month
FROM cse587.silver.core_cves
WHERE published_timestamp IS NOT NULL
GROUP BY DATE_FORMAT(published_timestamp, 'yyyy-MM')
ORDER BY publication_month DESC;

-- COMMAND ----------

-- Query 2.3: Day of Week Publication Patterns
SELECT
    DAYOFWEEK(published_timestamp) as day_number,
    CASE DAYOFWEEK(published_timestamp)
        WHEN 1 THEN 'Sunday'
        WHEN 2 THEN 'Monday'
        WHEN 3 THEN 'Tuesday'
        WHEN 4 THEN 'Wednesday'
        WHEN 5 THEN 'Thursday'
        WHEN 6 THEN 'Friday'
        WHEN 7 THEN 'Saturday'
    END as day_of_week,
    COUNT(*) as total_publications,
    ROUND(AVG(cvss_base_score), 2) as avg_cvss_score,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage_of_total
FROM cse587.silver.core_cves
WHERE published_timestamp IS NOT NULL
GROUP BY DAYOFWEEK(published_timestamp)
ORDER BY day_number;

-- COMMAND ----------

-- Section 3: CVSS Score Analysis & Risk Assessment
-- Query 3.1: Risk Category Distribution
SELECT
    cvss_severity_rating as risk_category,
    COUNT(*) as cve_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage,
    ROUND(AVG(cvss_base_score), 2) as avg_cvss_in_category,
    MIN(cvss_base_score) as min_score,
    MAX(cvss_base_score) as max_score
FROM cse587.silver.core_cves
WHERE cvss_severity_rating IS NOT NULL
GROUP BY cvss_severity_rating
ORDER BY
    CASE cvss_severity_rating
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END;

-- COMMAND ----------

-- Query 3.2: CVSS Version Usage Analysis
SELECT
    cvss_version_used,
    COUNT(*) as usage_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as usage_percentage,
    ROUND(AVG(cvss_base_score), 2) as average_score,
    SUM(CASE WHEN cvss_severity_rating = 'CRITICAL' THEN 1 ELSE 0 END) as critical_vulnerabilities,
    SUM(CASE WHEN cvss_severity_rating = 'HIGH' THEN 1 ELSE 0 END) as high_vulnerabilities
FROM cse587.silver.core_cves
WHERE cvss_version_used IS NOT NULL
GROUP BY cvss_version_used
ORDER BY usage_count DESC;

-- COMMAND ----------

-- Query 3.3: CVSS Severity Rating Distribution
SELECT
    cvss_severity_rating,
    COUNT(*) as count,
    ROUND(AVG(cvss_base_score), 2) as avg_score,
    MIN(cvss_base_score) as min_score,
    MAX(cvss_base_score) as max_score,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage
FROM cse587.silver.core_cves
WHERE cvss_severity_rating IS NOT NULL AND cvss_severity_rating != 'UNKNOWN'
GROUP BY cvss_severity_rating
ORDER BY avg_score DESC;

-- COMMAND ----------

-- Query 3.4: Top 20 Highest CVSS Scored Vulnerabilities
SELECT
    cve_id,
    cvss_base_score,
    cvss_severity_rating as severity_rating,
    risk_category,
    DATE(published_timestamp) as published_date,
    assigning_org_name as assigned_by,
    SUBSTRING(cve_description, 1, 100) as description_preview
FROM cse587.silver.core_cves
WHERE cvss_base_score IS NOT NULL
ORDER BY cvss_base_score DESC, published_timestamp DESC
LIMIT 20;

-- COMMAND ----------

-- Section 4: Vendor & Product Vulnerability Analysis

-- Query 4.1: Top 25 Vendors by Vulnerability Count
SELECT
    vendor_name,
    COUNT(DISTINCT cve_id) as total_vulnerabilities,
    COUNT(*) as total_product_instances,
    COUNT(DISTINCT product_name) as unique_products_affected,
    ROUND(COUNT(DISTINCT cve_id) * 1.0 / NULLIF(COUNT(DISTINCT product_name), 0), 2) as avg_cves_per_product
FROM cse587.silver.affected_products
WHERE vendor_name IS NOT NULL
GROUP BY vendor_name
ORDER BY total_vulnerabilities DESC
LIMIT 25;

-- COMMAND ----------

-- Query 4.2: Most Vulnerable Products (Vendor/Product Combination)
SELECT
    vendor_name,
    product_name,
    COUNT(DISTINCT cve_id) as vulnerability_count,
    COUNT(*) as total_records,
    CASE
        WHEN COUNT(DISTINCT cve_id) >= 20 THEN 'CRITICAL PRIORITY'
        WHEN COUNT(DISTINCT cve_id) >= 10 THEN 'HIGH PRIORITY'
        WHEN COUNT(DISTINCT cve_id) >= 5 THEN 'MEDIUM PRIORITY'
        ELSE 'LOW PRIORITY'
    END as priority_level
FROM cse587.silver.affected_products
WHERE vendor_name IS NOT NULL AND product_name IS NOT NULL
GROUP BY vendor_name, product_name
ORDER BY vulnerability_count DESC
LIMIT 30;

-- COMMAND ----------

-- Query 4.3: Vendor Portfolio Diversity Analysis
SELECT
    vendor_name,
    COUNT(DISTINCT product_name) as product_portfolio_size,
    COUNT(DISTINCT cve_id) as total_vulnerabilities,
    ROUND(COUNT(DISTINCT cve_id) * 1.0 / NULLIF(COUNT(DISTINCT product_name), 0), 2) as vulnerability_density,
    CASE
        WHEN COUNT(DISTINCT cve_id) > 100 THEN 'HIGH RISK'
        WHEN COUNT(DISTINCT cve_id) > 50 THEN 'MEDIUM RISK'
        ELSE 'LOW RISK'
    END as vendor_risk_level
FROM cse587.silver.affected_products
WHERE vendor_name IS NOT NULL AND product_name IS NOT NULL
GROUP BY vendor_name
HAVING COUNT(DISTINCT product_name) >= 3
ORDER BY total_vulnerabilities DESC
LIMIT 20;

-- COMMAND ----------

SELECT
    'CVE Lakehouse Executive Summary' as report_title,
    (SELECT COUNT(DISTINCT cve_id) FROM cse587.silver.core_cves) as total_unique_cves,
    (SELECT COUNT(DISTINCT vendor_name) FROM cse587.silver.affected_products WHERE vendor_name IS NOT NULL) as total_vendors,
    (SELECT COUNT(DISTINCT product_name) FROM cse587.silver.affected_products WHERE product_name IS NOT NULL) as total_products,
    (SELECT ROUND(AVG(cvss_base_score), 2) FROM cse587.silver.core_cves WHERE cvss_base_score IS NOT NULL) as overall_avg_cvss,
    (SELECT COUNT(*) FROM cse587.silver.core_cves WHERE cvss_severity_rating = 'CRITICAL') as critical_cves,
    (SELECT COUNT(*) FROM cse587.silver.core_cves WHERE cvss_severity_rating = 'HIGH') as high_risk_cves,
    (SELECT MAX(published_timestamp) FROM cse587.silver.core_cves) as most_recent_publication,
    CURRENT_TIMESTAMP() as report_generated_at;

-- ============================================================================
-- INSTRUCTIONS:
-- 1. Create a notebook with all queries and export results table-by-table
-- 2. refer to html file for all reults of the queries
-- ============================================================================