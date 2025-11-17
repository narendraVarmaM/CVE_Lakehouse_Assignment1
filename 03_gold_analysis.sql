-- ============================================================================
-- CVE DATA LAKEHOUSE - GOLD LAYER ANALYTICS
-- Data Engineering Assignment - University at Buffalo
--
-- Purpose: Exploratory analysis and business intelligence queries
-- Tables: workspace.default.core_cves, workspace.default.affected_products
-- Author: [Your Name]
-- Date: November 2024
-- ============================================================================

-- Note: Adjust catalog/schema names based on your configuration
-- Current configuration: workspace.default

-- ============================================================================
-- SECTION 1: DATA OVERVIEW AND SUMMARY STATISTICS
-- ============================================================================

-- Query 1.1: Overall CVE dataset summary
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
FROM workspace.default.core_cves;

-- Query 1.2: Data completeness and quality metrics
SELECT
    'Data Quality Metrics' as category,
    COUNT(*) as total_records,
    SUM(CASE WHEN cve_id IS NOT NULL THEN 1 ELSE 0 END) as cve_id_present,
    SUM(CASE WHEN has_cvss THEN 1 ELSE 0 END) as cvss_scores_available,
    SUM(CASE WHEN has_description THEN 1 ELSE 0 END) as descriptions_available,
    ROUND(100.0 * SUM(CASE WHEN has_cvss THEN 1 ELSE 0 END) / COUNT(*), 2) as cvss_coverage_percent,
    ROUND(100.0 * SUM(CASE WHEN has_description THEN 1 ELSE 0 END) / COUNT(*), 2) as description_coverage_percent
FROM workspace.default.core_cves;

-- Query 1.3: Publication state breakdown
SELECT
    publication_state,
    COUNT(*) as cve_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage,
    MIN(published_timestamp) as first_occurrence,
    MAX(published_timestamp) as last_occurrence
FROM workspace.default.core_cves
GROUP BY publication_state
ORDER BY cve_count DESC;

-- ============================================================================
-- SECTION 2: TEMPORAL ANALYSIS - Publication Trends Over Time
-- ============================================================================

-- Query 2.1: Daily publication trends
SELECT
    DATE(published_timestamp) as publication_date,
    COUNT(*) as daily_cve_count,
    COUNT(DISTINCT cve_id) as unique_cves_daily,
    SUM(CASE WHEN risk_category = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN risk_category = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN risk_category = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count
FROM workspace.default.core_cves
WHERE published_timestamp IS NOT NULL
GROUP BY DATE(published_timestamp)
ORDER BY publication_date DESC;

-- Query 2.2: Monthly aggregation with trends
SELECT
    DATE_FORMAT(published_timestamp, 'yyyy-MM') as publication_month,
    COUNT(*) as monthly_total,
    COUNT(DISTINCT cve_id) as unique_monthly_cves,
    ROUND(AVG(cvss_base_score), 2) as avg_monthly_cvss,
    MAX(cvss_base_score) as max_monthly_cvss,
    COUNT(DISTINCT DATE(published_timestamp)) as active_days_in_month
FROM workspace.default.core_cves
WHERE published_timestamp IS NOT NULL
GROUP BY DATE_FORMAT(published_timestamp, 'yyyy-MM')
ORDER BY publication_month DESC;

-- Query 2.3: Day of week patterns
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
FROM workspace.default.core_cves
WHERE published_timestamp IS NOT NULL
GROUP BY DAYOFWEEK(published_timestamp)
ORDER BY day_number;

-- ============================================================================
-- SECTION 3: CVSS SCORE ANALYSIS AND RISK ASSESSMENT
-- ============================================================================

-- Query 3.1: Risk category distribution
SELECT
    risk_category,
    COUNT(*) as cve_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage,
    ROUND(AVG(cvss_base_score), 2) as avg_cvss_in_category,
    MIN(cvss_base_score) as min_score,
    MAX(cvss_base_score) as max_score
FROM workspace.default.core_cves
GROUP BY risk_category
ORDER BY
    CASE risk_category
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END;

-- Query 3.2: CVSS version usage analysis
SELECT
    cvss_version_used,
    COUNT(*) as usage_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as usage_percentage,
    ROUND(AVG(cvss_base_score), 2) as average_score,
    COUNT(CASE WHEN risk_category = 'CRITICAL' THEN 1 END) as critical_vulnerabilities
FROM workspace.default.core_cves
GROUP BY cvss_version_used
ORDER BY usage_count DESC;

-- Query 3.3: Severity rating distribution
SELECT
    cvss_severity_rating,
    COUNT(*) as count,
    ROUND(AVG(cvss_base_score), 2) as avg_score,
    MIN(cvss_base_score) as min_score,
    MAX(cvss_base_score) as max_score,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage
FROM workspace.default.core_cves
WHERE cvss_severity_rating != 'UNKNOWN'
GROUP BY cvss_severity_rating
ORDER BY avg_score DESC;

-- Query 3.4: Top 20 highest CVSS scored vulnerabilities
SELECT
    cve_id,
    cvss_base_score,
    cvss_severity_rating,
    risk_category,
    DATE(published_timestamp) as published_date,
    SUBSTRING(cve_description, 1, 100) as description_preview
FROM workspace.default.core_cves
WHERE cvss_base_score IS NOT NULL
ORDER BY cvss_base_score DESC, published_timestamp DESC
LIMIT 20;

-- ============================================================================
-- SECTION 4: VENDOR AND PRODUCT VULNERABILITY ANALYSIS
-- ============================================================================

-- Query 4.1: Top 25 vendors by vulnerability count
SELECT
    vendor_name,
    COUNT(DISTINCT cve_id) as total_vulnerabilities,
    COUNT(*) as total_product_instances,
    COUNT(DISTINCT product_name) as unique_products_affected,
    ROUND(COUNT(DISTINCT cve_id) * 1.0 / COUNT(DISTINCT product_name), 2) as avg_cves_per_product
FROM workspace.default.affected_products
WHERE vendor_name IS NOT NULL
GROUP BY vendor_name
ORDER BY total_vulnerabilities DESC
LIMIT 25;

-- Query 4.2: Most vulnerable products (vendor/product combination)
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
FROM workspace.default.affected_products
WHERE vendor_name IS NOT NULL AND product_name IS NOT NULL
GROUP BY vendor_name, product_name
ORDER BY vulnerability_count DESC
LIMIT 30;

-- Query 4.3: Vendor portfolio diversity analysis
SELECT
    vendor_name,
    COUNT(DISTINCT product_name) as product_portfolio_size,
    COUNT(DISTINCT cve_id) as total_vulnerabilities,
    ROUND(COUNT(DISTINCT cve_id) * 1.0 / COUNT(DISTINCT product_name), 2) as vulnerability_density
FROM workspace.default.affected_products
WHERE vendor_name IS NOT NULL AND product_name IS NOT NULL
GROUP BY vendor_name
HAVING COUNT(DISTINCT product_name) >= 3
ORDER BY total_vulnerabilities DESC
LIMIT 20;

-- ============================================================================
-- SECTION 5: INTEGRATED ANALYSIS - CVE Details with Product Information
-- ============================================================================

-- Query 5.1: Critical CVEs with affected vendor/product information
SELECT
    c.cve_id,
    c.cvss_base_score,
    c.risk_category,
    DATE(c.published_timestamp) as published_date,
    COUNT(DISTINCT a.vendor_name) as affected_vendor_count,
    COUNT(DISTINCT a.product_name) as affected_product_count,
    SUBSTRING(c.cve_description, 1, 80) as description_excerpt
FROM workspace.default.core_cves c
LEFT JOIN workspace.default.affected_products a ON c.cve_id = a.cve_id
WHERE c.risk_category = 'CRITICAL'
GROUP BY c.cve_id, c.cvss_base_score, c.risk_category, c.published_timestamp, c.cve_description
ORDER BY c.cvss_base_score DESC, affected_vendor_count DESC
LIMIT 25;

-- Query 5.2: Vendor risk profile with CVSS statistics
SELECT
    a.vendor_name,
    COUNT(DISTINCT c.cve_id) as total_cves,
    ROUND(AVG(c.cvss_base_score), 2) as avg_cvss_score,
    MAX(c.cvss_base_score) as max_cvss_score,
    SUM(CASE WHEN c.risk_category = 'CRITICAL' THEN 1 ELSE 0 END) as critical_vulns,
    SUM(CASE WHEN c.risk_category = 'HIGH' THEN 1 ELSE 0 END) as high_vulns,
    SUM(CASE WHEN c.risk_category = 'MEDIUM' THEN 1 ELSE 0 END) as medium_vulns,
    COUNT(DISTINCT a.product_name) as products_affected
FROM workspace.default.affected_products a
INNER JOIN workspace.default.core_cves c ON a.cve_id = c.cve_id
WHERE a.vendor_name IS NOT NULL AND c.cvss_base_score IS NOT NULL
GROUP BY a.vendor_name
ORDER BY total_cves DESC
LIMIT 20;

-- ============================================================================
-- SECTION 6: PUBLICATION PATTERNS AND BATCH ANALYSIS
-- ============================================================================

-- Query 6.1: Identify batch publication dates (potential coordinated disclosures)
SELECT
    DATE(published_timestamp) as publication_date,
    COUNT(*) as cves_published,
    COUNT(DISTINCT cve_id) as unique_cves,
    SUM(CASE WHEN risk_category IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as high_severity_count,
    ROUND(AVG(cvss_base_score), 2) as avg_cvss,
    CASE
        WHEN COUNT(*) >= 20 THEN 'MAJOR BATCH'
        WHEN COUNT(*) >= 10 THEN 'LARGE BATCH'
        WHEN COUNT(*) >= 5 THEN 'MEDIUM BATCH'
        WHEN COUNT(*) >= 2 THEN 'SMALL BATCH'
        ELSE 'SINGLE'
    END as batch_classification
FROM workspace.default.core_cves
WHERE published_timestamp IS NOT NULL
GROUP BY DATE(published_timestamp)
ORDER BY cves_published DESC, publication_date DESC;

-- Query 6.2: Assigning organization activity
SELECT
    assigning_org_name,
    COUNT(*) as total_assigned,
    COUNT(DISTINCT cve_id) as unique_cves,
    ROUND(AVG(cvss_base_score), 2) as avg_cvss,
    MIN(published_timestamp) as first_assignment,
    MAX(published_timestamp) as last_assignment,
    DATEDIFF(MAX(published_timestamp), MIN(published_timestamp)) as activity_span_days
FROM workspace.default.core_cves
WHERE assigning_org_name IS NOT NULL
GROUP BY assigning_org_name
ORDER BY total_assigned DESC
LIMIT 20;

-- ============================================================================
-- SECTION 7: TIME-BASED RISK TRENDING
-- ============================================================================

-- Query 7.1: Cumulative CVE count over time
SELECT
    DATE(published_timestamp) as date,
    COUNT(*) as daily_count,
    SUM(COUNT(*)) OVER (ORDER BY DATE(published_timestamp)) as cumulative_total,
    AVG(cvss_base_score) as daily_avg_cvss,
    DATEDIFF(CURRENT_DATE(), DATE(published_timestamp)) as days_ago
FROM workspace.default.core_cves
WHERE published_timestamp IS NOT NULL
GROUP BY DATE(published_timestamp)
ORDER BY date DESC;

-- Query 7.2: Recent activity (last 30 days)
SELECT
    DATE(published_timestamp) as date,
    COUNT(*) as cve_count,
    SUM(CASE WHEN risk_category = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
    SUM(CASE WHEN risk_category = 'HIGH' THEN 1 ELSE 0 END) as high,
    SUM(CASE WHEN risk_category = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
    ROUND(AVG(cvss_base_score), 2) as avg_cvss
FROM workspace.default.core_cves
WHERE published_timestamp >= DATE_SUB(CURRENT_DATE(), 30)
GROUP BY DATE(published_timestamp)
ORDER BY date DESC;

-- ============================================================================
-- SECTION 8: DATA VALIDATION AND INTEGRITY CHECKS
-- ============================================================================

-- Query 8.1: Referential integrity check
SELECT
    'Referential Integrity' as check_type,
    COUNT(DISTINCT ap.cve_id) as cves_in_affected_products,
    COUNT(DISTINCT cc.cve_id) as cves_in_core_table,
    COUNT(DISTINCT ap.cve_id) - COUNT(DISTINCT cc.cve_id) as difference
FROM workspace.default.affected_products ap
FULL OUTER JOIN workspace.default.core_cves cc ON ap.cve_id = cc.cve_id;

-- Query 8.2: Orphaned records detection
SELECT
    'Orphaned Products Check' as validation_check,
    COUNT(*) as orphaned_count
FROM workspace.default.affected_products ap
LEFT ANTI JOIN workspace.default.core_cves cc ON ap.cve_id = cc.cve_id;

-- Query 8.3: Duplicate detection in core table
SELECT
    cve_id,
    COUNT(*) as occurrence_count
FROM workspace.default.core_cves
GROUP BY cve_id
HAVING COUNT(*) > 1
ORDER BY occurrence_count DESC;

-- ============================================================================
-- SECTION 9: EXECUTIVE SUMMARY DASHBOARD
-- ============================================================================

-- Query 9.1: Executive KPI summary
SELECT
    'CVE Lakehouse Executive Summary' as report_title,
    (SELECT COUNT(DISTINCT cve_id) FROM workspace.default.core_cves) as total_unique_cves,
    (SELECT COUNT(DISTINCT vendor_name) FROM workspace.default.affected_products WHERE vendor_name IS NOT NULL) as total_vendors,
    (SELECT COUNT(DISTINCT product_name) FROM workspace.default.affected_products WHERE product_name IS NOT NULL) as total_products,
    (SELECT ROUND(AVG(cvss_base_score), 2) FROM workspace.default.core_cves WHERE cvss_base_score IS NOT NULL) as overall_avg_cvss,
    (SELECT COUNT(*) FROM workspace.default.core_cves WHERE risk_category = 'CRITICAL') as critical_cves,
    (SELECT COUNT(*) FROM workspace.default.core_cves WHERE risk_category = 'HIGH') as high_risk_cves,
    (SELECT MAX(published_timestamp) FROM workspace.default.core_cves) as most_recent_publication;

-- ============================================================================
-- END OF GOLD LAYER ANALYTICS
-- ============================================================================
