-- ClickHouse Table Creation Script for L1 Anomaly Detection System
-- Compatible with ClickHouse versions 20.x and above
-- Run this script to create all required tables

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS l1_anomaly_detection;

-- Use the database
USE l1_anomaly_detection;

-- 1. Main anomalies table for storing detected anomalies
CREATE TABLE IF NOT EXISTS anomalies (
    anomaly_id String,
    timestamp DateTime,
    file_path String,
    file_format String,
    anomaly_type String,
    severity String,
    confidence_score Float64,
    packet_number UInt32,
    line_number UInt32,
    description String,
    ml_detected UInt8,
    rule_based_detected UInt8,
    details String
) ENGINE = MergeTree()
ORDER BY (timestamp, file_path, anomaly_type);

-- 2. Analysis sessions table for tracking processing sessions
CREATE TABLE IF NOT EXISTS analysis_sessions (
    session_id String,
    timestamp DateTime,
    file_path String,
    file_format String,
    total_packets UInt32,
    total_lines UInt32,
    total_anomalies UInt32,
    high_severity_anomalies UInt32,
    medium_severity_anomalies UInt32,
    low_severity_anomalies UInt32,
    analysis_duration_seconds Float64,
    session_details String
) ENGINE = MergeTree()
ORDER BY (timestamp, file_path);

-- 3. ML training metrics table for storing training results
CREATE TABLE IF NOT EXISTS training_metrics (
    training_id String,
    timestamp DateTime,
    model_type String,
    training_data_path String,
    model_save_path String,
    precision_score Float64,
    recall_score Float64,
    f1_score Float64,
    accuracy_score Float64,
    training_duration_seconds Float64,
    data_points_count UInt32,
    model_parameters String,
    training_report String
) ENGINE = MergeTree()
ORDER BY (timestamp, model_type);

-- 4. Comprehensive anomalies table for all L1 analysis types
CREATE TABLE IF NOT EXISTS comprehensive_anomalies (
    anomaly_id String,
    timestamp DateTime,
    file_path String,
    file_format String,
    analysis_category String,
    anomaly_type String,
    severity String,
    confidence_score Float64,
    packet_number UInt32,
    line_number UInt32,
    description String,
    ue_context UInt8,
    fronthaul_context UInt8,
    mac_context UInt8,
    protocol_context UInt8,
    signal_context UInt8,
    performance_context UInt8,
    ml_detected UInt8,
    rule_based_detected UInt8,
    cross_correlated UInt8,
    details String
) ENGINE = MergeTree()
ORDER BY (timestamp, file_path, analysis_category, anomaly_type);

-- 5. L1 analysis sessions table for comprehensive analysis tracking
CREATE TABLE IF NOT EXISTS l1_analysis_sessions (
    session_id String,
    timestamp DateTime,
    file_path String,
    file_format String,
    total_packets UInt32,
    total_lines UInt32,
    ue_events_count UInt32,
    fronthaul_issues_count UInt32,
    mac_anomalies_count UInt32,
    protocol_violations_count UInt32,
    signal_quality_issues_count UInt32,
    performance_issues_count UInt32,
    total_anomalies UInt32,
    high_severity_anomalies UInt32,
    medium_severity_anomalies UInt32,
    low_severity_anomalies UInt32,
    overall_health_score Float64,
    analysis_duration_seconds Float64,
    session_details String
) ENGINE = MergeTree()
ORDER BY (timestamp, file_path);

-- 6. ML algorithm details table for storing individual algorithm results
CREATE TABLE IF NOT EXISTS ml_algorithm_details (
    detection_id String,
    session_id String,
    timestamp DateTime,
    file_path String,
    algorithm_name String,
    anomaly_detected UInt8,
    confidence_score Float64,
    algorithm_specific_data String,
    processing_time_ms Float64
) ENGINE = MergeTree()
ORDER BY (timestamp, session_id, algorithm_name);

-- 7. Feature vectors table for ML training data
CREATE TABLE IF NOT EXISTS feature_vectors (
    vector_id String,
    timestamp DateTime,
    file_path String,
    line_number UInt32,
    packet_number UInt32,
    feature_vector String,
    label UInt8,
    data_source String
) ENGINE = MergeTree()
ORDER BY (timestamp, file_path);

-- 8. System status table for tracking system health
CREATE TABLE IF NOT EXISTS system_status (
    status_id String,
    timestamp DateTime,
    component_name String,
    status String,
    uptime_seconds UInt32,
    memory_usage_mb Float64,
    cpu_usage_percent Float64,
    disk_usage_mb Float64,
    status_details String
) ENGINE = MergeTree()
ORDER BY (timestamp, component_name);

-- Create materialized views for common queries

-- View for anomaly summary by type
CREATE MATERIALIZED VIEW IF NOT EXISTS anomaly_summary_by_type
ENGINE = SummingMergeTree()
ORDER BY (anomaly_type, severity, toDate(timestamp))
AS SELECT
    anomaly_type,
    severity,
    toDate(timestamp) as date,
    count() as count,
    avg(confidence_score) as avg_confidence
FROM comprehensive_anomalies
GROUP BY anomaly_type, severity, toDate(timestamp);

-- View for daily analysis summary
CREATE MATERIALIZED VIEW IF NOT EXISTS daily_analysis_summary
ENGINE = SummingMergeTree()
ORDER BY (toDate(timestamp))
AS SELECT
    toDate(timestamp) as date,
    count() as sessions_count,
    sum(total_anomalies) as total_anomalies,
    avg(overall_health_score) as avg_health_score,
    sum(analysis_duration_seconds) as total_processing_time
FROM l1_analysis_sessions
GROUP BY toDate(timestamp);

-- View for ML algorithm performance
CREATE MATERIALIZED VIEW IF NOT EXISTS ml_algorithm_performance
ENGINE = SummingMergeTree()
ORDER BY (algorithm_name, toDate(timestamp))
AS SELECT
    algorithm_name,
    toDate(timestamp) as date,
    count() as detections_count,
    sum(anomaly_detected) as anomalies_found,
    avg(confidence_score) as avg_confidence,
    avg(processing_time_ms) as avg_processing_time
FROM ml_algorithm_details
GROUP BY algorithm_name, toDate(timestamp);

-- Insert sample data for testing (optional)
-- Uncomment the following lines to insert test data

/*
INSERT INTO comprehensive_anomalies VALUES
(
    'TEST_001',
    now(),
    '/test/sample.pcap',
    'pcap',
    'ue_events',
    'ue_attach',
    'high',
    0.95,
    1001,
    0,
    'Test UE attach anomaly detected',
    1, 0, 0, 0, 0, 0,
    1, 1, 0,
    '{"test": true}'
);

INSERT INTO l1_analysis_sessions VALUES
(
    'SESSION_001',
    now(),
    '/test/sample.pcap',
    'pcap',
    1500,
    0,
    1, 0, 0, 0, 0, 0,
    1,
    1, 0, 0,
    95.5,
    2.34,
    '{"test_session": true}'
);
*/

-- Show created tables
SHOW TABLES FROM l1_anomaly_detection;

-- Show table structures (uncomment to see details)
/*
DESCRIBE l1_anomaly_detection.comprehensive_anomalies;
DESCRIBE l1_anomaly_detection.l1_analysis_sessions;
DESCRIBE l1_anomaly_detection.training_metrics;
*/