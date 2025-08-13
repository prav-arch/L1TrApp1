-- ClickHouse 18 Compatible Table Creation Script for L1 Anomaly Detection
-- Execute this script to create all required tables with proper schema

-- Create database
CREATE DATABASE IF NOT EXISTS l1_anomaly_detection;

-- Use the database
USE l1_anomaly_detection;

-- Drop existing tables if they exist (optional - uncomment if needed)
-- DROP TABLE IF EXISTS anomalies;
-- DROP TABLE IF EXISTS sessions;
-- DROP TABLE IF EXISTS processed_files;

-- 1. Main anomalies table with all ML algorithm details
CREATE TABLE IF NOT EXISTS anomalies (
    id UInt64,
    timestamp DateTime,
    anomaly_type String,
    description String,
    severity String,
    source_file String,
    packet_number UInt32,
    session_id String,
    confidence_score Float64,
    model_agreement UInt8,
    ml_algorithm_details String,
    isolation_forest_score Float64,
    one_class_svm_score Float64,
    dbscan_prediction Int8,
    random_forest_score Float64,
    ensemble_vote String,
    detection_timestamp String,
    status String
) ENGINE = MergeTree
ORDER BY (timestamp, severity, anomaly_type)
PARTITION BY toYYYYMM(timestamp);

-- 2. Analysis sessions tracking table
CREATE TABLE IF NOT EXISTS sessions (
    session_id String,
    start_time DateTime,
    end_time DateTime,
    files_to_process UInt32,
    files_processed UInt32,
    total_anomalies UInt32,
    status String,
    processing_time_seconds Float64
) ENGINE = MergeTree
ORDER BY start_time;

-- 3. Processed files log table
CREATE TABLE IF NOT EXISTS processed_files (
    filename String,
    processing_time DateTime,
    total_samples UInt32,
    anomalies_detected UInt32,
    session_id String,
    processing_status String
) ENGINE = MergeTree
ORDER BY processing_time;

-- 4. Optional: ML model performance tracking table
CREATE TABLE IF NOT EXISTS ml_model_performance (
    timestamp DateTime,
    session_id String,
    model_name String,
    detection_rate Float64,
    avg_confidence Float64,
    accuracy_score Float64,
    precision_score Float64,
    recall_score Float64,
    f1_score Float64,
    file_analyzed String,
    total_samples UInt32,
    anomalies_found UInt32,
    false_positives UInt32,
    true_positives UInt32
) ENGINE = MergeTree
ORDER BY (timestamp, model_name);

-- Verify tables were created
SHOW TABLES FROM l1_anomaly_detection;

-- Show table schemas to verify structure
DESCRIBE l1_anomaly_detection.anomalies;
DESCRIBE l1_anomaly_detection.sessions;
DESCRIBE l1_anomaly_detection.processed_files;