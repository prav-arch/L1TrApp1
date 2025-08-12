-- Raw SQL to create ClickHouse database and tables
-- Execute this in ClickHouse client or web interface

-- Create database
CREATE DATABASE IF NOT EXISTS l1_anomaly_detection;

-- Use the database
USE l1_anomaly_detection;

-- Create anomalies table with frontend-compatible schema
CREATE TABLE IF NOT EXISTS anomalies (
    id String,
    timestamp DateTime,
    type String,
    description String,
    severity String,
    source_file String,
    packet_number UInt32,
    mac_address String,
    ue_id String,
    details String,
    status String,
    anomaly_type String,
    confidence_score Float64,
    detection_algorithm String,
    context_data String
) ENGINE = MergeTree()
ORDER BY (timestamp, type, severity);

-- Create analysis_sessions table
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
ORDER BY (timestamp, session_id);

-- Create metrics table
CREATE TABLE IF NOT EXISTS metrics (
    metric_id String,
    timestamp DateTime,
    category String,
    name String,
    value Float64,
    unit String,
    tags String
) ENGINE = MergeTree()
ORDER BY (timestamp, category, name);

-- Create processed_files table
CREATE TABLE IF NOT EXISTS processed_files (
    file_id String,
    timestamp DateTime,
    file_name String,
    file_path String,
    file_size UInt64,
    file_type String,
    status String,
    processing_time_seconds Float64,
    anomalies_found UInt32,
    error_message String
) ENGINE = MergeTree()
ORDER BY (timestamp, file_name);

-- Verify tables were created
SHOW TABLES FROM l1_anomaly_detection;