-- Create ClickHouse database and tables for L1 troubleshooting system

CREATE DATABASE IF NOT EXISTS l1_anomaly_detection;

USE l1_anomaly_detection;

-- Anomalies table
CREATE TABLE IF NOT EXISTS anomalies (
    id String,
    timestamp DateTime64(3),
    type String,
    description String,
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    source_file String,
    packet_number Nullable(UInt32),
    mac_address Nullable(String),
    ue_id Nullable(String),
    details Nullable(String),
    status Enum8('open' = 1, 'investigating' = 2, 'resolved' = 3, 'closed' = 4),
    anomaly_type Nullable(String),
    confidence_score Nullable(Float32),
    detection_algorithm Nullable(String),
    context_data Nullable(String)
) ENGINE = MergeTree()
ORDER BY timestamp
PARTITION BY toYYYYMM(timestamp);

-- Processed files table
CREATE TABLE IF NOT EXISTS processed_files (
    id String,
    filename String,
    file_type String,
    file_size UInt64,
    upload_date DateTime64(3),
    processing_status Enum8('pending' = 1, 'processing' = 2, 'completed' = 3, 'failed' = 4),
    anomalies_found UInt32 DEFAULT 0,
    processing_time Nullable(UInt32),
    error_message Nullable(String)
) ENGINE = MergeTree()
ORDER BY upload_date
PARTITION BY toYYYYMM(upload_date);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id String,
    session_name String,
    start_time DateTime64(3),
    end_time Nullable(DateTime64(3)),
    packets_analyzed UInt64 DEFAULT 0,
    anomalies_detected UInt32 DEFAULT 0
) ENGINE = MergeTree()
ORDER BY start_time
PARTITION BY toYYYYMM(start_time);

-- Metrics table
CREATE TABLE IF NOT EXISTS metrics (
    id String,
    category String,
    metric_name String,
    metric_value Float64,
    timestamp DateTime64(3),
    description Nullable(String)
) ENGINE = MergeTree()
ORDER BY timestamp
PARTITION BY toYYYYMM(timestamp);

-- Insert sample data for testing
INSERT INTO anomalies VALUES
('test001', '2025-08-12 09:00:00.000', 'fronthaul', 'DU-RU link timeout on interface eth0, packet loss: 75%', 'critical', 'log_20250812_120530.txt', 1523, 'aa:bb:cc:dd:ee:ff', NULL, '{"cell_id": "Cell-45", "technology": "5G-NR"}', 'open', 'fronthaul_du_ru_communication_failure', 0.95, 'isolation_forest', '{"cell_id": "Cell-45", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 150}'),
('test002', '2025-08-12 09:01:00.000', 'ue_event', 'UE 345678 attach rejected, cause: authentication failure', 'high', 'log_20250812_125630.txt', NULL, NULL, 'UE-345678', '{"ue_id": "UE-345678", "imsi": "123456789012345"}', 'open', 'ue_attach_failure', 0.88, 'dbscan', '{"cell_id": "Cell-23", "sector_id": 1, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 1}'),
('test003', '2025-08-12 09:02:00.000', 'mac_address', 'Duplicate MAC address detected: aa:bb:cc:dd:ee:ff, conflict on VLAN 50', 'medium', 'log_20250812_130215.txt', NULL, 'aa:bb:cc:dd:ee:ff', NULL, NULL, 'open', 'mac_address_conflict', 0.82, 'one_class_svm', '{"cell_id": "Cell-67", "sector_id": 3, "frequency_band": "2100MHz", "technology": "5G-NR", "affected_users": 25}'),
('test004', '2025-08-12 09:03:00.000', 'protocol', 'L1 protocol violation: invalid PRACH preamble format 3', 'high', 'log_20250812_132145.txt', NULL, NULL, NULL, NULL, 'open', 'protocol_violation', 0.91, 'hybrid_ensemble', '{"cell_id": "Cell-12", "sector_id": 1, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 75}'),
('test005', '2025-08-12 09:04:00.000', 'fronthaul', 'RSRP degraded to -110 dBm on Cell-89, interference detected', 'critical', 'log_20250812_134520.txt', NULL, NULL, NULL, NULL, 'open', 'signal_quality_degradation', 0.93, 'isolation_forest', '{"cell_id": "Cell-89", "sector_id": 2, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 300}');