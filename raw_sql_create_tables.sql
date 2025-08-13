-- Raw SQL for ClickHouse 18.16.1 - Ultra Simple Version
-- Execute line by line in ClickHouse client

-- Create database
CREATE DATABASE IF NOT EXISTS l1_anomaly_detection;

-- Switch to database
USE l1_anomaly_detection;

-- Drop table if exists
DROP TABLE IF EXISTS anomalies;

-- Create table with simplest possible syntax for ClickHouse 18.x
CREATE TABLE anomalies (
    id String,
    timestamp String,
    type String,
    description String,
    severity String,
    source_file String,
    packet_number UInt32,
    mac_address String,
    ue_id String,
    details String,
    status String
) ENGINE = Log;

-- Verify table creation
SHOW TABLES;

-- Describe table structure
DESCRIBE TABLE anomalies;