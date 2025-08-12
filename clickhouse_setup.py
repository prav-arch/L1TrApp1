#!/usr/bin/env python3
"""
ClickHouse Database Setup for L1 Anomaly Detection System
Creates tables optimized for time-series anomaly data
"""

import clickhouse_connect
import os

# ClickHouse connection configuration
CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST', 'localhost')
CLICKHOUSE_PORT = int(os.getenv('CLICKHOUSE_PORT', '8123'))
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER', 'default')
CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD', '')
CLICKHOUSE_DATABASE = os.getenv('CLICKHOUSE_DATABASE', 'l1_anomaly_detection')

def create_clickhouse_tables():
    """Create ClickHouse tables for L1 anomaly detection"""
    
    # Connect to ClickHouse
    client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD
    )
    
    print(f"🔗 Connecting to ClickHouse at {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}")
    
    # Create database if it doesn't exist
    client.command(f'CREATE DATABASE IF NOT EXISTS {CLICKHOUSE_DATABASE}')
    print(f"📊 Database '{CLICKHOUSE_DATABASE}' ready")
    
    # Use the database
    client.command(f'USE {CLICKHOUSE_DATABASE}')
    
    # Drop existing tables if they exist
    print("🧹 Cleaning up existing tables...")
    client.command('DROP TABLE IF EXISTS anomalies')
    client.command('DROP TABLE IF EXISTS processed_files')
    client.command('DROP TABLE IF EXISTS sessions')
    client.command('DROP TABLE IF EXISTS metrics')
    
    # Create anomalies table (optimized for time-series data)
    anomalies_sql = """
    CREATE TABLE anomalies (
        id UInt64,
        file_path String,
        file_type Enum8('PCAP' = 1, 'TEXT' = 2),
        line_number UInt32,
        anomaly_type String,
        severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
        description String,
        details String,
        ue_id String,
        du_mac String DEFAULT '00:11:22:33:44:67',
        ru_mac String DEFAULT '6c:ad:ad:00:03:2a',
        timestamp DateTime DEFAULT now(),
        status Enum8('active' = 1, 'resolved' = 2, 'ignored' = 3) DEFAULT 'active'
    ) ENGINE = MergeTree()
    ORDER BY (timestamp, file_type, severity)
    SETTINGS index_granularity = 8192
    """
    
    client.command(anomalies_sql)
    print("✅ Created 'anomalies' table")
    
    # Create processed_files table
    processed_files_sql = """
    CREATE TABLE processed_files (
        id UInt64,
        file_path String,
        file_name String,
        file_type Enum8('PCAP' = 1, 'TEXT' = 2),
        file_size UInt64,
        processing_status Enum8('pending' = 1, 'processing' = 2, 'completed' = 3, 'failed' = 4) DEFAULT 'pending',
        events_extracted UInt32 DEFAULT 0,
        anomalies_found UInt32 DEFAULT 0,
        processed_at DateTime DEFAULT now(),
        error_message String
    ) ENGINE = MergeTree()
    ORDER BY (processed_at, processing_status)
    SETTINGS index_granularity = 8192
    """
    
    client.command(processed_files_sql)
    print("✅ Created 'processed_files' table")
    
    # Create sessions table
    sessions_sql = """
    CREATE TABLE sessions (
        id UInt64,
        session_name String,
        folder_path String,
        total_files UInt32 DEFAULT 0,
        pcap_files UInt32 DEFAULT 0,
        text_files UInt32 DEFAULT 0,
        total_anomalies UInt32 DEFAULT 0,
        start_time DateTime DEFAULT now(),
        end_time DateTime,
        duration_seconds UInt32,
        status Enum8('running' = 1, 'completed' = 2, 'failed' = 3) DEFAULT 'running'
    ) ENGINE = MergeTree()
    ORDER BY (start_time, status)
    SETTINGS index_granularity = 8192
    """
    
    client.command(sessions_sql)
    print("✅ Created 'sessions' table")
    
    # Create metrics table
    metrics_sql = """
    CREATE TABLE metrics (
        id UInt64,
        session_id UInt64,
        metric_name String,
        metric_value Float64,
        metric_text String,
        created_at DateTime DEFAULT now()
    ) ENGINE = MergeTree()
    ORDER BY (created_at, session_id, metric_name)
    SETTINGS index_granularity = 8192
    """
    
    client.command(metrics_sql)
    print("✅ Created 'metrics' table")
    
    # Create materialized views for common queries
    anomaly_summary_view = """
    CREATE MATERIALIZED VIEW IF NOT EXISTS anomaly_summary_mv
    ENGINE = SummingMergeTree()
    ORDER BY (toDate(timestamp), file_type, severity)
    AS SELECT
        toDate(timestamp) as date,
        file_type,
        severity,
        count() as anomaly_count
    FROM anomalies
    GROUP BY date, file_type, severity
    """
    
    client.command(anomaly_summary_view)
    print("✅ Created 'anomaly_summary_mv' materialized view")
    
    # Insert sample data for testing
    print("📝 Inserting sample data...")
    
    # Sample anomalies
    sample_anomalies = [
        [1, '/test/sample.pcap', 'PCAP', 100, 'DU-RU Communication', 'high', 
         'Missing response packets detected', '{"missing_responses": 5}', 
         '', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a', '2025-08-03 17:30:00', 'active'],
        [2, '/test/ue_events.txt', 'TEXT', 50, 'UE Event Pattern', 'critical',
         'Failed attach procedures', '{"failed_attaches": 3}', '460110123456789',
         '00:11:22:33:44:67', '6c:ad:ad:00:03:2a', '2025-08-03 17:31:00', 'active']
    ]
    
    client.insert('anomalies', sample_anomalies, column_names=[
        'id', 'file_path', 'file_type', 'line_number', 'anomaly_type', 'severity',
        'description', 'details', 'ue_id', 'du_mac', 'ru_mac', 'timestamp', 'status'
    ])
    
    # Sample processed files
    sample_files = [
        [1, '/test/sample.pcap', 'sample.pcap', 'PCAP', 1024000, 'completed', 150, 1, '2025-08-03 17:30:00', ''],
        [2, '/test/ue_events.txt', 'ue_events.txt', 'TEXT', 50000, 'completed', 25, 1, '2025-08-03 17:31:00', '']
    ]
    
    client.insert('processed_files', sample_files, column_names=[
        'id', 'file_path', 'file_name', 'file_type', 'file_size', 'processing_status',
        'events_extracted', 'anomalies_found', 'processed_at', 'error_message'
    ])
    
    # Sample session
    sample_sessions = [
        [1, 'Test Analysis Session', '/test', 2, 1, 1, 2, '2025-08-03 17:30:00', '2025-08-03 17:32:00', 120, 'completed']
    ]
    
    client.insert('sessions', sample_sessions, column_names=[
        'id', 'session_name', 'folder_path', 'total_files', 'pcap_files', 'text_files',
        'total_anomalies', 'start_time', 'end_time', 'duration_seconds', 'status'
    ])
    
    print("✅ Sample data inserted")
    
    # Verify tables and data
    print("\n📊 Verifying ClickHouse setup:")
    
    tables = client.query("SHOW TABLES").result_rows
    print(f"   Tables created: {len(tables)}")
    for table in tables:
        table_name = table[0]
        count = client.query(f"SELECT count() FROM {table_name}").result_rows[0][0]
        print(f"   • {table_name}: {count} rows")
    
    client.close()
    print("\n🎯 ClickHouse database setup completed successfully!")
    print(f"   Database: {CLICKHOUSE_DATABASE}")
    print(f"   Host: {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}")
    print("   System ready for L1 anomaly detection")

if __name__ == "__main__":
    create_clickhouse_tables()