#!/usr/bin/env python3
"""
ClickHouse 18 Table Setup Script for L1 Anomaly Detection
Automatically creates all required tables with proper schema
"""

import clickhouse_connect
import sys

def setup_clickhouse_tables():
    """Create all ClickHouse 18 compatible tables for L1 anomaly detection"""
    
    try:
        # Connect to ClickHouse
        print("Connecting to ClickHouse at 127.0.0.1:8123...")
        client = clickhouse_connect.get_client(
            host='127.0.0.1',
            port=8123,
            username='default',
            password='',
            database='default'  # Connect to default first to create database
        )
        
        # Create database
        print("Creating l1_anomaly_detection database...")
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        
        # Reconnect to the new database
        client = clickhouse_connect.get_client(
            host='127.0.0.1',
            port=8123,
            username='default',
            password='',
            database='l1_anomaly_detection'
        )
        
        print("Creating tables in l1_anomaly_detection database...")
        
        # 1. Main anomalies table with all ML algorithm details
        anomalies_table = """
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
        PARTITION BY toYYYYMM(timestamp)
        """
        
        # 2. Analysis sessions tracking table
        sessions_table = """
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
        ORDER BY start_time
        """
        
        # 3. Processed files log table
        processed_files_table = """
        CREATE TABLE IF NOT EXISTS processed_files (
            filename String,
            processing_time DateTime,
            total_samples UInt32,
            anomalies_detected UInt32,
            session_id String,
            processing_status String
        ) ENGINE = MergeTree
        ORDER BY processing_time
        """
        
        # 4. ML model performance tracking table
        ml_performance_table = """
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
        ORDER BY (timestamp, model_name)
        """
        
        # Execute table creation commands
        print("Creating anomalies table...")
        client.command(anomalies_table)
        
        print("Creating sessions table...")
        client.command(sessions_table)
        
        print("Creating processed_files table...")
        client.command(processed_files_table)
        
        print("Creating ml_model_performance table...")
        client.command(ml_performance_table)
        
        # Verify tables were created
        print("\nVerifying tables...")
        tables = client.query("SHOW TABLES FROM l1_anomaly_detection")
        print("Created tables:")
        for table in tables.result_rows:
            print(f"  - {table[0]}")
        
        # Show table schemas
        print("\nTable schemas:")
        for table_name in ['anomalies', 'sessions', 'processed_files', 'ml_model_performance']:
            print(f"\n{table_name} schema:")
            schema = client.query(f"DESCRIBE l1_anomaly_detection.{table_name}")
            for row in schema.result_rows:
                print(f"  {row[0]:<25} {row[1]}")
        
        print("\n✅ All tables created successfully!")
        print("Database: l1_anomaly_detection")
        print("ClickHouse version: 18.x compatible")
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        sys.exit(1)

if __name__ == "__main__":
    setup_clickhouse_tables()