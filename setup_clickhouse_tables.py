#!/usr/bin/env python3
"""
ClickHouse Table Setup Script for L1 Anomaly Detection System
Creates all required tables with proper compatibility
"""

import sys
import time

try:
    import clickhouse_connect
    CLICKHOUSE_AVAILABLE = True
except ImportError:
    CLICKHOUSE_AVAILABLE = False
    print("Error: clickhouse-connect module not available")
    print("Install with: pip install clickhouse-connect")
    sys.exit(1)

def create_clickhouse_tables():
    """Create all ClickHouse tables for L1 analysis system"""
    
    print("Setting up ClickHouse tables for L1 Anomaly Detection...")
    
    try:
        # Connect to ClickHouse
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password='',
            database='l1_anomaly_detection',
            connect_timeout=10,
            send_receive_timeout=30
        )
        
        print("✓ Connected to ClickHouse")
        
        # Create database
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        print("✓ Database 'l1_anomaly_detection' created/verified")
        
        # Table creation statements
        tables = {
            'anomalies': """
                CREATE TABLE IF NOT EXISTS l1_anomaly_detection.anomalies (
                    anomaly_id String,
                    timestamp DateTime DEFAULT now(),
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
                ORDER BY (timestamp, file_path, anomaly_type)
            """,
            
            'analysis_sessions': """
                CREATE TABLE IF NOT EXISTS l1_anomaly_detection.analysis_sessions (
                    session_id String,
                    timestamp DateTime DEFAULT now(),
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
                ORDER BY (timestamp, file_path)
            """,
            
            'training_metrics': """
                CREATE TABLE IF NOT EXISTS l1_anomaly_detection.training_metrics (
                    training_id String,
                    timestamp DateTime DEFAULT now(),
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
                ORDER BY (timestamp, model_type)
            """,
            
            'comprehensive_anomalies': """
                CREATE TABLE IF NOT EXISTS l1_anomaly_detection.comprehensive_anomalies (
                    anomaly_id String,
                    timestamp DateTime DEFAULT now(),
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
                ORDER BY (timestamp, file_path, analysis_category, anomaly_type)
            """,
            
            'l1_analysis_sessions': """
                CREATE TABLE IF NOT EXISTS l1_anomaly_detection.l1_analysis_sessions (
                    session_id String,
                    timestamp DateTime DEFAULT now(),
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
                ORDER BY (timestamp, file_path)
            """,
            
            'ml_algorithm_details': """
                CREATE TABLE IF NOT EXISTS l1_anomaly_detection.ml_algorithm_details (
                    detection_id String,
                    session_id String,
                    timestamp DateTime DEFAULT now(),
                    file_path String,
                    algorithm_name String,
                    anomaly_detected UInt8,
                    confidence_score Float64,
                    algorithm_specific_data String,
                    processing_time_ms Float64
                ) ENGINE = MergeTree()
                ORDER BY (timestamp, session_id, algorithm_name)
            """,
            
            'feature_vectors': """
                CREATE TABLE IF NOT EXISTS l1_anomaly_detection.feature_vectors (
                    vector_id String,
                    timestamp DateTime DEFAULT now(),
                    file_path String,
                    line_number UInt32,
                    packet_number UInt32,
                    feature_vector String,
                    label UInt8,
                    data_source String
                ) ENGINE = MergeTree()
                ORDER BY (timestamp, file_path)
            """,
            
            'system_status': """
                CREATE TABLE IF NOT EXISTS l1_anomaly_detection.system_status (
                    status_id String,
                    timestamp DateTime DEFAULT now(),
                    component_name String,
                    status String,
                    uptime_seconds UInt32,
                    memory_usage_mb Float64,
                    cpu_usage_percent Float64,
                    disk_usage_mb Float64,
                    status_details String
                ) ENGINE = MergeTree()
                ORDER BY (timestamp, component_name)
            """
        }
        
        # Create each table
        created_tables = 0
        for table_name, create_sql in tables.items():
            try:
                client.command(create_sql)
                print(f"✓ Table '{table_name}' created/verified")
                created_tables += 1
            except Exception as e:
                print(f"✗ Failed to create table '{table_name}': {e}")
        
        print(f"\n✓ Successfully created/verified {created_tables}/{len(tables)} tables")
        
        # Test connection with a simple query
        try:
            result = client.query("SELECT count() FROM l1_anomaly_detection.comprehensive_anomalies")
            print(f"✓ Connection test successful - comprehensive_anomalies table has {result.result_rows[0][0]} rows")
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
        
        # Show all tables
        try:
            tables_result = client.query("SHOW TABLES FROM l1_anomaly_detection")
            print(f"\nTables in l1_anomaly_detection database:")
            for row in tables_result.result_rows:
                print(f"  - {row[0]}")
        except Exception as e:
            print(f"✗ Failed to list tables: {e}")
        
        client.close()
        print("\n✓ ClickHouse setup completed successfully!")
        return True
        
    except Exception as e:
        print(f"✗ ClickHouse setup failed: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure ClickHouse server is running")
        print("2. Check if port 8123 is accessible") 
        print("3. Verify ClickHouse configuration allows connections")
        print("4. Try: SELECT 1 in ClickHouse client to test basic connectivity")
        return False

def test_clickhouse_connection():
    """Test ClickHouse connection and basic functionality"""
    
    print("Testing ClickHouse connection...")
    
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password=''
        )
        
        # Test basic query
        result = client.query("SELECT 1 as test")
        if result.result_rows[0][0] == 1:
            print("✓ Basic connection test passed")
        
        # Test database access
        client.query("USE l1_anomaly_detection")
        print("✓ Database access confirmed")
        
        # Test table access
        tables = client.query("SHOW TABLES FROM l1_anomaly_detection")
        print(f"✓ Found {len(tables.result_rows)} tables")
        
        client.close()
        return True
        
    except Exception as e:
        print(f"✗ Connection test failed: {e}")
        return False

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ClickHouse Table Setup for L1 Analysis')
    parser.add_argument('--test', action='store_true', help='Test connection only')
    parser.add_argument('--create', action='store_true', help='Create tables')
    
    args = parser.parse_args()
    
    if not CLICKHOUSE_AVAILABLE:
        print("ClickHouse client not available. Install with:")
        print("pip install clickhouse-connect")
        return False
    
    if args.test:
        return test_clickhouse_connection()
    elif args.create or len(sys.argv) == 1:
        return create_clickhouse_tables()
    else:
        parser.print_help()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)