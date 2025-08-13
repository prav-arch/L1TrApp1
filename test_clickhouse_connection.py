#!/usr/bin/env python3
"""
Simple test script to diagnose ClickHouse connection and SQL syntax issues
"""

import clickhouse_connect
import traceback

def test_basic_connection():
    """Test basic ClickHouse connection"""
    print("=== Testing ClickHouse Connection ===")
    
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password=''
        )
        
        # Test basic query
        result = client.query("SELECT 1")
        print(f"✓ Connection successful: {result.first_row[0]}")
        
        # Test database creation
        client.command("CREATE DATABASE IF NOT EXISTS test_db")
        print("✓ Database creation works")
        
        # Test simple table creation
        simple_table_sql = """
        CREATE TABLE IF NOT EXISTS test_db.simple_test (
            id String,
            name String,
            value UInt32
        ) ENGINE = MergeTree()
        ORDER BY id
        """
        client.command(simple_table_sql)
        print("✓ Simple table creation works")
        
        # Test insertion
        client.insert('test_db.simple_test', [['test1', 'name1', 100]], column_names=['id', 'name', 'value'])
        print("✓ Data insertion works")
        
        # Test query
        result = client.query("SELECT * FROM test_db.simple_test")
        print(f"✓ Data query works: {result.result_rows}")
        
        # Cleanup
        client.command("DROP TABLE IF EXISTS test_db.simple_test")
        client.command("DROP DATABASE IF EXISTS test_db")
        print("✓ Cleanup completed")
        
        return True
        
    except Exception as e:
        print(f"✗ Connection test failed: {e}")
        print("Full error details:")
        traceback.print_exc()
        return False

def test_l1_database():
    """Test L1 database creation with simpler syntax"""
    print("\n=== Testing L1 Database Creation ===")
    
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password=''
        )
        
        # Create database
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        print("✓ L1 database created")
        
        # Simple anomalies table without complex syntax
        simple_anomalies_sql = """
        CREATE TABLE IF NOT EXISTS l1_anomaly_detection.anomalies (
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
            status String
        ) ENGINE = MergeTree()
        ORDER BY timestamp
        """
        
        client.command(simple_anomalies_sql)
        print("✓ Anomalies table created with simplified schema")
        
        # Test data insertion
        test_data = [
            ['test_001', '2025-08-12 12:00:00', 'fronthaul', 'Test anomaly', 'high', 'test.pcap', 123, 'AA:BB:CC:DD:EE:FF', 'UE-123456', '{"test": true}', 'open']
        ]
        
        client.insert(
            'l1_anomaly_detection.anomalies',
            test_data,
            column_names=['id', 'timestamp', 'type', 'description', 'severity', 'source_file', 'packet_number', 'mac_address', 'ue_id', 'details', 'status']
        )
        print("✓ Test data inserted successfully")
        
        # Verify data
        result = client.query("SELECT count(*) FROM l1_anomaly_detection.anomalies")
        count = result.first_row[0]
        print(f"✓ Data verification: {count} records found")
        
        return True
        
    except Exception as e:
        print(f"✗ L1 database test failed: {e}")
        print("Full error details:")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("ClickHouse Diagnostic Tool")
    print("=" * 50)
    
    # Test 1: Basic connection
    basic_ok = test_basic_connection()
    
    # Test 2: L1 database
    if basic_ok:
        l1_ok = test_l1_database()
        
        if l1_ok:
            print("\n🎉 All tests passed! ClickHouse is working correctly.")
            print("You can now use the main data insertion scripts.")
        else:
            print("\n💥 L1 database test failed. Check the error details above.")
    else:
        print("\n💥 Basic connection failed. Please check:")
        print("1. ClickHouse server is running on localhost:8123")
        print("2. No firewall blocking the connection")
        print("3. ClickHouse service is properly configured")

if __name__ == "__main__":
    main()