#!/usr/bin/env python3
"""
Debug script to understand what's happening with ClickHouse table creation
Tests different engine types and table structures
"""

import clickhouse_connect
import traceback

def test_connection():
    """Test basic connection"""
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password=''
        )
        
        result = client.query("SELECT version()")
        version = result.first_row[0]
        print(f"✓ Connected to ClickHouse version: {version}")
        return client
        
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        return None

def test_log_engine(client):
    """Test with Log engine (simplest possible)"""
    print("\n=== Testing Log Engine ===")
    
    try:
        # Create database
        client.command("CREATE DATABASE IF NOT EXISTS test_log")
        
        # Create simple table with Log engine
        client.command("""
            CREATE TABLE test_log.simple_anomalies (
                id String,
                timestamp String,
                type String,
                description String,
                severity String
            ) ENGINE = Log
        """)
        
        print("✓ Log engine table created successfully")
        
        # Test insertion
        client.command("INSERT INTO test_log.simple_anomalies VALUES ('test1', '2025-08-12 12:00:00', 'test', 'Test anomaly', 'high')")
        print("✓ Data insertion successful")
        
        # Test query
        result = client.query("SELECT * FROM test_log.simple_anomalies")
        print(f"✓ Query successful: {result.result_rows}")
        
        # Cleanup
        client.command("DROP TABLE test_log.simple_anomalies")
        client.command("DROP DATABASE test_log")
        print("✓ Log engine test completed")
        
        return True
        
    except Exception as e:
        print(f"✗ Log engine failed: {e}")
        traceback.print_exc()
        return False

def test_memory_engine(client):
    """Test with Memory engine"""
    print("\n=== Testing Memory Engine ===")
    
    try:
        client.command("CREATE DATABASE IF NOT EXISTS test_memory")
        
        client.command("""
            CREATE TABLE test_memory.simple_anomalies (
                id String,
                timestamp String,
                type String,
                description String,
                severity String
            ) ENGINE = Memory
        """)
        
        print("✓ Memory engine table created successfully")
        
        client.command("INSERT INTO test_memory.simple_anomalies VALUES ('test1', '2025-08-12 12:00:00', 'test', 'Test anomaly', 'high')")
        print("✓ Data insertion successful")
        
        result = client.query("SELECT * FROM test_memory.simple_anomalies")
        print(f"✓ Query successful: {result.result_rows}")
        
        client.command("DROP TABLE test_memory.simple_anomalies")
        client.command("DROP DATABASE test_memory")
        print("✓ Memory engine test completed")
        
        return True
        
    except Exception as e:
        print(f"✗ Memory engine failed: {e}")
        traceback.print_exc()
        return False

def create_production_table(client):
    """Create the actual production table with working engine"""
    print("\n=== Creating Production Table ===")
    
    try:
        # Create main database
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        print("✓ Database created")
        
        # Drop existing table
        try:
            client.command("DROP TABLE IF EXISTS l1_anomaly_detection.anomalies")
            print("✓ Cleared existing table")
        except:
            pass
        
        # Create table with Log engine (most compatible)
        client.command("""
            CREATE TABLE l1_anomaly_detection.anomalies (
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
            ) ENGINE = Log
        """)
        print("✓ Production table created with Log engine")
        
        # Insert test data
        test_data = [
            "INSERT INTO l1_anomaly_detection.anomalies VALUES ('anom_001', '2025-08-12 14:23:15', 'fronthaul', 'DU-RU link timeout', 'critical', 'log_001.pcap', 1523, 'AA:BB:CC:DD:EE:01', 'UE-345678', 'Cell timeout', 'open')",
            "INSERT INTO l1_anomaly_detection.anomalies VALUES ('anom_002', '2025-08-12 14:45:32', 'ue_event', 'UE attach failure', 'high', 'log_002.pcap', 2847, 'AA:BB:CC:DD:EE:02', 'UE-567890', 'Auth failed', 'open')",
            "INSERT INTO l1_anomaly_detection.anomalies VALUES ('anom_003', '2025-08-12 15:12:45', 'mac_conflict', 'Duplicate MAC', 'medium', 'log_003.pcap', 3456, 'AA:BB:CC:DD:EE:03', 'UE-234567', 'MAC conflict', 'investigating')"
        ]
        
        for insert_sql in test_data:
            client.command(insert_sql)
        
        print(f"✓ Inserted {len(test_data)} test anomalies")
        
        # Verify
        result = client.query("SELECT count(*) FROM l1_anomaly_detection.anomalies")
        count = result.first_row[0]
        print(f"✓ Verification: {count} records in database")
        
        # Show sample
        sample = client.query("SELECT id, type, severity FROM l1_anomaly_detection.anomalies")
        print("✓ Sample data:")
        for row in sample.result_rows:
            print(f"  {row[0]} - {row[1]} ({row[2]})")
        
        return True
        
    except Exception as e:
        print(f"✗ Production table creation failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests and create working table"""
    print("=== ClickHouse 18.16.1 Compatibility Testing ===")
    
    client = test_connection()
    if not client:
        print("Cannot proceed without connection")
        return
    
    # Test different engines
    log_ok = test_log_engine(client)
    memory_ok = test_memory_engine(client)
    
    print(f"\n=== Test Results ===")
    print(f"Log engine: {'✓ Working' if log_ok else '✗ Failed'}")
    print(f"Memory engine: {'✓ Working' if memory_ok else '✗ Failed'}")
    
    # Create production table with working engine
    if log_ok:
        print("\nUsing Log engine for production table...")
        if create_production_table(client):
            print("\n🎉 Success! Production table created and populated.")
            print("Your web application should now connect successfully.")
        else:
            print("\n💥 Production table creation failed.")
    else:
        print("\n💥 No compatible engines found. Check ClickHouse installation.")

if __name__ == "__main__":
    main()