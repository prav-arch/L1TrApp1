#!/usr/bin/env python3
"""
Simplified ClickHouse data insertion script that avoids syntax issues
Uses the most basic ClickHouse SQL syntax to prevent comment_expression errors
"""

import clickhouse_connect
import traceback

def connect_clickhouse():
    """Simple connection to ClickHouse"""
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password=''
        )
        print("✓ Connected to ClickHouse")
        return client
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        traceback.print_exc()
        return None

def create_simple_schema(client):
    """Create database and table with minimal syntax"""
    try:
        # Create database
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        print("✓ Database created")
        
        # Drop existing table to avoid conflicts
        try:
            client.command("DROP TABLE IF EXISTS l1_anomaly_detection.anomalies")
            print("✓ Cleared existing table")
        except:
            pass
        
        # Create table with absolute minimal syntax
        create_sql = """CREATE TABLE l1_anomaly_detection.anomalies (
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
) ENGINE = MergeTree() ORDER BY id"""
        
        client.command(create_sql)
        print("✓ Table created with minimal syntax")
        return True
        
    except Exception as e:
        print(f"✗ Schema creation failed: {e}")
        traceback.print_exc()
        return False

def insert_basic_data(client):
    """Insert data using simplest possible approach"""
    try:
        # Prepare simple data
        data = [
            ['anom_001', '2025-08-12 14:23:15', 'fronthaul', 'DU-RU link timeout', 'critical', 'log_001.pcap', 1523, 'AA:BB:CC:DD:EE:01', 'UE-345678', 'Cell-45 timeout', 'open'],
            ['anom_002', '2025-08-12 14:45:32', 'ue_event', 'UE attach failure', 'high', 'log_002.pcap', 2847, 'AA:BB:CC:DD:EE:02', 'UE-567890', 'Auth error', 'open'],
            ['anom_003', '2025-08-12 15:12:45', 'mac_conflict', 'Duplicate MAC detected', 'medium', 'log_003.pcap', 3456, 'AA:BB:CC:DD:EE:03', 'UE-234567', 'MAC conflict', 'investigating'],
            ['anom_004', '2025-08-12 15:34:18', 'protocol_violation', 'Invalid RRC sequence', 'high', 'log_004.pcap', 4721, 'AA:BB:CC:DD:EE:04', 'UE-789012', 'RRC error', 'open'],
            ['anom_005', '2025-08-12 16:01:22', 'signal_quality', 'Poor RSRP levels', 'medium', 'log_005.pcap', 5638, 'AA:BB:CC:DD:EE:05', 'UE-456789', 'RSRP -115 dBm', 'resolved']
        ]
        
        # Insert using basic column specification
        client.insert(
            'l1_anomaly_detection.anomalies',
            data,
            column_names=['id', 'timestamp', 'type', 'description', 'severity', 'source_file', 'packet_number', 'mac_address', 'ue_id', 'details', 'status']
        )
        
        print(f"✓ Inserted {len(data)} anomalies successfully")
        return True
        
    except Exception as e:
        print(f"✗ Data insertion failed: {e}")
        print("Full error details:")
        traceback.print_exc()
        return False

def verify_data(client):
    """Verify the inserted data"""
    try:
        # Simple count query
        result = client.query("SELECT count(*) FROM l1_anomaly_detection.anomalies")
        count = result.first_row[0]
        print(f"✓ Total records: {count}")
        
        # Sample data query
        sample = client.query("SELECT id, type, severity FROM l1_anomaly_detection.anomalies LIMIT 3")
        print("✓ Sample records:")
        for row in sample.result_rows:
            print(f"  {row[0]} - {row[1]} ({row[2]})")
            
        return True
        
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Main execution"""
    print("=== Simple ClickHouse Data Insertion ===")
    print("Using minimal SQL syntax to avoid comment_expression errors")
    print()
    
    # Connect
    client = connect_clickhouse()
    if not client:
        print("Cannot proceed without connection")
        return False
    
    # Create schema
    if not create_simple_schema(client):
        print("Schema creation failed")
        return False
    
    # Insert data
    if not insert_basic_data(client):
        print("Data insertion failed")
        return False
    
    # Verify
    if not verify_data(client):
        print("Verification failed")
        return False
    
    print("\n🎉 Success! Data inserted with minimal syntax.")
    print("Your web application should now display the anomalies.")
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        print("\n💥 Script failed. Try running test_clickhouse_connection.py first.")