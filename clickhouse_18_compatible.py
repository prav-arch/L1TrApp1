#!/usr/bin/env python3
"""
ClickHouse 18.x compatible data insertion script
Uses legacy SQL syntax compatible with ClickHouse 18.16.1
"""

import clickhouse_connect
import traceback

def connect_clickhouse():
    """Connect to ClickHouse with legacy settings"""
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password='',
            database='default'  # Start with default database
        )
        print("✓ Connected to ClickHouse 18.16.1")
        return client
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        traceback.print_exc()
        return None

def create_legacy_schema(client):
    """Create database and table using ClickHouse 18.x syntax"""
    try:
        # Create database using legacy syntax
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        print("✓ Database created")
        
        # Switch to the database
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password='',
            database='l1_anomaly_detection'
        )
        
        # Drop existing table to avoid conflicts
        try:
            client.command("DROP TABLE IF EXISTS anomalies")
            print("✓ Cleared existing table")
        except:
            pass
        
        # Create table with ClickHouse 18.x compatible syntax using Log engine
        create_sql = """CREATE TABLE anomalies (
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
) ENGINE = Log"""
        
        client.command(create_sql)
        print("✓ Table created with ClickHouse 18.x syntax")
        return client
        
    except Exception as e:
        print(f"✗ Schema creation failed: {e}")
        traceback.print_exc()
        return None

def insert_legacy_data(client):
    """Insert data using ClickHouse 18.x compatible method"""
    try:
        # Use INSERT VALUES syntax for ClickHouse 18.x
        insert_queries = [
            "INSERT INTO anomalies VALUES ('anom_001', '2025-08-12 14:23:15', 'fronthaul', 'DU-RU link timeout on interface eth0', 'critical', 'log_20250812_142315.pcap', 1523, 'AA:BB:CC:DD:EE:01', 'UE-345678', 'Cell-45 timeout issue', 'open')",
            "INSERT INTO anomalies VALUES ('anom_002', '2025-08-12 14:45:32', 'ue_event', 'UE attach failure - authentication error', 'high', 'log_20250812_144532.pcap', 2847, 'AA:BB:CC:DD:EE:02', 'UE-567890', 'Authentication failed', 'open')",
            "INSERT INTO anomalies VALUES ('anom_003', '2025-08-12 15:12:45', 'mac_conflict', 'Duplicate MAC address detected in network', 'medium', 'log_20250812_151245.pcap', 3456, 'AA:BB:CC:DD:EE:03', 'UE-234567', 'MAC address conflict', 'investigating')",
            "INSERT INTO anomalies VALUES ('anom_004', '2025-08-12 15:34:18', 'protocol_violation', 'Invalid RRC message sequence detected', 'high', 'log_20250812_153418.pcap', 4721, 'AA:BB:CC:DD:EE:04', 'UE-789012', 'RRC protocol error', 'open')",
            "INSERT INTO anomalies VALUES ('anom_005', '2025-08-12 16:01:22', 'signal_quality', 'Poor RSRP levels causing connection drops', 'medium', 'log_20250812_160122.pcap', 5638, 'AA:BB:CC:DD:EE:05', 'UE-456789', 'RSRP -115 dBm detected', 'resolved')",
            "INSERT INTO anomalies VALUES ('anom_006', '2025-08-12 16:28:55', 'fronthaul', 'High packet loss on DU-RU interface', 'critical', 'log_20250812_162855.pcap', 6789, 'AA:BB:CC:DD:EE:06', 'UE-123456', 'Packet loss 85 percent', 'open')",
            "INSERT INTO anomalies VALUES ('anom_007', '2025-08-12 16:45:12', 'ue_event', 'UE handover failure - target cell unavailable', 'high', 'log_20250812_164512.pcap', 7234, 'AA:BB:CC:DD:EE:07', 'UE-654321', 'Handover to Cell-45 failed', 'investigating')",
            "INSERT INTO anomalies VALUES ('anom_008', '2025-08-12 17:03:45', 'mac_conflict', 'MAC address spoofing attempt detected', 'critical', 'log_20250812_170345.pcap', 8567, 'AA:BB:CC:DD:EE:08', 'UE-987654', 'Spoofing detected', 'open')",
            "INSERT INTO anomalies VALUES ('anom_009', '2025-08-12 17:20:33', 'protocol_violation', 'Malformed PDCP header in data packet', 'medium', 'log_20250812_172033.pcap', 9123, 'AA:BB:CC:DD:EE:09', 'UE-321987', 'PDCP header malformed', 'resolved')",
            "INSERT INTO anomalies VALUES ('anom_010', '2025-08-12 17:42:18', 'signal_quality', 'Excessive interference on uplink channel', 'high', 'log_20250812_174218.pcap', 9876, 'AA:BB:CC:DD:EE:10', 'UE-147258', 'Uplink interference detected', 'open')"
        ]
        
        # Execute each insert statement
        for i, query in enumerate(insert_queries, 1):
            client.command(query)
            print(f"✓ Inserted anomaly {i}/10")
        
        print(f"✓ Successfully inserted all {len(insert_queries)} anomalies")
        return True
        
    except Exception as e:
        print(f"✗ Data insertion failed: {e}")
        print("Full error details:")
        traceback.print_exc()
        return False

def verify_legacy_data(client):
    """Verify data using ClickHouse 18.x queries"""
    try:
        # Simple count query
        result = client.query("SELECT count(*) FROM anomalies")
        count = result.first_row[0]
        print(f"✓ Total records: {count}")
        
        # Sample data query
        sample = client.query("SELECT id, type, severity, description FROM anomalies ORDER BY timestamp DESC LIMIT 3")
        print("✓ Sample records:")
        for row in sample.result_rows:
            print(f"  {row[0]} - {row[1]} ({row[2]}): {row[3]}")
            
        return True
        
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Main execution for ClickHouse 18.x"""
    print("=== ClickHouse 18.16.1 Compatible Data Insertion ===")
    print("Using legacy SQL syntax for older ClickHouse versions")
    print()
    
    # Connect
    client = connect_clickhouse()
    if not client:
        print("Cannot proceed without connection")
        return False
    
    # Create schema with legacy syntax
    client = create_legacy_schema(client)
    if not client:
        print("Schema creation failed")
        return False
    
    # Insert data using legacy method
    if not insert_legacy_data(client):
        print("Data insertion failed")
        return False
    
    # Verify
    if not verify_legacy_data(client):
        print("Verification failed")
        return False
    
    print("\n🎉 Success! Data inserted using ClickHouse 18.x compatible syntax.")
    print("Your web application should now display the anomalies.")
    print("\nNote: Using legacy MergeTree syntax for ClickHouse 18.16.1 compatibility")
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        print("\n💥 Script failed. Check ClickHouse server is running on localhost:8123")