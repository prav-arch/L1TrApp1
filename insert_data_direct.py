#!/usr/bin/env python3
"""
Direct executable script to insert dummy data into ClickHouse
Bypasses schema issues and inserts data directly with proper error handling
"""

import clickhouse_connect
import traceback
from datetime import datetime

def get_clickhouse_client():
    """Connect to ClickHouse"""
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password='',
            database='l1_anomaly_detection'
        )
        print("✓ Connected to ClickHouse successfully")
        return client
    except Exception as e:
        print(f"✗ Failed to connect to ClickHouse: {e}")
        print("Connection error stack trace:")
        traceback.print_exc()
        return None

def create_database_and_tables(client):
    """Create database and tables if they don't exist"""
    try:
        print("Creating database and tables...")
        
        # Create database
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        print("✓ Database created/verified")
        
        # Create anomalies table with proper syntax
        anomalies_sql = """
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
            status String,
            anomaly_type String,
            confidence_score Float64,
            detection_algorithm String,
            context_data String
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, type, severity)
        """
        client.command(anomalies_sql)
        print("✓ Anomalies table created/verified")
        
        # Create sessions table
        sessions_sql = """
        CREATE TABLE IF NOT EXISTS l1_anomaly_detection.analysis_sessions (
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
        ORDER BY (timestamp, session_id)
        """
        client.command(sessions_sql)
        print("✓ Analysis sessions table created/verified")
        
        return True
        
    except Exception as e:
        print(f"✗ Error creating tables: {e}")
        traceback.print_exc()
        return False

def insert_anomalies_data(client):
    """Insert anomalies data directly"""
    print("Inserting anomalies data...")
    
    try:
        # Prepare anomalies data
        anomalies_data = [
            ['anom_001', '2025-08-12 14:23:15', 'fronthaul', 'DU-RU link timeout on interface eth0', 'critical', 'log_20250812_142315.pcap', 1523, 'AA:BB:CC:DD:EE:01', 'UE-345678', '{"cell_id": "Cell-45", "technology": "5G-NR"}', 'open', 'fronthaul_du_ru_communication_failure', 0.95, 'isolation_forest', '{"cell_id": "Cell-45", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 150}'],
            ['anom_002', '2025-08-12 14:45:32', 'ue_event', 'UE attach failure - authentication error', 'high', 'log_20250812_144532.pcap', 2847, 'AA:BB:CC:DD:EE:02', 'UE-567890', '{"ue_id": "UE-567890", "imsi": "123456789012345"}', 'open', 'ue_attach_failure', 0.88, 'dbscan', '{"cell_id": "Cell-23", "sector_id": 1, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 1}'],
            ['anom_003', '2025-08-12 15:12:45', 'mac_conflict', 'Duplicate MAC address detected in network', 'medium', 'log_20250812_151245.pcap', 3456, 'AA:BB:CC:DD:EE:03', 'UE-234567', '{"mac_address": "AA:BB:CC:DD:EE:03", "count": 3}', 'investigating', 'mac_address_conflict', 0.92, 'one_class_svm', '{"cell_id": "Cell-12", "sector_id": 3, "frequency_band": "3500MHz", "technology": "5G-NR", "affected_users": 25}'],
            ['anom_004', '2025-08-12 15:34:18', 'protocol_violation', 'Invalid RRC message sequence detected', 'high', 'log_20250812_153418.pcap', 4721, 'AA:BB:CC:DD:EE:04', 'UE-789012', '{"message_type": "RRC_Connection_Request", "expected": "RRC_Setup"}', 'open', 'protocol_violation_rrc', 0.85, 'lof', '{"cell_id": "Cell-67", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 8}'],
            ['anom_005', '2025-08-12 16:01:22', 'signal_quality', 'Poor RSRP levels causing connection drops', 'medium', 'log_20250812_160122.pcap', 5638, 'AA:BB:CC:DD:EE:05', 'UE-456789', '{"rsrp": -115, "rsrq": -18, "sinr": -2}', 'resolved', 'signal_quality_degradation', 0.79, 'isolation_forest', '{"cell_id": "Cell-89", "sector_id": 1, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 45}'],
            ['anom_006', '2025-08-12 16:28:55', 'fronthaul', 'High packet loss on DU-RU interface', 'critical', 'log_20250812_162855.pcap', 6789, 'AA:BB:CC:DD:EE:06', 'UE-123456', '{"packet_loss_percentage": 85, "interface": "eth1"}', 'open', 'fronthaul_packet_loss', 0.98, 'dbscan', '{"cell_id": "Cell-34", "sector_id": 3, "frequency_band": "3500MHz", "technology": "5G-NR", "affected_users": 200}'],
            ['anom_007', '2025-08-12 16:45:12', 'ue_event', 'UE handover failure - target cell unavailable', 'high', 'log_20250812_164512.pcap', 7234, 'AA:BB:CC:DD:EE:07', 'UE-654321', '{"source_cell": "Cell-12", "target_cell": "Cell-45"}', 'investigating', 'ue_handover_failure', 0.91, 'one_class_svm', '{"cell_id": "Cell-12", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 12}'],
            ['anom_008', '2025-08-12 17:03:45', 'mac_conflict', 'MAC address spoofing attempt detected', 'critical', 'log_20250812_170345.pcap', 8567, 'AA:BB:CC:DD:EE:08', 'UE-987654', '{"suspicious_mac": "AA:BB:CC:DD:EE:08", "legitimate_ue": "UE-111222"}', 'open', 'mac_spoofing', 0.94, 'lof', '{"cell_id": "Cell-56", "sector_id": 1, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 75}'],
            ['anom_009', '2025-08-12 17:20:33', 'protocol_violation', 'Malformed PDCP header in data packet', 'medium', 'log_20250812_172033.pcap', 9123, 'AA:BB:CC:DD:EE:09', 'UE-321987', '{"header_field": "PDCP_SN", "expected_length": 12, "actual_length": 8}', 'resolved', 'protocol_violation_pdcp', 0.83, 'isolation_forest', '{"cell_id": "Cell-78", "sector_id": 3, "frequency_band": "3500MHz", "technology": "5G-NR", "affected_users": 5}'],
            ['anom_010', '2025-08-12 17:42:18', 'signal_quality', 'Excessive interference on uplink channel', 'high', 'log_20250812_174218.pcap', 9876, 'AA:BB:CC:DD:EE:10', 'UE-147258', '{"interference_level": -85, "channel": "PUSCH", "affected_prbs": 25}', 'open', 'uplink_interference', 0.87, 'dbscan', '{"cell_id": "Cell-90", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 30}']
        ]
        
        # Insert anomalies
        client.insert(
            'l1_anomaly_detection.anomalies',
            anomalies_data,
            column_names=[
                'id', 'timestamp', 'type', 'description', 'severity',
                'source_file', 'packet_number', 'mac_address', 'ue_id',
                'details', 'status', 'anomaly_type', 'confidence_score',
                'detection_algorithm', 'context_data'
            ]
        )
        
        print(f"✓ Successfully inserted {len(anomalies_data)} anomalies")
        return True
        
    except Exception as e:
        print(f"✗ Error inserting anomalies: {e}")
        print("Full stack trace:")
        traceback.print_exc()
        print(f"Data sample being inserted:")
        if anomalies_data:
            print(f"First row: {anomalies_data[0]}")
            print(f"Column count: {len(anomalies_data[0])}")
            print(f"Total rows: {len(anomalies_data)}")
        return False

def insert_sessions_data(client):
    """Insert analysis sessions data"""
    print("Inserting analysis sessions data...")
    
    try:
        sessions_data = [
            ['session_1001', '2025-08-12 14:00:00', 'analysis_20250812_140000.txt', 'pcap', 45623, 2845, 15, 3, 8, 4, 125.7, '{"analysis_type": "pcap", "algorithms_used": ["isolation_forest", "dbscan"], "total_features": 42}'],
            ['session_1002', '2025-08-12 15:30:00', 'analysis_20250812_153000.txt', 'text', 32156, 1967, 8, 1, 4, 3, 89.3, '{"analysis_type": "text", "algorithms_used": ["one_class_svm", "lof"], "total_features": 28}'],
            ['session_1003', '2025-08-12 16:45:00', 'analysis_20250812_164500.txt', 'hybrid', 58934, 3421, 22, 5, 12, 5, 178.9, '{"analysis_type": "hybrid", "algorithms_used": ["isolation_forest", "dbscan", "lof"], "total_features": 65}'],
            ['session_1004', '2025-08-12 17:15:00', 'analysis_20250812_171500.txt', 'pcap', 27845, 1532, 6, 1, 3, 2, 67.2, '{"analysis_type": "pcap", "algorithms_used": ["dbscan", "one_class_svm"], "total_features": 35}'],
            ['session_1005', '2025-08-12 17:45:00', 'analysis_20250812_174500.txt', 'text', 41267, 2789, 12, 2, 7, 3, 143.5, '{"analysis_type": "text", "algorithms_used": ["isolation_forest", "lof"], "total_features": 48}']
        ]
        
        client.insert(
            'l1_anomaly_detection.analysis_sessions',
            sessions_data,
            column_names=[
                'session_id', 'timestamp', 'file_path', 'file_format',
                'total_packets', 'total_lines', 'total_anomalies',
                'high_severity_anomalies', 'medium_severity_anomalies',
                'low_severity_anomalies', 'analysis_duration_seconds', 'session_details'
            ]
        )
        
        print(f"✓ Successfully inserted {len(sessions_data)} analysis sessions")
        return True
        
    except Exception as e:
        print(f"✗ Error inserting sessions: {e}")
        print("Full stack trace:")
        traceback.print_exc()
        return False

def verify_data(client):
    """Verify that data was inserted correctly"""
    print("\n=== Verification ===")
    
    try:
        # Count anomalies
        anomaly_count = client.query("SELECT count(*) FROM l1_anomaly_detection.anomalies").first_row[0]
        print(f"Total anomalies in database: {anomaly_count}")
        
        # Count sessions
        session_count = client.query("SELECT count(*) FROM l1_anomaly_detection.analysis_sessions").first_row[0]
        print(f"Total sessions in database: {session_count}")
        
        # Show sample anomalies
        print("\n=== Sample Anomalies ===")
        sample = client.query("SELECT timestamp, type, severity, description FROM l1_anomaly_detection.anomalies ORDER BY timestamp DESC LIMIT 3")
        for row in sample.result_rows:
            print(f"[{row[0]}] {row[1]} ({row[2]}): {row[3]}")
            
        return True
        
    except Exception as e:
        print(f"✗ Error during verification: {e}")
        traceback.print_exc()
        return False

def main():
    """Main execution function"""
    print("=== L1 Troubleshooting Direct Data Insertion ===")
    print("This script will create tables and insert dummy data directly into ClickHouse")
    print()
    
    # Connect to ClickHouse
    client = get_clickhouse_client()
    if not client:
        print("✗ Cannot proceed without ClickHouse connection")
        print("Please ensure ClickHouse is running on localhost:8123")
        return False
    
    # Create database and tables
    if not create_database_and_tables(client):
        print("✗ Failed to create database/tables")
        return False
    
    # Insert data
    anomalies_ok = insert_anomalies_data(client)
    sessions_ok = insert_sessions_data(client)
    
    if anomalies_ok and sessions_ok:
        print("\n✓ All data inserted successfully!")
        verify_data(client)
        print("\n=== Ready for Testing ===")
        print("✓ Frontend can now display anomalies")
        print("✓ 'Get Recommendations' feature ready for testing")
        print("✓ 10 realistic L1 network anomalies available")
        print("✓ 5 analysis sessions with metrics")
        return True
    else:
        print("\n✗ Some data insertion failed")
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n🎉 Data insertion completed successfully!")
    else:
        print("\n💥 Data insertion failed - check errors above")