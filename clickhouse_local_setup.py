#!/usr/bin/env python3
"""
ClickHouse Local Database Setup Script for L1 Troubleshooting System
Creates the necessary database schema and tables for anomaly detection
"""

import clickhouse_connect
import sys
import json
from datetime import datetime

def create_clickhouse_schema():
    """Create ClickHouse database and tables for L1 anomaly detection"""
    
    try:
        # Connect to ClickHouse (adjust host/port as needed for your local setup)
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password='',
        )
        
        print("🔗 Connected to ClickHouse successfully")
        
        # Create database
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        print("✅ Database 'l1_anomaly_detection' created")
        
        # Use the database
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password='',
            database='l1_anomaly_detection'
        )
        
        # Create anomalies table with MergeTree engine for time-series optimization
        anomalies_schema = """
        CREATE TABLE IF NOT EXISTS anomalies (
            id UInt64,
            file_path String,
            file_type String,
            packet_number UInt32,
            anomaly_type String,
            severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
            description String,
            details String,
            ue_id String,
            du_mac String,
            ru_mac String,
            timestamp DateTime,
            status Enum8('open' = 1, 'investigating' = 2, 'resolved' = 3, 'active' = 4)
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, id)
        PARTITION BY toYYYYMM(timestamp)
        TTL timestamp + INTERVAL 1 YEAR
        """
        
        client.command(anomalies_schema)
        print("✅ Anomalies table created with MergeTree engine")
        
        # Create processed_files table
        files_schema = """
        CREATE TABLE IF NOT EXISTS processed_files (
            id UInt64,
            filename String,
            file_type String,
            file_size UInt64,
            upload_date DateTime,
            processing_status Enum8('pending' = 1, 'processing' = 2, 'completed' = 3, 'failed' = 4),
            anomalies_found UInt32 DEFAULT 0,
            processing_time UInt32,
            error_message String
        ) ENGINE = MergeTree()
        ORDER BY upload_date
        """
        
        client.command(files_schema)
        print("✅ Processed files table created")
        
        # Create sessions table
        sessions_schema = """
        CREATE TABLE IF NOT EXISTS sessions (
            id UInt64,
            session_id String,
            start_time DateTime,
            end_time DateTime,
            packets_analyzed UInt32 DEFAULT 0,
            anomalies_detected UInt32 DEFAULT 0,
            source_file String
        ) ENGINE = MergeTree()
        ORDER BY start_time
        """
        
        client.command(sessions_schema)
        print("✅ Sessions table created")
        
        # Create metrics table for dashboard
        metrics_schema = """
        CREATE TABLE IF NOT EXISTS metrics (
            id UInt64,
            metric_name String,
            metric_value Float64,
            timestamp DateTime,
            category String
        ) ENGINE = MergeTree()
        ORDER BY timestamp
        """
        
        client.command(metrics_schema)
        print("✅ Metrics table created")
        
        # Insert comprehensive sample data to test the system
        print("\n📊 Inserting comprehensive anomaly test data...")
        
        # Clear existing test data
        client.command("TRUNCATE TABLE anomalies")
        
        # Create comprehensive test anomalies
        sample_anomalies = [
            # Fronthaul DU-RU Communication Issues
            (
                1001, '/analysis/fronthaul_capture_001.pcap', 'pcap', 150, 'DU-RU Communication', 'high',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Missing RU Response Packets',
                '{"missing_responses": 5, "communication_ratio": 0.65, "latency_violations": 3}',
                '', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 17:45:30', 'active'
            ),
            (
                1002, '/analysis/timing_sync_002.pcap', 'pcap', 275, 'Timing Synchronization', 'critical',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Ultra-Low Latency Violation (>100μs)',
                '{"latency_measured": 150, "threshold": 100, "jitter": 25, "packet_loss": 0.5}',
                '', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 17:46:15', 'active'
            ),
            (
                1003, '/analysis/mac_mismatch_003.pcap', 'pcap', 89, 'MAC Address Anomaly', 'medium',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Unexpected MAC Address Pattern',
                '{"expected_du_mac": "00:11:22:33:44:67", "found_mac": "00:11:22:33:44:68", "frequency": 12}',
                '', '00:11:22:33:44:68', '6c:ad:ad:00:03:2a',
                '2025-08-05 17:47:02', 'active'
            ),
            
            # UE Event Pattern Anomalies
            (
                2001, '/logs/ue_attach_events_001.txt', 'log', 45, 'UE Event Pattern', 'critical',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - UE Attach Failure Pattern',
                '{"failed_attaches": 8, "success_rate": 0.12, "context_failures": 5, "timeout_events": 3}',
                '460110123456789', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 17:48:20', 'active'
            ),
            (
                2002, '/logs/mobility_events_002.txt', 'log', 127, 'UE Mobility Issue', 'high',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Handover Failure Sequence',
                '{"handover_attempts": 4, "successful_handovers": 1, "signal_drops": 3}',
                '460110987654321', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 17:49:45', 'active'
            ),
            (
                2003, '/logs/context_setup_003.txt', 'log', 203, 'Context Setup Failure', 'medium',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Context Setup Timeout',
                '{"setup_attempts": 6, "timeout_count": 4, "avg_setup_time": 250}',
                '460111234567890', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 17:50:12', 'investigating'
            ),
            
            # Protocol Violation Anomalies
            (
                3001, '/captures/protocol_errors_001.pcap', 'pcap', 412, 'Protocol Violation', 'high',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Invalid Frame Structure',
                '{"malformed_frames": 7, "crc_errors": 2, "sequence_violations": 5}',
                '', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 17:51:33', 'active'
            ),
            (
                3002, '/captures/bandwidth_violation_002.pcap', 'pcap', 568, 'Bandwidth Violation', 'critical',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Bandwidth Threshold Exceeded',
                '{"measured_bandwidth": 12.5, "threshold": 10.0, "peak_usage": 15.2}',
                '', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 17:52:18', 'active'
            ),
            
            # Historical Resolved Issues
            (
                4001, '/archive/resolved_timing_001.pcap', 'pcap', 95, 'Timing Synchronization', 'medium',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Jitter Threshold Exceeded (Resolved)',
                '{"jitter_measured": 75, "threshold": 50, "correction_applied": true}',
                '', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 16:30:00', 'resolved'
            ),
            (
                4002, '/archive/resolved_ue_002.txt', 'log', 234, 'UE Event Pattern', 'low',
                '*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - Minor Attachment Delay (Resolved)',
                '{"avg_attach_time": 1.2, "threshold": 1.0, "improvement": 0.3}',
                '460112345678901', '00:11:22:33:44:67', '6c:ad:ad:00:03:2a',
                '2025-08-05 16:15:00', 'resolved'
            )
        ]
        
        client.insert('anomalies', sample_anomalies, column_names=[
            'id', 'file_path', 'file_type', 'packet_number', 'anomaly_type',
            'severity', 'description', 'details', 'ue_id', 'du_mac', 
            'ru_mac', 'timestamp', 'status'
        ])
        
        print("✅ Comprehensive anomaly test data inserted (10 records)")
        
        # Insert sample processed files
        print("📂 Inserting processed files data...")
        
        sample_files = [
            (1, 'fronthaul_capture_001.pcap', 'pcap', 2048576, '2025-08-05 17:45:00', 'completed', 3, 1250, ''),
            (2, 'ue_attach_events_001.txt', 'log', 524288, '2025-08-05 17:48:00', 'completed', 2, 890, ''),
            (3, 'protocol_errors_001.pcap', 'pcap', 1572864, '2025-08-05 17:51:00', 'completed', 2, 1100, ''),
            (4, 'current_analysis.pcap', 'pcap', 3145728, '2025-08-05 17:55:00', 'processing', 0, 0, ''),
            (5, 'failed_capture.pcap', 'pcap', 1048576, '2025-08-05 17:30:00', 'failed', 0, 500, 'File corruption detected')
        ]
        
        client.insert('processed_files', sample_files, column_names=[
            'id', 'filename', 'file_type', 'file_size', 'upload_date', 
            'processing_status', 'anomalies_found', 'processing_time', 'error_message'
        ])
        
        print("✅ Processed files test data inserted (5 records)")
        
        # Insert analysis sessions
        print("📊 Inserting analysis sessions...")
        
        sample_sessions = [
            (1, 'session_20250805_001', '2025-08-05 17:45:00', '2025-08-05 17:47:30', 1250, 3),
            (2, 'session_20250805_002', '2025-08-05 17:48:00', '2025-08-05 17:49:15', 890, 2),
            (3, 'session_20250805_003', '2025-08-05 17:51:00', '2025-08-05 17:52:45', 1100, 2),
            (4, 'session_20250805_004', '2025-08-05 17:55:00', None, 0, 0)
        ]
        
        client.insert('sessions', sample_sessions, column_names=[
            'id', 'session_id', 'start_time', 'end_time', 'packets_analyzed', 'anomalies_detected'
        ])
        
        print("✅ Analysis sessions test data inserted (4 records)")
        
        # Verification queries
        print("\n🔍 Verifying database content...")
        
        # Count anomalies
        result = client.query("SELECT count() FROM anomalies")
        anomaly_count = result.result_rows[0][0] if result.result_rows else 0
        print(f"✅ Total anomalies: {anomaly_count}")
        
        # Count by severity
        result = client.query("SELECT severity, count() FROM anomalies GROUP BY severity ORDER BY severity")
        print("📊 Anomalies by severity:")
        for row in result.result_rows:
            print(f"   - {row[0]}: {row[1]} records")
        
        # Count by type
        result = client.query("SELECT anomaly_type, count() FROM anomalies GROUP BY anomaly_type ORDER BY count() DESC")
        print("📋 Anomalies by type:")
        for row in result.result_rows:
            print(f"   - {row[0]}: {row[1]} records")
        
        # Sample recent anomalies
        result = client.query("SELECT id, packet_number, anomaly_type, severity FROM anomalies ORDER BY timestamp DESC LIMIT 3")
        print("🕒 Recent anomalies (sample):")
        for row in result.result_rows:
            print(f"   - ID {row[0]}: Packet #{row[1]} - {row[2]} ({row[3]})")
        
        # Verify files and sessions
        file_result = client.query("SELECT count() FROM processed_files")
        session_result = client.query("SELECT count() FROM sessions")
        
        file_count = file_result.result_rows[0][0] if file_result.result_rows else 0
        session_count = session_result.result_rows[0][0] if session_result.result_rows else 0
        
        print(f"📂 Processed files: {file_count}")
        print(f"📊 Analysis sessions: {session_count}")
        
        print("\n🎉 ClickHouse setup completed successfully!")
        print("🔧 Database: l1_anomaly_detection")
        print("📋 Tables: anomalies, processed_files, sessions, metrics")
        print("💾 Engine: MergeTree with time-series optimization")
        print("\n🔗 Connection details:")
        print("   Host: localhost:8123")
        print("   Database: l1_anomaly_detection")
        print("   Username: default")
        print("\n🚀 Your L1 Troubleshooting system is ready!")
        print("💡 The frontend should now display all test anomalies with packet numbers")
        print("🔍 Each anomaly includes 'Get Recommendations' functionality")
        
        return True
        
    except Exception as e:
        print(f"❌ ClickHouse setup failed: {e}")
        print("\n🔧 Troubleshooting:")
        print("1. Ensure ClickHouse server is running: sudo systemctl status clickhouse-server")
        print("2. Check connection: curl http://localhost:8123/ping")
        print("3. Verify credentials and port (default: 8123)")
        return False

if __name__ == "__main__":
    print("🗄️  ClickHouse L1 Anomaly Detection Setup")
    print("=" * 50)
    
    if create_clickhouse_schema():
        sys.exit(0)
    else:
        sys.exit(1)