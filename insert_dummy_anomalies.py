#!/usr/bin/env python3
"""
Insert realistic dummy anomaly data into ClickHouse for testing the L1 troubleshooting frontend
"""

import clickhouse_connect
import random
import json
from datetime import datetime, timedelta

def get_clickhouse_client():
    """Initialize ClickHouse client"""
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password='',
            database='l1_anomaly_detection'
        )
        return client
    except Exception as e:
        print(f"Failed to connect to ClickHouse: {e}")
        return None

def generate_realistic_anomalies():
    """Generate realistic L1 network anomaly data"""
    anomaly_types = [
        'fronthaul_du_ru_communication_failure',
        'ue_attach_failure',
        'handover_failure', 
        'mac_address_conflict',
        'protocol_violation',
        'signal_quality_degradation',
        'timing_synchronization_error',
        'resource_allocation_failure',
        'interference_detection',
        'pci_conflict'
    ]
    
    severities = ['critical', 'high', 'medium', 'low']
    
    # Base time - start from 24 hours ago
    base_time = datetime.now() - timedelta(hours=24)
    
    anomalies = []
    
    for i in range(50):  # Generate 50 realistic anomalies
        timestamp = base_time + timedelta(minutes=random.randint(0, 1440))  # Spread over 24 hours
        anomaly_type = random.choice(anomaly_types)
        severity = random.choice(severities)
        
        # Generate realistic descriptions based on anomaly type
        descriptions = {
            'fronthaul_du_ru_communication_failure': [
                f"DU-RU link timeout on interface eth0, packet loss: {random.randint(15, 85)}%",
                f"Fronthaul synchronization lost between DU-{random.randint(1,10)} and RU-{random.randint(1,20)}",
                f"CPRI link failure detected, error rate: {random.uniform(0.01, 0.15):.3f}"
            ],
            'ue_attach_failure': [
                f"UE {random.randint(100000, 999999)} attach rejected, cause: authentication failure",
                f"RRC connection establishment failed for IMSI {random.randint(100000000000000, 999999999999999)}",
                f"UE context setup failure, bearer establishment timeout"
            ],
            'handover_failure': [
                f"Inter-cell handover failed from Cell-{random.randint(1,50)} to Cell-{random.randint(51,100)}",
                f"X2 handover preparation timeout, target cell overloaded",
                f"Handover command execution failed, UE lost connection"
            ],
            'mac_address_conflict': [
                f"Duplicate MAC address detected: {generate_mac_address()}, conflict on VLAN {random.randint(10,100)}",
                f"MAC address table overflow, learning disabled on port {random.randint(1,48)}",
                f"Invalid MAC address format in frame header"
            ],
            'protocol_violation': [
                f"L1 protocol violation: invalid PRACH preamble format {random.randint(0,4)}",
                f"RLC protocol error: sequence number out of range",
                f"PDCP integrity check failed, potential security breach"
            ],
            'signal_quality_degradation': [
                f"RSRP degraded to {random.randint(-120, -90)} dBm on Cell-{random.randint(1,100)}",
                f"SINR below threshold: {random.uniform(0.5, 3.0):.1f} dB, interference detected",
                f"Reference signal quality alarm: RSRQ {random.randint(-20, -10)} dB"
            ],
            'timing_synchronization_error': [
                f"GPS synchronization lost, timing drift: {random.randint(10, 500)} microseconds",
                f"PTP sync failure between master and slave clocks",
                f"Frame timing misalignment detected, offset: {random.randint(1, 50)} samples"
            ],
            'resource_allocation_failure': [
                f"PRB allocation failed, utilization: {random.randint(85, 100)}%",
                f"Insufficient PUCCH resources for scheduling request",
                f"DL resource block exhaustion in Cell-{random.randint(1,50)}"
            ],
            'interference_detection': [
                f"Adjacent channel interference detected at {random.randint(1800, 2600)} MHz",
                f"Co-channel interference from external source, power: {random.randint(-80, -40)} dBm",
                f"Intermodulation distortion identified in UL band"
            ],
            'pci_conflict': [
                f"PCI collision detected: Cell-{random.randint(1,100)} and Cell-{random.randint(101,200)} using PCI {random.randint(0,503)}",
                f"PCI planning violation: insufficient separation distance",
                f"Automatic neighbor relation conflict with PCI {random.randint(0,503)}"
            ]
        }
        
        description = random.choice(descriptions[anomaly_type])
        
        # Generate additional context based on anomaly type
        context_data = {
            'cell_id': f"Cell-{random.randint(1,100)}",
            'sector_id': random.randint(1, 3),
            'frequency_band': random.choice(['1800MHz', '2100MHz', '2600MHz']),
            'technology': '5G-NR',
            'detected_by': 'L1_Monitor',
            'impact_level': severity,
            'affected_users': random.randint(1, 500) if severity in ['critical', 'high'] else random.randint(1, 50)
        }
        
        anomaly = {
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'anomaly_id': f"ANM-{random.randint(100000, 999999)}",
            'anomaly_type': anomaly_type,
            'severity': severity,
            'description': description,
            'source_file': f"log_{timestamp.strftime('%Y%m%d_%H%M%S')}.txt",
            'confidence_score': round(random.uniform(0.7, 0.99), 3),
            'detection_algorithm': random.choice(['isolation_forest', 'dbscan', 'one_class_svm', 'hybrid_ensemble']),
            'status': random.choice(['new', 'investigating', 'resolved']),
            'context_data': json.dumps(context_data),
            'resolution_time': random.randint(5, 120) if random.choice([True, False]) else None
        }
        
        anomalies.append(anomaly)
    
    return anomalies

def generate_mac_address():
    """Generate a realistic MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def insert_anomalies(client, anomalies):
    """Insert anomalies into ClickHouse"""
    print(f"Inserting {len(anomalies)} dummy anomalies into ClickHouse...")
    
    try:
        # Prepare data for batch insert - match the actual table schema
        data = []
        for anomaly in anomalies:
            row = [
                anomaly['anomaly_id'],
                anomaly['timestamp'],
                anomaly['source_file'],  # file_path
                'pcap',                  # file_format
                anomaly['anomaly_type'],
                anomaly['severity'],
                anomaly['confidence_score'],
                random.randint(1, 10000),  # packet_number
                random.randint(1, 1000),   # line_number
                anomaly['description'],
                1,  # ml_detected (1 = true)
                0,  # rule_based_detected (0 = false)
                anomaly['context_data']  # details
            ]
            data.append(row)
        
        # Insert into anomalies table
        client.insert(
            'anomalies',
            data,
            column_names=[
                'anomaly_id', 'timestamp', 'file_path', 'file_format',
                'anomaly_type', 'severity', 'confidence_score', 
                'packet_number', 'line_number', 'description',
                'ml_detected', 'rule_based_detected', 'details'
            ]
        )
        
        print(f"Successfully inserted {len(anomalies)} anomalies")
        
        # Verify insertion
        count = client.query("SELECT count(*) FROM anomalies").first_row[0]
        print(f"Total anomalies in database: {count}")
        
    except Exception as e:
        print(f"Error inserting anomalies: {e}")

def insert_session_data(client):
    """Insert realistic session data"""
    print("Inserting dummy session data...")
    
    sessions = []
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(10):
        timestamp = base_time + timedelta(hours=random.randint(0, 24))
        session = [
            f"session_{random.randint(1000, 9999)}",
            timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            f"analysis_{timestamp.strftime('%Y%m%d_%H%M%S')}.txt",  # file_path
            'pcap',  # file_format
            random.randint(1000, 50000),    # total_packets
            random.randint(500, 5000),      # total_lines
            random.randint(1, 20),          # total_anomalies
            random.randint(0, 5),           # high_severity_anomalies
            random.randint(2, 10),          # medium_severity_anomalies
            random.randint(1, 8),           # low_severity_anomalies
            round(random.uniform(10.5, 300.7), 2),  # analysis_duration_seconds
            json.dumps({
                'analysis_type': random.choice(['pcap', 'text', 'hybrid']),
                'algorithms_used': ['isolation_forest', 'dbscan'],
                'total_features': random.randint(15, 50)
            })  # session_details
        ]
        sessions.append(session)
    
    try:
        client.insert(
            'analysis_sessions',
            sessions,
            column_names=[
                'session_id', 'timestamp', 'file_path', 'file_format',
                'total_packets', 'total_lines', 'total_anomalies',
                'high_severity_anomalies', 'medium_severity_anomalies', 
                'low_severity_anomalies', 'analysis_duration_seconds', 'session_details'
            ]
        )
        print(f"Successfully inserted {len(sessions)} session records")
    except Exception as e:
        print(f"Error inserting sessions: {e}")

def main():
    """Main function to insert dummy data"""
    print("=== L1 Troubleshooting Dummy Data Insertion ===")
    
    # Connect to ClickHouse
    client = get_clickhouse_client()
    if not client:
        print("Failed to connect to ClickHouse. Please ensure it's running.")
        return
    
    print("Connected to ClickHouse successfully")
    
    # Generate and insert anomalies
    anomalies = generate_realistic_anomalies()
    insert_anomalies(client, anomalies)
    
    # Insert session data
    insert_session_data(client)
    
    print("\n=== Summary ===")
    print("✓ 50 realistic L1 network anomalies inserted")
    print("✓ 10 analysis session records inserted")
    print("✓ Data includes various anomaly types: fronthaul, UE events, MAC conflicts, protocol violations")
    print("✓ Realistic timestamps spanning last 24 hours")
    print("✓ Ready for frontend testing with 'Get Recommendations' feature")
    
    # Show sample data
    print("\n=== Sample Anomalies ===")
    try:
        sample = client.query("SELECT timestamp, anomaly_type, severity, description FROM anomalies ORDER BY timestamp DESC LIMIT 3")
        for row in sample.result_rows:
            print(f"[{row[0]}] {row[1]} ({row[2]}): {row[3]}")
    except Exception as e:
        print(f"Error fetching sample data: {e}")

if __name__ == "__main__":
    main()