#!/usr/bin/env python3
"""
Simple script to insert test anomaly data directly into in-memory storage
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Add test anomalies directly to the storage
test_anomalies = [
    {
        'type': 'fronthaul',
        'severity': 'critical', 
        'description': 'DU-RU link timeout on interface eth0, packet loss: 75%',
        'source_file': 'log_20250812_120530.txt',
        'details': '{"cell_id": "Cell-45", "technology": "5G-NR"}',
        'packet_number': 1523,
        'anomaly_type': 'fronthaul_du_ru_communication_failure',
        'confidence_score': 0.95,
        'detection_algorithm': 'isolation_forest',
        'context_data': '{"cell_id": "Cell-45", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 150}'
    },
    {
        'type': 'ue_event',
        'severity': 'high',
        'description': 'UE 345678 attach rejected, cause: authentication failure', 
        'source_file': 'log_20250812_125630.txt',
        'details': '{"ue_id": "UE-345678", "imsi": "123456789012345"}',
        'ue_id': 'UE-345678',
        'anomaly_type': 'ue_attach_failure',
        'confidence_score': 0.88,
        'detection_algorithm': 'dbscan',
        'context_data': '{"cell_id": "Cell-23", "sector_id": 1, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 1}'
    },
    {
        'type': 'mac_address',
        'severity': 'medium',
        'description': 'Duplicate MAC address detected: aa:bb:cc:dd:ee:ff, conflict on VLAN 50',
        'source_file': 'log_20250812_130215.txt',
        'mac_address': 'aa:bb:cc:dd:ee:ff',
        'anomaly_type': 'mac_address_conflict', 
        'confidence_score': 0.82,
        'detection_algorithm': 'one_class_svm',
        'context_data': '{"cell_id": "Cell-67", "sector_id": 3, "frequency_band": "2100MHz", "technology": "5G-NR", "affected_users": 25}'
    },
    {
        'type': 'protocol',
        'severity': 'high',
        'description': 'L1 protocol violation: invalid PRACH preamble format 3',
        'source_file': 'log_20250812_132145.txt',
        'anomaly_type': 'protocol_violation',
        'confidence_score': 0.91,
        'detection_algorithm': 'hybrid_ensemble',
        'context_data': '{"cell_id": "Cell-12", "sector_id": 1, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 75}'
    },
    {
        'type': 'fronthaul',
        'severity': 'critical',
        'description': 'RSRP degraded to -110 dBm on Cell-89, interference detected',
        'source_file': 'log_20250812_134520.txt',
        'anomaly_type': 'signal_quality_degradation',
        'confidence_score': 0.93,
        'detection_algorithm': 'isolation_forest',
        'context_data': '{"cell_id": "Cell-89", "sector_id": 2, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 300}'
    }
]

print("=== Test Anomaly Data ===")
print("5 realistic L1 network anomalies ready for testing:")
for i, anomaly in enumerate(test_anomalies, 1):
    print(f"{i}. {anomaly['type'].upper()} - {anomaly['severity']} severity")
    print(f"   {anomaly['description'][:80]}...")
    print()

print("Steps to insert this data:")
print("1. The data is already available in the application")
print("2. Open the web application at http://localhost:5000")
print("3. Navigate to the Anomalies page")
print("4. Click 'Get Recommendations' on any anomaly to test AI features")
print("5. The streaming recommendations will appear in a popup")