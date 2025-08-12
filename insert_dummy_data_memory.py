#!/usr/bin/env python3
"""
Insert realistic dummy anomaly data into the in-memory storage via API calls
"""

import requests
import json
from datetime import datetime, timedelta
import random

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
    
    # Base time - start from 6 hours ago
    base_time = datetime.now() - timedelta(hours=6)
    
    anomalies = []
    
    for i in range(20):  # Generate 20 realistic anomalies
        timestamp = base_time + timedelta(minutes=random.randint(0, 360))  # Spread over 6 hours
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
        
        # Map anomaly types to frontend display types
        type_mapping = {
            'fronthaul_du_ru_communication_failure': 'fronthaul',
            'ue_attach_failure': 'ue_event',
            'handover_failure': 'ue_event', 
            'mac_address_conflict': 'mac_address',
            'protocol_violation': 'protocol',
            'signal_quality_degradation': 'fronthaul',
            'timing_synchronization_error': 'protocol',
            'resource_allocation_failure': 'fronthaul',
            'interference_detection': 'fronthaul',
            'pci_conflict': 'protocol'
        }
        
        # Generate additional context data
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
            'type': type_mapping[anomaly_type],
            'anomaly_type': anomaly_type,
            'severity': severity,
            'description': description,
            'source_file': f"log_{timestamp.strftime('%Y%m%d_%H%M%S')}.txt",
            'confidence_score': round(random.uniform(0.7, 0.99), 3),
            'detection_algorithm': random.choice(['isolation_forest', 'dbscan', 'one_class_svm', 'hybrid_ensemble']),
            'status': random.choice(['new', 'investigating', 'resolved']),
            'context_data': json.dumps(context_data),
            'anomaly_id': f"ANM-{random.randint(100000, 999999)}",
            'packet_number': random.randint(1, 10000) if random.choice([True, False]) else None,
            'mac_address': generate_mac_address() if anomaly_type == 'mac_address_conflict' else None,
            'ue_id': f"UE-{random.randint(100000, 999999)}" if 'ue_' in anomaly_type else None
        }
        
        anomalies.append(anomaly)
    
    return anomalies

def generate_mac_address():
    """Generate a realistic MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def insert_via_api(anomalies, base_url="http://localhost:5000"):
    """Insert anomalies via API calls"""
    print(f"Inserting {len(anomalies)} dummy anomalies via API...")
    
    successful = 0
    failed = 0
    
    for anomaly in anomalies:
        try:
            response = requests.post(
                f"{base_url}/api/anomalies",
                json=anomaly,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                successful += 1
                print(f"✓ Inserted: {anomaly['anomaly_type']} ({anomaly['severity']})")
            else:
                failed += 1
                print(f"✗ Failed: {response.status_code} - {response.text}")
                
        except Exception as e:
            failed += 1
            print(f"✗ Error inserting anomaly: {e}")
    
    print(f"\n=== Summary ===")
    print(f"✓ Successfully inserted: {successful} anomalies")
    print(f"✗ Failed to insert: {failed} anomalies")
    print(f"📊 Ready for testing 'Get Recommendations' feature")
    
    return successful > 0

def main():
    """Main function to insert dummy data via API"""
    print("=== L1 Troubleshooting Dummy Data Insertion (Memory Storage) ===")
    
    # Generate realistic anomalies
    anomalies = generate_realistic_anomalies()
    
    # Insert via API calls
    success = insert_via_api(anomalies)
    
    if success:
        print("\n🎉 Dummy data insertion completed!")
        print("💡 You can now test the 'Get Recommendations' button in the frontend")
        print("🤖 Each anomaly will generate AI-powered troubleshooting advice")
        print("\n📍 Open the application and navigate to the Anomalies page to see the data")
    else:
        print("\n❌ Failed to insert dummy data. Please check if the server is running on port 5000")

if __name__ == "__main__":
    main()