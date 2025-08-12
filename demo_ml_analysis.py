#!/usr/bin/env python3
"""
Demo script showing ML-based anomaly detection capabilities
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

def demonstrate_ml_algorithms():
    """Demonstrate the ML algorithms used for anomaly detection"""
    
    print("ML ANOMALY DETECTION DEMONSTRATION")
    print("=" * 50)
    print("Algorithms used:")
    print("✓ Isolation Forest - Detects outliers in high-dimensional data")
    print("✓ DBSCAN - Finds dense clusters and marks sparse points as anomalies")
    print("✓ One-Class SVM - Learns normal behavior boundary")
    print("✓ Local Outlier Factor - Detects local density-based outliers")
    print()
    
    # Generate sample fronthaul communication data
    np.random.seed(42)
    
    # Normal communication patterns
    normal_data = []
    for i in range(80):
        # Normal DU-RU communication
        du_packets = np.random.poisson(10)  # ~10 DU packets per window
        ru_packets = np.random.poisson(9)   # ~9 RU responses (some may be lost)
        response_time = np.random.normal(75, 15)  # ~75μs average response
        jitter = np.random.normal(20, 5)    # ~20μs jitter
        packet_size = np.random.normal(128, 20)  # ~128 bytes average
        
        normal_data.append([
            du_packets, ru_packets, ru_packets/du_packets if du_packets > 0 else 0,
            max(0, du_packets - ru_packets), response_time, jitter,
            np.random.uniform(0.001, 0.01), packet_size
        ])
    
    # Anomalous communication patterns
    anomaly_data = []
    
    # Communication failures
    for i in range(5):
        du_packets = np.random.poisson(12)
        ru_packets = np.random.poisson(3)   # Many missing responses
        response_time = np.random.normal(150, 30)  # High latency
        jitter = np.random.normal(80, 20)   # High jitter
        packet_size = np.random.normal(128, 20)
        
        anomaly_data.append([
            du_packets, ru_packets, ru_packets/du_packets if du_packets > 0 else 0,
            du_packets - ru_packets, response_time, jitter,
            np.random.uniform(0.02, 0.05), packet_size
        ])
    
    # Timing violations
    for i in range(5):
        du_packets = np.random.poisson(8)
        ru_packets = np.random.poisson(8)
        response_time = np.random.normal(250, 50)  # Very high latency
        jitter = np.random.normal(150, 30)  # Very high jitter
        packet_size = np.random.normal(128, 20)
        
        anomaly_data.append([
            du_packets, ru_packets, ru_packets/du_packets if du_packets > 0 else 0,
            max(0, du_packets - ru_packets), response_time, jitter,
            np.random.uniform(0.001, 0.01), packet_size
        ])
    
    # Combine data
    all_data = np.array(normal_data + anomaly_data)
    feature_names = [
        'du_packets', 'ru_packets', 'comm_ratio', 'missing_responses',
        'response_time', 'jitter', 'inter_arrival', 'packet_size'
    ]
    
    print(f"Generated {len(all_data)} time windows:")
    print(f"  Normal patterns: {len(normal_data)}")
    print(f"  Anomalous patterns: {len(anomaly_data)}")
    print()
    
    # Normalize data
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(all_data)
    
    # Apply Isolation Forest
    iso_forest = IsolationForest(contamination=0.15, random_state=42)
    iso_predictions = iso_forest.fit_predict(data_scaled)
    iso_anomalies = np.where(iso_predictions == -1)[0]
    
    # Apply DBSCAN
    dbscan = DBSCAN(eps=0.5, min_samples=5)
    dbscan_labels = dbscan.fit_predict(data_scaled)
    dbscan_anomalies = np.where(dbscan_labels == -1)[0]
    
    print("DETECTION RESULTS:")
    print("-" * 30)
    print(f"Isolation Forest detected: {len(iso_anomalies)} anomalies")
    print(f"DBSCAN detected: {len(dbscan_anomalies)} anomalies")
    
    # Known anomalies are in indices 80-89
    known_anomalies = set(range(80, 90))
    iso_detected = set(iso_anomalies)
    dbscan_detected = set(dbscan_anomalies)
    
    print()
    print("DETECTION ACCURACY:")
    print("-" * 20)
    iso_true_positives = len(known_anomalies & iso_detected)
    dbscan_true_positives = len(known_anomalies & dbscan_detected)
    
    print(f"Isolation Forest accuracy: {iso_true_positives}/{len(known_anomalies)} true anomalies detected")
    print(f"DBSCAN accuracy: {dbscan_true_positives}/{len(known_anomalies)} true anomalies detected")
    
    # Show sample anomalies
    print()
    print("SAMPLE DETECTED ANOMALIES:")
    print("-" * 30)
    
    for idx in list(iso_anomalies)[:3]:
        row = all_data[idx]
        print(f"Window #{idx}:")
        print(f"  DU packets: {row[0]:.0f}, RU packets: {row[1]:.0f}")
        print(f"  Missing responses: {row[3]:.0f}")
        print(f"  Response time: {row[4]:.1f}μs")
        print(f"  Jitter: {row[5]:.1f}μs")
        
        # Classify anomaly type
        if row[3] > 3:  # Missing responses
            print("  TYPE: Communication Failure")
        elif row[4] > 100:  # High latency
            print("  TYPE: Timing Violation")
        elif row[5] > 50:  # High jitter
            print("  TYPE: Synchronization Issue")
        print()

def show_feature_analysis():
    """Show what features are extracted for ML analysis"""
    
    print("FEATURE EXTRACTION FOR ML ANALYSIS")
    print("=" * 40)
    print("Features extracted from each 100ms time window:")
    print()
    
    features = [
        ("du_count", "Number of DU->RU packets"),
        ("ru_count", "Number of RU->DU packets"),
        ("communication_ratio", "RU response rate (RU/DU)"),
        ("missing_responses", "DU packets with no RU response"),
        ("avg_inter_arrival", "Average time between packets"),
        ("jitter", "Inter-arrival time variation"),
        ("max_gap", "Maximum gap between packets"),
        ("min_gap", "Minimum gap between packets"),
        ("avg_response_time", "Average DU->RU response time (μs)"),
        ("response_jitter", "Response time variation"),
        ("max_response_time", "Maximum response time"),
        ("latency_violations", "Count of >100μs responses"),
        ("avg_size", "Average packet size"),
        ("size_variance", "Packet size variation"),
        ("max_size", "Largest packet size"),
        ("min_size", "Smallest packet size")
    ]
    
    for i, (name, description) in enumerate(features, 1):
        print(f"{i:2d}. {name:20s} - {description}")
    
    print()
    print("ANOMALY DETECTION APPROACH:")
    print("- Each algorithm learns 'normal' fronthaul communication patterns")
    print("- Deviations from normal patterns are flagged as anomalies")
    print("- Ensemble voting increases detection confidence")
    print("- High-confidence anomalies are detected by 2+ algorithms")

def main():
    demonstrate_ml_algorithms()
    print()
    show_feature_analysis()
    
    print()
    print("USAGE:")
    print("python ml_anomaly_detection.py YOUR_PCAP_FILE.pcap")

if __name__ == "__main__":
    main()