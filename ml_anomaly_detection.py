#!/usr/bin/env python3
"""
Advanced ML-based Anomaly Detection for DU-RU Fronthaul Communication
Uses multiple machine learning algorithms to detect communication failures and timing violations
"""

import sys
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from sklearn.decomposition import PCA
from sklearn.neighbors import LocalOutlierFactor
import warnings
warnings.filterwarnings('ignore')

try:
    from scapy.all import rdpcap, Ether, IP, UDP
except ImportError:
    print("Installing required packages...")
    os.system("pip install scapy pandas scikit-learn numpy")
    from scapy.all import rdpcap, Ether, IP, UDP

class MLAnomalyDetector:
    """Advanced ML-based anomaly detection for fronthaul communication"""
    
    def __init__(self):
        self.DU_MAC = "00:11:22:33:44:67"
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        self.scaler = StandardScaler()
        
        # Initialize ML models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.one_class_svm = OneClassSVM(nu=0.1, gamma='auto')
        self.lof = LocalOutlierFactor(n_neighbors=20, contamination=0.1)
        
        print("ML Anomaly Detection System Initialized")
        print("Algorithms: Isolation Forest, DBSCAN, One-Class SVM, Local Outlier Factor")
    
    def extract_features_from_packets(self, packets):
        """Extract comprehensive features for ML analysis"""
        features = []
        packet_metadata = []
        
        print(f"Extracting features from {len(packets)} packets...")
        
        # Group packets by time windows for analysis
        time_windows = {}
        
        for i, packet in enumerate(packets):
            if not Ether in packet:
                continue
                
            src_mac = packet[Ether].src.lower()
            dst_mac = packet[Ether].dst.lower()
            timestamp = float(packet.time) if hasattr(packet, 'time') else i
            
            # Focus on DU-RU communication
            if not (src_mac in [self.DU_MAC.lower(), self.RU_MAC.lower()] and 
                   dst_mac in [self.DU_MAC.lower(), self.RU_MAC.lower()]):
                continue
            
            # Create time window (100ms windows)
            time_window = int(timestamp * 10) / 10
            if time_window not in time_windows:
                time_windows[time_window] = {
                    'du_packets': [],
                    'ru_packets': [],
                    'timestamps': []
                }
            
            packet_info = {
                'timestamp': timestamp,
                'size': len(packet),
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'direction': 'DU_TO_RU' if src_mac == self.DU_MAC.lower() else 'RU_TO_DU'
            }
            
            # Add protocol information
            if IP in packet:
                packet_info['has_ip'] = 1
                packet_info['ip_len'] = packet[IP].len
            else:
                packet_info['has_ip'] = 0
                packet_info['ip_len'] = 0
                
            if UDP in packet:
                packet_info['has_udp'] = 1
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
            else:
                packet_info['has_udp'] = 0
                packet_info['src_port'] = 0
                packet_info['dst_port'] = 0
            
            if packet_info['direction'] == 'DU_TO_RU':
                time_windows[time_window]['du_packets'].append(packet_info)
            else:
                time_windows[time_window]['ru_packets'].append(packet_info)
            
            time_windows[time_window]['timestamps'].append(timestamp)
        
        # Generate features for each time window
        print(f"Analyzing {len(time_windows)} time windows...")
        
        for window_time, window_data in time_windows.items():
            du_packets = window_data['du_packets']
            ru_packets = window_data['ru_packets']
            all_timestamps = sorted(window_data['timestamps'])
            
            # Communication pattern features
            du_count = len(du_packets)
            ru_count = len(ru_packets)
            communication_ratio = ru_count / du_count if du_count > 0 else 0
            
            # Timing features
            if len(all_timestamps) > 1:
                inter_arrival_times = np.diff(all_timestamps)
                avg_inter_arrival = np.mean(inter_arrival_times)
                jitter = np.std(inter_arrival_times)
                max_gap = np.max(inter_arrival_times)
                min_gap = np.min(inter_arrival_times)
            else:
                avg_inter_arrival = jitter = max_gap = min_gap = 0
            
            # Response time analysis
            response_times = []
            missing_responses = 0
            
            for du_pkt in du_packets:
                du_time = du_pkt['timestamp']
                # Look for RU response within 1ms
                found_response = False
                for ru_pkt in ru_packets:
                    ru_time = ru_pkt['timestamp']
                    if ru_time > du_time and (ru_time - du_time) < 0.001:
                        response_times.append((ru_time - du_time) * 1000000)  # microseconds
                        found_response = True
                        break
                if not found_response:
                    missing_responses += 1
            
            # Response timing statistics
            if response_times:
                avg_response_time = np.mean(response_times)
                response_jitter = np.std(response_times)
                max_response_time = np.max(response_times)
                latency_violations = sum(1 for rt in response_times if rt > 100)
            else:
                avg_response_time = response_jitter = max_response_time = latency_violations = 0
            
            # Packet size features
            all_sizes = [pkt['size'] for pkt in du_packets + ru_packets]
            if all_sizes:
                avg_size = np.mean(all_sizes)
                size_variance = np.var(all_sizes)
                max_size = np.max(all_sizes)
                min_size = np.min(all_sizes)
            else:
                avg_size = size_variance = max_size = min_size = 0
            
            # Create feature vector
            feature_vector = [
                du_count,                    # Number of DU packets
                ru_count,                    # Number of RU packets  
                communication_ratio,         # RU/DU packet ratio
                missing_responses,           # Missing RU responses
                avg_inter_arrival,          # Average inter-arrival time
                jitter,                     # Inter-arrival jitter
                max_gap,                    # Maximum gap between packets
                min_gap,                    # Minimum gap between packets
                avg_response_time,          # Average response time (μs)
                response_jitter,            # Response time jitter
                max_response_time,          # Maximum response time
                latency_violations,         # Count of >100μs violations
                avg_size,                   # Average packet size
                size_variance,              # Packet size variance
                max_size,                   # Maximum packet size
                min_size                    # Minimum packet size
            ]
            
            features.append(feature_vector)
            packet_metadata.append({
                'window_time': window_time,
                'du_count': du_count,
                'ru_count': ru_count,
                'missing_responses': missing_responses,
                'avg_response_time': avg_response_time,
                'latency_violations': latency_violations,
                'du_packets_info': du_packets,
                'ru_packets_info': ru_packets,
                'response_times': response_times
            })
        
        return np.array(features), packet_metadata
    
    def detect_anomalies_ml(self, features, metadata):
        """Apply multiple ML algorithms to detect anomalies"""
        print("\nApplying ML algorithms for anomaly detection...")
        
        if len(features) < 5:
            print("Insufficient data for ML analysis (need at least 5 time windows)")
            return {}
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        results = {}
        
        # 1. Isolation Forest
        print("Running Isolation Forest...")
        iso_predictions = self.isolation_forest.fit_predict(features_scaled)
        iso_scores = self.isolation_forest.decision_function(features_scaled)
        iso_anomalies = np.where(iso_predictions == -1)[0]
        results['isolation_forest'] = {
            'anomalies': iso_anomalies,
            'scores': iso_scores,
            'n_anomalies': len(iso_anomalies)
        }
        
        # 2. DBSCAN Clustering
        print("Running DBSCAN clustering...")
        dbscan_labels = self.dbscan.fit_predict(features_scaled)
        dbscan_anomalies = np.where(dbscan_labels == -1)[0]
        results['dbscan'] = {
            'anomalies': dbscan_anomalies,
            'labels': dbscan_labels,
            'n_anomalies': len(dbscan_anomalies)
        }
        
        # 3. One-Class SVM
        print("Running One-Class SVM...")
        svm_predictions = self.one_class_svm.fit_predict(features_scaled)
        svm_scores = self.one_class_svm.decision_function(features_scaled)
        svm_anomalies = np.where(svm_predictions == -1)[0]
        results['one_class_svm'] = {
            'anomalies': svm_anomalies,
            'scores': svm_scores,
            'n_anomalies': len(svm_anomalies)
        }
        
        # 4. Local Outlier Factor
        print("Running Local Outlier Factor...")
        lof_predictions = self.lof.fit_predict(features_scaled)
        lof_scores = self.lof.negative_outlier_factor_
        lof_anomalies = np.where(lof_predictions == -1)[0]
        results['lof'] = {
            'anomalies': lof_anomalies,
            'scores': lof_scores,
            'n_anomalies': len(lof_anomalies)
        }
        
        # Ensemble voting - anomaly if detected by multiple algorithms
        all_indices = set(range(len(features)))
        anomaly_votes = {}
        
        for idx in all_indices:
            votes = 0
            if idx in iso_anomalies: votes += 1
            if idx in dbscan_anomalies: votes += 1
            if idx in svm_anomalies: votes += 1
            if idx in lof_anomalies: votes += 1
            anomaly_votes[idx] = votes
        
        # High confidence anomalies (detected by 2+ algorithms)
        high_confidence_anomalies = [idx for idx, votes in anomaly_votes.items() if votes >= 2]
        
        results['ensemble'] = {
            'high_confidence_anomalies': high_confidence_anomalies,
            'anomaly_votes': anomaly_votes,
            'n_high_confidence': len(high_confidence_anomalies)
        }
        
        return results
    
    def analyze_anomaly_patterns(self, results, metadata):
        """Analyze detected anomalies for communication patterns"""
        print("\nAnalyzing anomaly patterns...")
        
        if 'ensemble' not in results:
            return
        
        high_conf_anomalies = results['ensemble']['high_confidence_anomalies']
        
        if not high_conf_anomalies:
            print("No high-confidence anomalies detected")
            return
        
        print(f"\nHIGH-CONFIDENCE ANOMALIES: {len(high_conf_anomalies)} detected")
        print("=" * 50)
        
        communication_failures = []
        timing_violations = []
        synchronization_issues = []
        
        for idx in high_conf_anomalies:
            meta = metadata[idx]
            
            print(f"\nLINE {idx + 1}: ANOMALY DETECTED - Time Window: {meta['window_time']:.3f}s")
            print(f"*** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
            print(f"DU MAC: {self.DU_MAC}")
            print(f"RU MAC: {self.RU_MAC}")
            print(f"  DU Packets: {meta['du_count']}")
            print(f"  RU Packets: {meta['ru_count']}")
            print(f"  Missing Responses: {meta['missing_responses']}")
            print(f"  Avg Response Time: {meta['avg_response_time']:.1f}μs")
            print(f"  Latency Violations: {meta['latency_violations']}")
            
            # Classify anomaly type and provide detailed analysis
            issue_found = False
            if meta['missing_responses'] > 0:
                communication_failures.append(idx)
                print(f"  ISSUE TYPE: COMMUNICATION FAILURE")
                print(f"  DETAILS: DU ({self.DU_MAC}) sent {meta['du_count']} packets but RU ({self.RU_MAC}) failed to respond to {meta['missing_responses']} packets")
                issue_found = True
            
            if meta['avg_response_time'] > 100:
                timing_violations.append(idx)
                print(f"  ISSUE TYPE: TIMING VIOLATION")
                print(f"  DETAILS: Response time {meta['avg_response_time']:.1f}μs exceeds 100μs threshold between DU ({self.DU_MAC}) and RU ({self.RU_MAC})")
                issue_found = True
            
            if meta['latency_violations'] > meta['du_count'] * 0.3:
                synchronization_issues.append(idx)
                print(f"  ISSUE TYPE: SYNCHRONIZATION ISSUE")
                print(f"  DETAILS: {meta['latency_violations']} out of {meta['du_count']} packets exceeded latency threshold in DU-RU communication")
                issue_found = True
            
            if not issue_found:
                print(f"  ISSUE TYPE: GENERAL ANOMALY")
                print(f"  DETAILS: Abnormal communication pattern detected between DU ({self.DU_MAC}) and RU ({self.RU_MAC})")
        
        # Summary analysis
        print(f"\nFRONTHAUL ANOMALY CLASSIFICATION SUMMARY:")
        print(f"Communication Failures: {len(communication_failures)}")
        print(f"Timing Violations: {len(timing_violations)}")
        print(f"Synchronization Issues: {len(synchronization_issues)}")
        
        # Detection confidence by algorithm
        print(f"\nDETECTION CONFIDENCE BY ALGORITHM:")
        for alg_name, alg_results in results.items():
            if alg_name != 'ensemble':
                print(f"{alg_name.replace('_', ' ').title()}: {alg_results['n_anomalies']} anomalies")
    
    def run_analysis(self, pcap_file):
        """Run complete ML-based anomaly analysis"""
        print(f"ML ANOMALY DETECTION ANALYSIS")
        print("=" * 60)
        print(f"Processing: {pcap_file}")
        
        try:
            # Load packets
            packets = rdpcap(pcap_file)
            print(f"Loaded {len(packets)} packets")
            
            # Extract features
            features, metadata = self.extract_features_from_packets(packets)
            print(f"Generated {len(features)} feature vectors")
            
            if len(features) == 0:
                print("No DU-RU communication packets found")
                return
            
            # Apply ML algorithms
            results = self.detect_anomalies_ml(features, metadata)
            
            # Analyze patterns
            self.analyze_anomaly_patterns(results, metadata)
            
            print(f"\nML ANALYSIS COMPLETE")
            
        except Exception as e:
            print(f"Analysis error: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python ml_anomaly_detection.py <pcap_file>")
        print("Example: python ml_anomaly_detection.py fronthaul_capture.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file '{pcap_file}' not found")
        sys.exit(1)
    
    # Initialize and run ML analysis
    detector = MLAnomalyDetector()
    detector.run_analysis(pcap_file)

if __name__ == "__main__":
    main()