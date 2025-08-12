#!/usr/bin/env python3
"""
Unified Anomaly Detection System
Analyzes both PCAP files and HDF5-converted text files for L1 troubleshooting
Detects DU-RU communication failures and UE Attach/Detach anomalies
"""

import sys
import os
import re
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Try to import Scapy for PCAP processing
try:
    # Try different import methods
    try:
        from scapy.all import rdpcap, Ether, IP, UDP
        SCAPY_AVAILABLE = True
    except ImportError:
        # Fallback to scapy3k if available
        import scapy
        from scapy.all import rdpcap, Ether, IP, UDP
        SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. PCAP analysis will be disabled.")

class UnifiedAnomalyDetector:
    """Unified anomaly detection for both PCAP and HDF5 text files"""
    
    def __init__(self):
        self.DU_MAC = "00:11:22:33:44:67"
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        self.scaler = StandardScaler()
        
        # Initialize ML models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.one_class_svm = OneClassSVM(nu=0.1, gamma='auto')
        self.lof = LocalOutlierFactor(n_neighbors=20, contamination=0.1)
        
        print("UNIFIED ANOMALY DETECTION SYSTEM INITIALIZED")
        print("Supports: PCAP files (.pcap, .cap) and HDF5 text files (.txt, .log)")
        print("Algorithms: Isolation Forest, DBSCAN, One-Class SVM, Local Outlier Factor")
        print("Target: DU-RU communication failures and UE event anomalies")
    
    def detect_file_type(self, file_path):
        """Automatically detect file type based on extension and content"""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext in ['.pcap', '.cap']:
            return 'pcap'
        elif file_ext in ['.txt', '.log']:
            return 'text'
        else:
            # Try to detect based on content
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    if header.startswith(b'\xa1\xb2\xc3\xd4') or header.startswith(b'\xd4\xc3\xb2\xa1'):
                        return 'pcap'
            except:
                pass
            
            # Default to text
            return 'text'
    
    def analyze_file(self, file_path):
        """Main analysis function - automatically detects and processes file type"""
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found")
            return
        
        file_type = self.detect_file_type(file_path)
        print(f"Detected file type: {file_type.upper()}")
        
        if file_type == 'pcap':
            if not SCAPY_AVAILABLE:
                print("Error: Scapy not available for PCAP analysis")
                return
            self.analyze_pcap_file(file_path)
        else:
            self.analyze_text_file(file_path)
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze PCAP file for DU-RU communication anomalies"""
        print(f"\nPCAP ANOMALY ANALYSIS")
        print("=" * 30)
        print(f"Processing: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            print(f"Loaded {len(packets)} packets")
            
            # Extract features from packets
            features, packet_metadata = self.extract_pcap_features(packets)
            
            if len(features) < 5:
                print("Insufficient time windows for PCAP analysis")
                return
            
            # Apply ML algorithms
            features_array = np.array(features)
            features_scaled = self.scaler.fit_transform(features_array)
            
            # Run all algorithms
            iso_predictions = self.isolation_forest.fit_predict(features_scaled)
            dbscan_labels = self.dbscan.fit_predict(features_scaled)
            svm_predictions = self.one_class_svm.fit_predict(features_scaled)
            lof_predictions = self.lof.fit_predict(features_scaled)
            
            # Find anomalies
            iso_anomalies = set(np.where(iso_predictions == -1)[0])
            dbscan_anomalies = set(np.where(dbscan_labels == -1)[0])
            svm_anomalies = set(np.where(svm_predictions == -1)[0])
            lof_anomalies = set(np.where(lof_predictions == -1)[0])
            
            # Ensemble voting
            all_indices = set(range(len(features)))
            high_confidence_anomalies = []
            
            for idx in all_indices:
                votes = 0
                if idx in iso_anomalies: votes += 1
                if idx in dbscan_anomalies: votes += 1
                if idx in svm_anomalies: votes += 1
                if idx in lof_anomalies: votes += 1
                
                if votes >= 2:  # High confidence threshold
                    high_confidence_anomalies.append(idx)
            
            # Report results
            self.report_pcap_anomalies(high_confidence_anomalies, features, packet_metadata)
            
        except Exception as e:
            print(f"PCAP analysis error: {e}")
    
    def extract_pcap_features(self, packets):
        """Extract features from PCAP packets for ML analysis"""
        features = []
        packet_metadata = []
        
        print(f"Extracting features from {len(packets)} packets...")
        
        # Group packets by time windows (100ms)
        time_windows = {}
        
        for i, packet in enumerate(packets):
            if not Ether in packet:
                continue
                
            src_mac = packet[Ether].src.lower()
            dst_mac = packet[Ether].dst.lower()
            timestamp = float(packet.time) if hasattr(packet, 'time') else i * 0.001
            
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
                'direction': 'DU_TO_RU' if src_mac == self.DU_MAC.lower() else 'RU_TO_DU',
                'packet_num': i + 1
            }
            
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
            
            if not du_packets and not ru_packets:
                continue
            
            # Extract 16 features per window
            window_features = self.calculate_window_features(du_packets, ru_packets, all_timestamps)
            if window_features:
                features.append(window_features)
                packet_metadata.append({
                    'window_time': window_time,
                    'du_packets': du_packets,
                    'ru_packets': ru_packets,
                    'packet_count': len(du_packets) + len(ru_packets)
                })
        
        return features, packet_metadata
    
    def calculate_window_features(self, du_packets, ru_packets, all_timestamps):
        """Calculate 16 features for a time window"""
        if not all_timestamps:
            return None
        
        # Communication pattern features
        du_count = len(du_packets)
        ru_count = len(ru_packets)
        communication_ratio = ru_count / du_count if du_count > 0 else 0
        
        # Calculate response times and missing responses
        response_times = []
        matched_responses = 0
        
        for du_pkt in du_packets:
            du_time = du_pkt['timestamp']
            for ru_pkt in ru_packets:
                ru_time = ru_pkt['timestamp']
                if ru_time > du_time and (ru_time - du_time) < 0.001:  # Within 1ms
                    response_time = (ru_time - du_time) * 1_000_000  # Convert to microseconds
                    response_times.append(response_time)
                    matched_responses += 1
                    break
        
        missing_responses = du_count - matched_responses
        
        # Timing features
        if len(all_timestamps) > 1:
            inter_arrival_times = np.diff(all_timestamps)
            avg_inter_arrival = np.mean(inter_arrival_times)
            jitter = np.std(inter_arrival_times)
            max_gap = np.max(inter_arrival_times)
            min_gap = np.min(inter_arrival_times)
        else:
            avg_inter_arrival = jitter = max_gap = min_gap = 0
        
        # Response time features
        if response_times:
            avg_response_time = np.mean(response_times)
            response_jitter = np.std(response_times)
            max_response_time = np.max(response_times)
            latency_violations = sum(1 for rt in response_times if rt > 100)
        else:
            avg_response_time = response_jitter = max_response_time = latency_violations = 0
        
        # Packet size features
        all_packets = du_packets + ru_packets
        if all_packets:
            packet_sizes = [pkt['size'] for pkt in all_packets]
            avg_size = np.mean(packet_sizes)
            size_variance = np.var(packet_sizes)
            max_size = np.max(packet_sizes)
            min_size = np.min(packet_sizes)
        else:
            avg_size = size_variance = max_size = min_size = 0
        
        # Return 16 features
        return [
            du_count, ru_count, communication_ratio, missing_responses,
            avg_inter_arrival, jitter, max_gap, min_gap,
            avg_response_time, response_jitter, max_response_time, latency_violations,
            avg_size, size_variance, max_size, min_size
        ]
    
    def analyze_text_file(self, text_file):
        """Analyze HDF5-converted text file for UE event anomalies"""
        print(f"\nUE EVENT ANOMALY ANALYSIS")
        print("=" * 30)
        print(f"Processing: {text_file}")
        
        try:
            # Parse UE events
            events = self.parse_ue_events_from_text(text_file)
            
            if not events:
                print("No UE events found in file")
                return
            
            # Analyze patterns
            results = self.analyze_ue_event_patterns(events)
            
            # Report anomalies
            self.report_ue_anomalies(results)
            
        except Exception as e:
            print(f"UE event analysis error: {e}")
    
    def parse_ue_events_from_text(self, text_file):
        """Parse UE events from HDF5-converted text file"""
        events = []
        line_number = 0
        
        print(f"Parsing UE events from: {text_file}")
        
        # Event patterns to detect
        event_patterns = {
            'attach_request': [r'attach.?request', r'rrc.?connection.?request', r'initial.?ue.?message'],
            'attach_accept': [r'attach.?accept', r'rrc.?connection.?setup'],
            'attach_complete': [r'attach.?complete', r'rrc.?connection.?setup.?complete'],
            'detach_request': [r'detach.?request', r'ue.?context.?release.?request'],
            'detach_accept': [r'detach.?accept', r'ue.?context.?release.?complete'],
            'handover_request': [r'handover.?request', r'x2.?handover.?request'],
            'handover_complete': [r'handover.?complete', r'path.?switch.?request.?ack'],
            'paging_request': [r'paging', r'paging.?request'],
            'service_request': [r'service.?request', r'nas.?service.?request'],
            'context_failure': [r'context.?setup.?failure', r'context.?failure', r'setup.?failure']
        }
        
        try:
            with open(text_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_number += 1
                    line_lower = line.strip().lower()
                    
                    if not line_lower:
                        continue
                    
                    # Extract timestamp
                    timestamp = self._extract_timestamp(line_lower) or line_number * 0.001
                    
                    # Extract UE identifier
                    ue_id = self._extract_ue_identifier(line_lower) or f'ue_{line_number}'
                    
                    # Extract cell information
                    cell_id = self._extract_cell_info(line_lower) or 'unknown'
                    
                    # Detect event type
                    event_type = None
                    for event_name, patterns in event_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, line_lower, re.IGNORECASE):
                                event_type = event_name
                                break
                        if event_type:
                            break
                    
                    # Extract cause code
                    cause_code = self._extract_cause_code(line_lower)
                    
                    # Check for DU-RU MAC addresses
                    has_du_mac = self.DU_MAC.lower() in line_lower
                    has_ru_mac = self.RU_MAC.lower() in line_lower
                    
                    if event_type or ue_id != f'ue_{line_number}' or has_du_mac or has_ru_mac:
                        event = {
                            'line_number': line_number,
                            'timestamp': timestamp,
                            'event_type': event_type or 'unknown',
                            'ue_id': ue_id,
                            'cell_id': cell_id,
                            'cause_code': cause_code,
                            'message_size': len(line),
                            'has_du_mac': has_du_mac,
                            'has_ru_mac': has_ru_mac,
                            'raw_line': line[:200]
                        }
                        events.append(event)
        
        except Exception as e:
            print(f"Error parsing file: {e}")
            return []
        
        print(f"Extracted {len(events)} UE events from {line_number} lines")
        return events
    
    def _extract_timestamp(self, line):
        """Extract timestamp from various formats"""
        patterns = [
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.?\d*)',
            r'(\d{10}\.\d+)',
            r'(\d{2}:\d{2}:\d{2}\.?\d*)',
            r'timestamp[:\s=]*(\d+\.?\d*)',
            r'time[:\s=]*(\d+\.?\d*)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                try:
                    timestamp_str = match.group(1)
                    if '.' in timestamp_str and len(timestamp_str.split('.')[0]) == 10:
                        return float(timestamp_str)
                    elif ':' in timestamp_str:
                        time_parts = timestamp_str.split(':')
                        return float(time_parts[0]) * 3600 + float(time_parts[1]) * 60 + float(time_parts[2].split('.')[0])
                except:
                    continue
        return None
    
    def _extract_ue_identifier(self, line):
        """Extract UE identifier"""
        patterns = [
            r'imsi[:\s=]*(\d+)',
            r'rnti[:\s=]*(\d+)',
            r'ue.?id[:\s=]*(\d+)',
            r'subscriber[:\s=]*(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _extract_cell_info(self, line):
        """Extract cell information"""
        patterns = [
            r'cell.?id[:\s=]*(\d+)',
            r'enb.?id[:\s=]*(\d+)',
            r'gnb.?id[:\s=]*(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _extract_cause_code(self, line):
        """Extract cause codes"""
        patterns = [
            r'cause[:\s=]*(\d+)',
            r'error[:\s=]*(\d+)',
            r'failure[:\s=]*(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return int(match.group(1))
        return 0
    
    def analyze_ue_event_patterns(self, events):
        """Analyze UE events for anomalous patterns"""
        if len(events) < 5:
            return {'events': events, 'anomalous_ues': 0}
        
        # Group events by UE ID
        ue_patterns = defaultdict(list)
        for event in events:
            ue_patterns[event['ue_id']].append(event)
        
        # Extract features for each UE
        ue_features = []
        ue_metadata = []
        
        for ue_id, ue_events in ue_patterns.items():
            if len(ue_events) < 2:
                continue
            
            ue_events.sort(key=lambda x: x['timestamp'])
            features = self._extract_ue_features(ue_events)
            
            if features:
                ue_features.append(features)
                ue_metadata.append({
                    'ue_id': ue_id,
                    'event_count': len(ue_events),
                    'events': ue_events
                })
        
        if len(ue_features) < 3:
            return {'events': events, 'anomalous_ues': 0, 'ue_metadata': ue_metadata}
        
        # Apply ML algorithms
        features_array = np.array(ue_features)
        features_scaled = self.scaler.fit_transform(features_array)
        
        # Isolation Forest and DBSCAN for UE events
        iso_predictions = self.isolation_forest.fit_predict(features_scaled)
        dbscan_labels = self.dbscan.fit_predict(features_scaled)
        
        iso_anomalies = set(np.where(iso_predictions == -1)[0])
        dbscan_anomalies = set(np.where(dbscan_labels == -1)[0])
        
        anomalous_ues = iso_anomalies | dbscan_anomalies
        
        return {
            'total_events': len(events),
            'total_ues': len(ue_patterns),
            'anomalous_ues': len(anomalous_ues),
            'anomalous_indices': anomalous_ues,
            'ue_metadata': ue_metadata,
            'events': events
        }
    
    def _extract_ue_features(self, ue_events):
        """Extract 12 features for UE analysis"""
        if len(ue_events) < 2:
            return None
        
        event_types = [event['event_type'] for event in ue_events]
        event_counts = Counter(event_types)
        
        timestamps = [event['timestamp'] for event in ue_events]
        time_diffs = np.diff(timestamps)
        
        # Calculate features
        attach_requests = event_counts.get('attach_request', 0)
        attach_accepts = event_counts.get('attach_accept', 0)
        attach_completes = event_counts.get('attach_complete', 0)
        detach_requests = event_counts.get('detach_request', 0)
        detach_accepts = event_counts.get('detach_accept', 0)
        failures = event_counts.get('context_failure', 0)
        
        return [
            len(ue_events),
            attach_requests,
            attach_accepts,
            attach_completes,
            detach_requests,
            detach_accepts,
            failures,
            attach_requests - attach_accepts,
            detach_requests - detach_accepts,
            np.mean(time_diffs) if len(time_diffs) > 0 else 0,
            np.std(time_diffs) if len(time_diffs) > 0 else 0,
            sum(1 for event in ue_events if event['cause_code'] > 0)
        ]
    
    def report_pcap_anomalies(self, anomalies, features, metadata):
        """Report PCAP anomalies"""
        print(f"\nPCAP ANOMALY ANALYSIS RESULTS")
        print("=" * 50)
        print(f"Time Windows Analyzed: {len(features)}")
        print(f"High-Confidence Anomalies: {len(anomalies)}")
        
        if not anomalies:
            print("No high-confidence PCAP anomalies detected")
            return
        
        print(f"\nANOMALOUS TIME WINDOWS:")
        print("-" * 30)
        
        for idx in sorted(anomalies):
            if idx >= len(metadata):
                continue
            
            window_info = metadata[idx]
            window_features = features[idx]
            
            # Get representative packet for line number
            all_packets = window_info['du_packets'] + window_info['ru_packets']
            if all_packets:
                line_number = min(pkt['packet_num'] for pkt in all_packets)
            else:
                line_number = idx + 1
            
            print(f"\nLINE {line_number}: PCAP ANOMALY DETECTED")
            print(f"*** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
            print(f"DU MAC: {self.DU_MAC}")
            print(f"RU MAC: {self.RU_MAC}")
            print(f"Time Window: {window_info['window_time']:.3f}s")
            print(f"Packet Count: {window_info['packet_count']}")
            
            # Analyze specific issues
            du_count, ru_count, comm_ratio, missing_resp = window_features[:4]
            avg_response, _, max_response, violations = window_features[8:12]
            
            issues = []
            if missing_resp > 0:
                issues.append(f"Missing Responses: {int(missing_resp)} DU packets without RU replies")
            if violations > 0:
                issues.append(f"Latency Violations: {int(violations)} responses > 100μs")
            if max_response > 100:
                issues.append(f"Max Response Time: {max_response:.1f}μs exceeds threshold")
            if comm_ratio < 0.8 and du_count > 0:
                issues.append(f"Poor Communication Ratio: {comm_ratio:.2f} (expected > 0.8)")
            
            if issues:
                print("DETECTED ISSUES:")
                for issue in issues:
                    print(f"  • {issue}")
            else:
                print("ISSUE TYPE: Statistical deviation from normal DU-RU patterns")
    
    def report_ue_anomalies(self, results):
        """Report UE anomalies"""
        print(f"\nUE EVENT ANOMALY ANALYSIS RESULTS")
        print("=" * 50)
        print(f"Total Events Analyzed: {results['total_events']}")
        print(f"Total UEs: {results['total_ues']}")
        print(f"Anomalous UEs Detected: {results['anomalous_ues']}")
        
        if results['anomalous_ues'] == 0:
            print("No anomalous UE behavior detected")
            return
        
        print(f"\nANOMALOUS UE PATTERNS:")
        print("-" * 30)
        
        for idx in sorted(results['anomalous_indices']):
            if idx >= len(results['ue_metadata']):
                continue
            
            ue_info = results['ue_metadata'][idx]
            ue_events = ue_info['events']
            
            print(f"\nLINE {ue_events[0]['line_number']}: UE ANOMALY DETECTED")
            print(f"*** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
            print(f"DU MAC: {self.DU_MAC}")
            print(f"RU MAC: {self.RU_MAC}")
            print(f"UE ID: {ue_info['ue_id']}")
            print(f"Event Count: {ue_info['event_count']}")
            
            # Analyze issues
            event_types = [event['event_type'] for event in ue_events]
            event_counts = Counter(event_types)
            
            attach_requests = event_counts.get('attach_request', 0)
            attach_accepts = event_counts.get('attach_accept', 0)
            detach_requests = event_counts.get('detach_request', 0)
            failures = event_counts.get('context_failure', 0)
            
            du_events = sum(1 for event in ue_events if event['has_du_mac'])
            ru_events = sum(1 for event in ue_events if event['has_ru_mac'])
            
            if du_events > 0 or ru_events > 0:
                print(f"DU Events: {du_events}, RU Events: {ru_events}")
            
            issues = []
            if attach_requests > attach_accepts + 1:
                issues.append(f"Failed Attach Procedures: {attach_requests - attach_accepts} incomplete")
            if failures > 0:
                issues.append(f"Context Failures: {failures} detected")
            if detach_requests == 0 and attach_requests > 0:
                issues.append("Missing Detach Events: UE may have unexpectedly disconnected")
            
            if issues:
                print("DETECTED ISSUES:")
                for issue in issues:
                    print(f"  • {issue}")
            else:
                print("ISSUE TYPE: Abnormal UE Event Pattern")
                print("DETAILS: Statistical deviation from normal UE behavior")
            
            # Show event sequence
            print("Event Sequence:")
            for i, event in enumerate(ue_events[:5]):
                print(f"  {i+1}. {event['event_type']} at line {event['line_number']}")
            if len(ue_events) > 5:
                print(f"  ... and {len(ue_events) - 5} more events")

def main():
    if len(sys.argv) != 2:
        print("UNIFIED ANOMALY DETECTION SYSTEM")
        print("=" * 40)
        print("Usage: python unified_anomaly_detector.py <file_path>")
        print()
        print("Supported formats:")
        print("• PCAP files (.pcap, .cap) - DU-RU communication analysis")
        print("• Text files (.txt, .log) - UE Attach/Detach event analysis")
        print()
        print("Examples:")
        print("  python unified_anomaly_detector.py network_capture.pcap")
        print("  python unified_anomaly_detector.py ue_events.txt")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)
    
    # Initialize and run unified analysis
    detector = UnifiedAnomalyDetector()
    detector.analyze_file(file_path)
    
    print(f"\nUNIFIED ANOMALY ANALYSIS COMPLETE")
    print("System provides comprehensive L1 troubleshooting for:")
    print("• DU-RU fronthaul communication issues (PCAP)")
    print("• UE mobility and attachment anomalies (Text)")

if __name__ == "__main__":
    main()