#!/usr/bin/env python3
"""
Folder-Based L1 Anomaly Detection System
Automatically processes all PCAP and HDF5-converted text files from a folder
Detects DU-RU communication failures and UE Attach/Detach anomalies
"""

import sys
import os
import glob
import struct
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

class FolderAnomalyAnalyzer:
    """Folder-based anomaly detection for both PCAP and HDF5 text files"""
    
    def __init__(self):
        self.DU_MAC = "00:11:22:33:44:67"
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        self.scaler = StandardScaler()
        
        # Initialize ML models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.one_class_svm = OneClassSVM(nu=0.1, gamma='auto')
        self.lof = LocalOutlierFactor(n_neighbors=20, contamination=0.1)
        
        # Statistics tracking
        self.total_files_processed = 0
        self.pcap_files_processed = 0
        self.text_files_processed = 0
        self.total_anomalies_found = 0
        
        print("FOLDER-BASED L1 ANOMALY DETECTION SYSTEM")
        print("=" * 50)
        print("Automatically processes all files in folder:")
        print("• PCAP files (.pcap, .cap)")
        print("• HDF5 text files (.txt, .log)")
        print("• Auto-detects file types")
        print("• Batch processing with summary report")
    
    def find_network_files(self, folder_path):
        """Find all PCAP and text files in the folder"""
        if not os.path.exists(folder_path):
            print(f"Error: Folder '{folder_path}' not found")
            return []
        
        if not os.path.isdir(folder_path):
            print(f"Error: '{folder_path}' is not a directory")
            return []
        
        # File patterns to search for
        patterns = [
            "*.pcap", "*.cap", "*.pcapng",  # PCAP files
            "*.txt", "*.log"                # Text files
        ]
        
        files_found = []
        
        for pattern in patterns:
            search_path = os.path.join(folder_path, pattern)
            files_found.extend(glob.glob(search_path))
        
        # Also search subdirectories
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1].lower()
                
                if file_ext in ['.pcap', '.cap', '.pcapng', '.txt', '.log']:
                    if file_path not in files_found:
                        files_found.append(file_path)
        
        return sorted(files_found)
    
    def detect_file_type(self, file_path):
        """Automatically detect file type"""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext in ['.pcap', '.cap', '.pcapng']:
            return 'pcap'
        elif file_ext in ['.txt', '.log']:
            return 'text'
        else:
            # Try to detect PCAP magic bytes
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    if (header.startswith(b'\xa1\xb2\xc3\xd4') or 
                        header.startswith(b'\xd4\xc3\xb2\xa1') or
                        header.startswith(b'\x0a\x0d\x0d\x0a')):
                        return 'pcap'
            except:
                pass
            
            return 'text'
    
    def process_folder(self, folder_path):
        """Process all network files in the folder"""
        print(f"\nSCANNING FOLDER: {folder_path}")
        print("-" * 40)
        
        # Find all network files
        files = self.find_network_files(folder_path)
        
        if not files:
            print("No PCAP or text files found in folder")
            return
        
        print(f"Found {len(files)} network files:")
        
        # Categorize files
        pcap_files = []
        text_files = []
        
        for file_path in files:
            file_type = self.detect_file_type(file_path)
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            print(f"  {file_name} ({file_type.upper()}, {file_size:,} bytes)")
            
            if file_type == 'pcap':
                pcap_files.append(file_path)
            else:
                text_files.append(file_path)
        
        print(f"\nFILE SUMMARY:")
        print(f"• PCAP files: {len(pcap_files)}")
        print(f"• Text files: {len(text_files)}")
        
        # Process all files
        print(f"\nPROCESSING FILES...")
        print("=" * 30)
        
        all_anomalies = []
        
        # Process PCAP files
        for pcap_file in pcap_files:
            print(f"\n📁 Processing PCAP: {os.path.basename(pcap_file)}")
            anomalies = self.analyze_pcap_file(pcap_file)
            if anomalies:
                all_anomalies.extend(anomalies)
            self.pcap_files_processed += 1
        
        # Process text files
        for text_file in text_files:
            print(f"\n📁 Processing TEXT: {os.path.basename(text_file)}")
            anomalies = self.analyze_text_file(text_file)
            if anomalies:
                all_anomalies.extend(anomalies)
            self.text_files_processed += 1
        
        self.total_files_processed = len(files)
        self.total_anomalies_found = len(all_anomalies)
        
        # Generate summary report
        self.generate_summary_report(folder_path, all_anomalies)
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze single PCAP file"""
        try:
            packets = self.parse_pcap_basic(pcap_file)
            
            if not packets:
                print("  No DU-RU packets found")
                return []
            
            print(f"  Extracted {len(packets)} DU-RU packets")
            
            features, packet_metadata = self.extract_pcap_features_basic(packets)
            
            if len(features) < 5:
                print("  Insufficient data for ML analysis")
                return []
            
            # Apply ML algorithms
            features_array = np.array(features)
            features_scaled = self.scaler.fit_transform(features_array)
            
            iso_predictions = self.isolation_forest.fit_predict(features_scaled)
            dbscan_labels = self.dbscan.fit_predict(features_scaled)
            svm_predictions = self.one_class_svm.fit_predict(features_scaled)
            lof_predictions = self.lof.fit_predict(features_scaled)
            
            anomalies = self.find_ensemble_anomalies(
                iso_predictions, dbscan_labels, svm_predictions, lof_predictions
            )
            
            print(f"  Found {len(anomalies)} anomalous time windows")
            
            # Create anomaly records
            anomaly_records = []
            for idx in anomalies:
                if idx < len(packet_metadata):
                    window_info = packet_metadata[idx]
                    all_packets = window_info['du_packets'] + window_info['ru_packets']
                    line_number = min(pkt['packet_num'] for pkt in all_packets) if all_packets else idx + 1
                    
                    anomaly_records.append({
                        'file': pcap_file,
                        'file_type': 'PCAP',
                        'line_number': line_number,
                        'anomaly_type': 'DU-RU Communication',
                        'details': self.analyze_pcap_anomaly_details(window_info, features[idx]),
                        'timestamp': window_info['window_time']
                    })
            
            return anomaly_records
            
        except Exception as e:
            print(f"  PCAP analysis error: {e}")
            return []
    
    def analyze_text_file(self, text_file):
        """Analyze single text file"""
        try:
            events = self.parse_ue_events_from_text(text_file)
            
            if not events:
                print("  No UE events found")
                return []
            
            print(f"  Extracted {len(events)} UE events")
            
            results = self.analyze_ue_event_patterns(events)
            
            print(f"  Found {results['anomalous_ues']} anomalous UEs")
            
            # Create anomaly records
            anomaly_records = []
            if 'anomalous_indices' in results and 'ue_metadata' in results:
                for idx in results['anomalous_indices']:
                    if idx < len(results['ue_metadata']):
                        ue_info = results['ue_metadata'][idx]
                        ue_events = ue_info['events']
                        
                        anomaly_records.append({
                            'file': text_file,
                            'file_type': 'TEXT',
                            'line_number': ue_events[0]['line_number'],
                            'anomaly_type': 'UE Event Pattern',
                            'details': self.analyze_ue_anomaly_details(ue_info),
                            'ue_id': ue_info['ue_id']
                        })
            
            return anomaly_records
            
        except Exception as e:
            print(f"  Text analysis error: {e}")
            return []
    
    def parse_pcap_basic(self, pcap_file):
        """Basic PCAP parsing"""
        packets = []
        
        try:
            with open(pcap_file, 'rb') as f:
                global_header = f.read(24)
                if len(global_header) < 24:
                    return []
                
                magic = struct.unpack('I', global_header[:4])[0]
                if magic not in [0xa1b2c3d4, 0xd4c3b2a1]:
                    return []
                
                packet_num = 0
                
                while True:
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    ts_sec, ts_usec, caplen, origlen = struct.unpack('IIII', packet_header)
                    timestamp = ts_sec + ts_usec / 1000000.0
                    
                    packet_data = f.read(caplen)
                    if len(packet_data) < caplen:
                        break
                    
                    packet_num += 1
                    
                    if len(packet_data) >= 14:
                        dst_mac = packet_data[0:6].hex(':')
                        src_mac = packet_data[6:12].hex(':')
                        
                        if (src_mac.lower() in [self.DU_MAC.lower(), self.RU_MAC.lower()] and
                            dst_mac.lower() in [self.DU_MAC.lower(), self.RU_MAC.lower()]):
                            
                            packet_info = {
                                'packet_num': packet_num,
                                'timestamp': timestamp,
                                'size': caplen,
                                'src_mac': src_mac.lower(),
                                'dst_mac': dst_mac.lower(),
                                'direction': 'DU_TO_RU' if src_mac.lower() == self.DU_MAC.lower() else 'RU_TO_DU'
                            }
                            packets.append(packet_info)
                
        except Exception as e:
            return []
        
        return packets
    
    def extract_pcap_features_basic(self, packets):
        """Extract basic features from PCAP packets"""
        features = []
        packet_metadata = []
        
        time_windows = {}
        
        for packet in packets:
            timestamp = packet['timestamp']
            time_window = int(timestamp * 10) / 10
            
            if time_window not in time_windows:
                time_windows[time_window] = {'du_packets': [], 'ru_packets': []}
            
            if packet['direction'] == 'DU_TO_RU':
                time_windows[time_window]['du_packets'].append(packet)
            else:
                time_windows[time_window]['ru_packets'].append(packet)
        
        for window_time, window_data in time_windows.items():
            du_packets = window_data['du_packets']
            ru_packets = window_data['ru_packets']
            
            if not du_packets and not ru_packets:
                continue
            
            window_features = self.calculate_basic_window_features(du_packets, ru_packets)
            if window_features:
                features.append(window_features)
                packet_metadata.append({
                    'window_time': window_time,
                    'du_packets': du_packets,
                    'ru_packets': ru_packets,
                    'packet_count': len(du_packets) + len(ru_packets)
                })
        
        return features, packet_metadata
    
    def calculate_basic_window_features(self, du_packets, ru_packets):
        """Calculate basic features for a time window"""
        du_count = len(du_packets)
        ru_count = len(ru_packets)
        
        communication_ratio = ru_count / du_count if du_count > 0 else 0
        missing_responses = max(0, du_count - ru_count)
        
        all_packets = du_packets + ru_packets
        if len(all_packets) > 1:
            timestamps = [pkt['timestamp'] for pkt in all_packets]
            timestamps.sort()
            inter_arrival_times = np.diff(timestamps)
            avg_inter_arrival = np.mean(inter_arrival_times)
            jitter = np.std(inter_arrival_times)
            max_gap = np.max(inter_arrival_times)
            min_gap = np.min(inter_arrival_times)
        else:
            avg_inter_arrival = jitter = max_gap = min_gap = 0
        
        estimated_response_time = 0
        response_violations = 0
        if du_packets and ru_packets:
            for du_pkt in du_packets:
                for ru_pkt in ru_packets:
                    if ru_pkt['timestamp'] > du_pkt['timestamp']:
                        resp_time = (ru_pkt['timestamp'] - du_pkt['timestamp']) * 1000000
                        estimated_response_time = max(estimated_response_time, resp_time)
                        if resp_time > 100:
                            response_violations += 1
                        break
        
        packet_sizes = [pkt['size'] for pkt in all_packets]
        if packet_sizes:
            avg_size = np.mean(packet_sizes)
            size_variance = np.var(packet_sizes)
        else:
            avg_size = size_variance = 0
        
        return [
            du_count, ru_count, communication_ratio, missing_responses,
            avg_inter_arrival, jitter, max_gap, min_gap,
            estimated_response_time, response_violations,
            avg_size, size_variance
        ]
    
    def parse_ue_events_from_text(self, text_file):
        """Parse UE events from text file"""
        events = []
        line_number = 0
        
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
                    
                    timestamp = self._extract_timestamp(line_lower) or line_number * 0.001
                    ue_id = self._extract_ue_identifier(line_lower) or f'ue_{line_number}'
                    cell_id = self._extract_cell_info(line_lower) or 'unknown'
                    
                    event_type = None
                    for event_name, patterns in event_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, line_lower, re.IGNORECASE):
                                event_type = event_name
                                break
                        if event_type:
                            break
                    
                    cause_code = self._extract_cause_code(line_lower)
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
            return []
        
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
        
        ue_patterns = defaultdict(list)
        for event in events:
            ue_patterns[event['ue_id']].append(event)
        
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
        
        features_array = np.array(ue_features)
        features_scaled = self.scaler.fit_transform(features_array)
        
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
        """Extract features for UE analysis"""
        if len(ue_events) < 2:
            return None
        
        event_types = [event['event_type'] for event in ue_events]
        event_counts = Counter(event_types)
        
        timestamps = [event['timestamp'] for event in ue_events]
        time_diffs = np.diff(timestamps)
        
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
    
    def find_ensemble_anomalies(self, iso_pred, dbscan_labels, svm_pred, lof_pred):
        """Find high-confidence anomalies using ensemble voting"""
        anomalies = []
        total_samples = len(iso_pred)
        
        for i in range(total_samples):
            votes = 0
            if iso_pred[i] == -1: votes += 1
            if dbscan_labels[i] == -1: votes += 1
            if svm_pred[i] == -1: votes += 1
            if lof_pred[i] == -1: votes += 1
            
            if votes >= 2:
                anomalies.append(i)
        
        return anomalies
    
    def analyze_pcap_anomaly_details(self, window_info, features):
        """Analyze PCAP anomaly details"""
        du_count, ru_count, comm_ratio, missing_resp = features[:4]
        
        issues = []
        if missing_resp > 0:
            issues.append(f"Missing Responses: {int(missing_resp)} DU packets without RU replies")
        if comm_ratio < 0.8 and du_count > 0:
            issues.append(f"Poor Communication Ratio: {comm_ratio:.2f} (expected > 0.8)")
        
        return issues if issues else ["Statistical deviation from normal DU-RU patterns"]
    
    def analyze_ue_anomaly_details(self, ue_info):
        """Analyze UE anomaly details"""
        ue_events = ue_info['events']
        event_types = [event['event_type'] for event in ue_events]
        event_counts = Counter(event_types)
        
        attach_requests = event_counts.get('attach_request', 0)
        attach_accepts = event_counts.get('attach_accept', 0)
        detach_requests = event_counts.get('detach_request', 0)
        failures = event_counts.get('context_failure', 0)
        
        issues = []
        if attach_requests > attach_accepts + 1:
            issues.append(f"Failed Attach Procedures: {attach_requests - attach_accepts} incomplete")
        if failures > 0:
            issues.append(f"Context Failures: {failures} detected")
        if detach_requests == 0 and attach_requests > 0:
            issues.append("Missing Detach Events: UE may have unexpectedly disconnected")
        
        return issues if issues else ["Abnormal UE Event Pattern"]
    
    def generate_summary_report(self, folder_path, all_anomalies):
        """Generate comprehensive summary report"""
        print(f"\n\n" + "=" * 80)
        print("COMPREHENSIVE L1 NETWORK ANALYSIS SUMMARY REPORT")
        print("=" * 80)
        
        # Header Information
        analysis_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"📅 Analysis Date: {analysis_time}")
        print(f"📁 Target Folder: {os.path.abspath(folder_path)}")
        print(f"🖥️  System: Unified L1 Anomaly Detection with ML Ensemble")
        
        # Processing Statistics
        print(f"\n" + "🔢 PROCESSING STATISTICS".ljust(50, '='))
        print(f"📊 Total Files Processed: {self.total_files_processed}")
        print(f"   ├─ PCAP Files: {self.pcap_files_processed}")
        print(f"   └─ Text Files: {self.text_files_processed}")
        
        if not all_anomalies:
            print(f"\n" + "✅ ANALYSIS COMPLETE - NO ANOMALIES DETECTED".ljust(50, '='))
            print("🎯 RESULT: All network files appear to be functioning normally")
            print("📈 NETWORK STATUS: HEALTHY")
            print("🔒 FRONTHAUL STATUS: No DU-RU communication issues detected")
            print("📱 UE BEHAVIOR: No abnormal attachment/detachment patterns")
            return
        
        # Critical Alert
        print(f"\n" + "🚨 CRITICAL NETWORK ANOMALIES DETECTED".ljust(50, '='))
        print(f"⚠️  TOTAL ANOMALIES FOUND: {self.total_anomalies_found}")
        print(f"🔴 NETWORK STATUS: REQUIRES ATTENTION")
        
        # Anomaly Breakdown
        pcap_anomalies = [a for a in all_anomalies if a['file_type'] == 'PCAP']
        text_anomalies = [a for a in all_anomalies if a['file_type'] == 'TEXT']
        
        print(f"\n" + "📈 ANOMALY STATISTICS".ljust(50, '='))
        print(f"🔍 PCAP Communication Anomalies: {len(pcap_anomalies)}")
        print(f"📱 UE Event Anomalies: {len(text_anomalies)}")
        
        if pcap_anomalies:
            print(f"   ⚡ DU-RU Fronthaul Issues: {len(pcap_anomalies)} detected")
        if text_anomalies:
            print(f"   📶 UE Mobility Issues: {len(text_anomalies)} detected")
        
        # File-by-File Breakdown
        print(f"\n" + "📋 DETAILED ANOMALY BREAKDOWN".ljust(50, '='))
        
        file_anomalies = defaultdict(list)
        for anomaly in all_anomalies:
            file_name = os.path.basename(anomaly['file'])
            file_anomalies[file_name].append(anomaly)
        
        for i, (file_name, anomalies) in enumerate(file_anomalies.items(), 1):
            print(f"\n📄 [{i}] FILE: {file_name}")
            print(f"    Type: {anomalies[0]['file_type']} | Anomalies: {len(anomalies)}")
            
            # Show critical anomalies
            for j, anomaly in enumerate(anomalies[:2], 1):  # Show first 2 per file
                print(f"\n    🔍 ANOMALY #{j}: LINE {anomaly['line_number']}")
                print(f"    ┌─ Type: {anomaly['anomaly_type']}")
                print(f"    ├─ *** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
                print(f"    ├─ DU MAC: {self.DU_MAC}")
                print(f"    ├─ RU MAC: {self.RU_MAC}")
                
                if 'ue_id' in anomaly:
                    print(f"    ├─ UE ID: {anomaly['ue_id']}")
                
                print(f"    └─ Issues Detected:")
                for detail in anomaly['details']:
                    print(f"       • {detail}")
            
            if len(anomalies) > 2:
                print(f"    📋 ... and {len(anomalies) - 2} additional anomalies")
        
        # Severity Analysis
        print(f"\n" + "⚠️  SEVERITY ASSESSMENT".ljust(50, '='))
        
        critical_count = len([a for a in all_anomalies if 'Missing Responses' in str(a['details']) or 'Context Failures' in str(a['details'])])
        medium_count = len([a for a in all_anomalies if 'Poor Communication' in str(a['details']) or 'Missing Detach' in str(a['details'])])
        low_count = self.total_anomalies_found - critical_count - medium_count
        
        if critical_count > 0:
            print(f"🔴 CRITICAL: {critical_count} anomalies (Immediate attention required)")
        if medium_count > 0:
            print(f"🟡 MEDIUM: {medium_count} anomalies (Investigation recommended)")
        if low_count > 0:
            print(f"🟢 LOW: {low_count} anomalies (Monitor and review)")
        
        # Network Health Summary
        print(f"\n" + "🏥 NETWORK HEALTH ASSESSMENT".ljust(50, '='))
        
        if critical_count > 0:
            print("🔴 NETWORK STATUS: CRITICAL - Immediate intervention required")
            print("⚡ FRONTHAUL: Multiple DU-RU communication failures detected")
        elif medium_count > 0:
            print("🟡 NETWORK STATUS: WARNING - Performance degradation detected")
            print("⚡ FRONTHAUL: Some communication issues present")
        else:
            print("🟢 NETWORK STATUS: STABLE - Minor issues detected")
            print("⚡ FRONTHAUL: Generally functioning within parameters")
        
        # Recommended Actions
        print(f"\n" + "🔧 IMMEDIATE ACTION PLAN".ljust(50, '='))
        
        actions = []
        if pcap_anomalies:
            actions.extend([
                "1. 🔍 INSPECT DU-RU physical connections and cable integrity",
                "2. ⚡ CHECK fronthaul timing synchronization (target: <100μs)",
                "3. 📊 MONITOR packet loss rates and communication ratios"
            ])
        
        if text_anomalies:
            actions.extend([
                f"{len(actions)+1}. 📱 INVESTIGATE UE attachment failure patterns",
                f"{len(actions)+2}. 🔄 REVIEW context setup procedures and timeouts",
                f"{len(actions)+3}. 📡 ANALYZE mobility management and handover processes"
            ])
        
        actions.extend([
            f"{len(actions)+1}. 📈 ESTABLISH continuous monitoring for these anomaly patterns",
            f"{len(actions)+2}. 🔄 RE-RUN analysis after implementing fixes",
            f"{len(actions)+3}. 📋 DOCUMENT findings and maintain incident log"
        ])
        
        for action in actions[:6]:  # Show top 6 actions
            print(f"   {action}")
        
        # Technical Summary
        print(f"\n" + "🔬 TECHNICAL SUMMARY".ljust(50, '='))
        print(f"🤖 ML Algorithms: Isolation Forest, DBSCAN, One-Class SVM, LOF")
        print(f"🎯 Detection Method: Ensemble voting (≥2 algorithms for high confidence)")
        print(f"📊 Analysis Scope: DU-RU communication + UE mobility patterns")
        print(f"🔍 MAC Addresses: DU={self.DU_MAC}, RU={self.RU_MAC}")
        
        # File Save Information
        report_file = os.path.join(folder_path, "anomaly_analysis_report.txt")
        self.save_detailed_report(report_file, folder_path, all_anomalies)
        
        print(f"\n" + "💾 REPORT STORAGE".ljust(50, '='))
        print(f"📄 Detailed report saved to: {report_file}")
        print(f"📊 Console summary displayed above")
        print(f"🔄 Use saved report for detailed technical analysis")
        
        print(f"\n" + "=" * 80)
        print("✅ COMPREHENSIVE L1 NETWORK ANALYSIS COMPLETED")
        print("=" * 80)
    
    def save_detailed_report(self, report_file, folder_path, all_anomalies):
        """Save detailed report to file"""
        try:
            with open(report_file, 'w') as f:
                f.write("L1 NETWORK ANOMALY ANALYSIS REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Folder: {folder_path}\n")
                f.write(f"Files Processed: {self.total_files_processed}\n")
                f.write(f"Anomalies Found: {self.total_anomalies_found}\n\n")
                
                for anomaly in all_anomalies:
                    f.write(f"ANOMALY: {os.path.basename(anomaly['file'])}\n")
                    f.write(f"Line: {anomaly['line_number']}\n")
                    f.write(f"Type: {anomaly['anomaly_type']}\n")
                    f.write(f"File Type: {anomaly['file_type']}\n")
                    
                    if 'ue_id' in anomaly:
                        f.write(f"UE ID: {anomaly['ue_id']}\n")
                    
                    f.write("Issues:\n")
                    for detail in anomaly['details']:
                        f.write(f"  - {detail}\n")
                    f.write("\n")
        except:
            pass

def main():
    if len(sys.argv) != 2:
        print("FOLDER-BASED L1 ANOMALY DETECTION SYSTEM")
        print("=" * 50)
        print("Usage: python folder_anomaly_analyzer.py <folder_path>")
        print()
        print("Description:")
        print("• Automatically processes all PCAP and text files in folder")
        print("• Detects DU-RU communication failures and UE anomalies")
        print("• Generates comprehensive summary report")
        print()
        print("Example:")
        print("  python folder_anomaly_analyzer.py /path/to/network/files")
        print("  python folder_anomaly_analyzer.py ./network_data")
        print()
        print("Supported files:")
        print("• PCAP files: .pcap, .cap, .pcapng")
        print("• Text files: .txt, .log (HDF5-converted)")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    
    # Initialize and run folder analysis
    analyzer = FolderAnomalyAnalyzer()
    analyzer.process_folder(folder_path)
    
    print(f"\n✅ FOLDER ANALYSIS COMPLETE")
    print("All network files have been processed and analyzed.")

if __name__ == "__main__":
    main()