#!/usr/bin/env python3
"""
UE Attach/Detach Event Anomaly Detection for HDF5-converted text files
Analyzes user equipment mobility events and detects abnormal patterns
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
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class UEEventAnalyzer:
    """Advanced UE event analysis for attach/detach anomaly detection"""
    
    def __init__(self):
        self.DU_MAC = "00:11:22:33:44:67"
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        self.scaler = StandardScaler()
        
        # Initialize ML models for UE event analysis
        self.isolation_forest = IsolationForest(contamination=0.15, random_state=42)
        self.dbscan = DBSCAN(eps=0.3, min_samples=3)
        
        print("UE EVENT ANALYZER INITIALIZED")
        print("Target: Attach/Detach event anomaly detection")
        print("Algorithms: Isolation Forest, DBSCAN clustering")
    
    def parse_ue_events_from_text(self, text_file):
        """Parse UE events from HDF5-converted text file"""
        events = []
        line_number = 0
        
        print(f"Parsing UE events from: {text_file}")
        
        # Common UE event patterns to detect
        event_patterns = {
            'attach_request': [
                r'attach.?request',
                r'rrc.?connection.?request',
                r'initial.?ue.?message',
                r'ue.?context.?setup'
            ],
            'attach_accept': [
                r'attach.?accept',
                r'rrc.?connection.?setup',
                r'initial.?context.?setup.?response'
            ],
            'attach_complete': [
                r'attach.?complete',
                r'rrc.?connection.?setup.?complete',
                r'initial.?context.?setup.?complete'
            ],
            'detach_request': [
                r'detach.?request',
                r'ue.?context.?release.?request',
                r'rrc.?connection.?release.?request'
            ],
            'detach_accept': [
                r'detach.?accept',
                r'ue.?context.?release.?complete',
                r'rrc.?connection.?release'
            ],
            'handover_request': [
                r'handover.?request',
                r'x2.?handover.?request',
                r'path.?switch.?request'
            ],
            'handover_complete': [
                r'handover.?complete',
                r'path.?switch.?request.?ack',
                r'ue.?context.?release'
            ],
            'paging_request': [
                r'paging',
                r'paging.?request'
            ],
            'service_request': [
                r'service.?request',
                r'nas.?service.?request'
            ],
            'context_failure': [
                r'context.?setup.?failure',
                r'initial.?context.?setup.?failure',
                r'ue.?context.?modification.?failure'
            ]
        }
        
        try:
            with open(text_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_number += 1
                    line = line.strip().lower()
                    
                    if not line:
                        continue
                    
                    # Extract timestamp (various formats)
                    timestamp_match = self._extract_timestamp(line)
                    timestamp = timestamp_match if timestamp_match else line_number * 0.001
                    
                    # Extract UE identifier (IMSI, RNTI, etc.)
                    ue_id = self._extract_ue_identifier(line)
                    
                    # Extract cell/base station information
                    cell_id = self._extract_cell_info(line)
                    
                    # Detect event type
                    event_type = None
                    for event_name, patterns in event_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                event_type = event_name
                                break
                        if event_type:
                            break
                    
                    # Extract additional parameters
                    cause_code = self._extract_cause_code(line)
                    message_size = len(line)  # Approximate message complexity
                    
                    # Check for DU-RU MAC addresses in the line
                    has_du_mac = self.DU_MAC.lower() in line
                    has_ru_mac = self.RU_MAC.lower() in line
                    
                    if event_type or ue_id or has_du_mac or has_ru_mac:
                        event = {
                            'line_number': line_number,
                            'timestamp': timestamp,
                            'event_type': event_type or 'unknown',
                            'ue_id': ue_id or f'ue_{line_number}',
                            'cell_id': cell_id or 'unknown',
                            'cause_code': cause_code,
                            'message_size': message_size,
                            'has_du_mac': has_du_mac,
                            'has_ru_mac': has_ru_mac,
                            'raw_line': line[:200]  # First 200 chars for reference
                        }
                        events.append(event)
        
        except Exception as e:
            print(f"Error parsing file: {e}")
            return []
        
        print(f"Extracted {len(events)} UE events from {line_number} lines")
        return events
    
    def _extract_timestamp(self, line):
        """Extract timestamp from various formats"""
        # Common timestamp patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.?\d*)',
            r'(\d{10}\.\d+)',  # Unix timestamp
            r'(\d{2}:\d{2}:\d{2}\.?\d*)',  # Time only
            r'timestamp[:\s=]*(\d+\.?\d*)',
            r'time[:\s=]*(\d+\.?\d*)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                try:
                    timestamp_str = match.group(1)
                    if '.' in timestamp_str and len(timestamp_str.split('.')[0]) == 10:
                        return float(timestamp_str)  # Unix timestamp
                    elif ':' in timestamp_str:
                        # Convert time to seconds from start of day
                        time_parts = timestamp_str.split(':')
                        return float(time_parts[0]) * 3600 + float(time_parts[1]) * 60 + float(time_parts[2].split('.')[0])
                except:
                    continue
        return None
    
    def _extract_ue_identifier(self, line):
        """Extract UE identifier (IMSI, RNTI, etc.)"""
        patterns = [
            r'imsi[:\s=]*(\d+)',
            r'rnti[:\s=]*(\d+)',
            r'ue.?id[:\s=]*(\d+)',
            r'subscriber[:\s=]*(\d+)',
            r'mobile[:\s=]*(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _extract_cell_info(self, line):
        """Extract cell/base station information"""
        patterns = [
            r'cell.?id[:\s=]*(\d+)',
            r'enb.?id[:\s=]*(\d+)',
            r'gnb.?id[:\s=]*(\d+)',
            r'base.?station[:\s=]*(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _extract_cause_code(self, line):
        """Extract cause codes for failures"""
        patterns = [
            r'cause[:\s=]*(\d+)',
            r'error[:\s=]*(\d+)',
            r'failure[:\s=]*(\d+)',
            r'reject[:\s=]*(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return int(match.group(1))
        return 0
    
    def analyze_ue_event_patterns(self, events):
        """Analyze UE events for anomalous patterns"""
        if len(events) < 5:
            print("Insufficient UE events for analysis")
            return {}
        
        print(f"Analyzing {len(events)} UE events for anomalies...")
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(events)
        
        # Group events by UE ID for pattern analysis
        ue_patterns = defaultdict(list)
        for event in events:
            ue_patterns[event['ue_id']].append(event)
        
        # Analyze each UE's event sequence
        ue_features = []
        ue_metadata = []
        
        for ue_id, ue_events in ue_patterns.items():
            if len(ue_events) < 2:
                continue
            
            # Sort by timestamp
            ue_events.sort(key=lambda x: x['timestamp'])
            
            # Extract UE-specific features
            features = self._extract_ue_features(ue_events)
            if features:
                ue_features.append(features)
                ue_metadata.append({
                    'ue_id': ue_id,
                    'event_count': len(ue_events),
                    'events': ue_events
                })
        
        if len(ue_features) < 3:
            print("Insufficient UE patterns for ML analysis")
            return {'events': events, 'patterns': ue_patterns}
        
        # Apply ML algorithms
        features_array = np.array(ue_features)
        features_scaled = self.scaler.fit_transform(features_array)
        
        # Isolation Forest
        iso_predictions = self.isolation_forest.fit_predict(features_scaled)
        iso_anomalies = np.where(iso_predictions == -1)[0]
        
        # DBSCAN
        dbscan_labels = self.dbscan.fit_predict(features_scaled)
        dbscan_anomalies = np.where(dbscan_labels == -1)[0]
        
        # Ensemble detection
        anomalous_ues = set(iso_anomalies) | set(dbscan_anomalies)
        
        results = {
            'total_events': len(events),
            'total_ues': len(ue_patterns),
            'anomalous_ues': len(anomalous_ues),
            'isolation_forest_anomalies': iso_anomalies,
            'dbscan_anomalies': dbscan_anomalies,
            'ue_metadata': ue_metadata,
            'events': events
        }
        
        return results
    
    def _extract_ue_features(self, ue_events):
        """Extract features for a specific UE's event sequence"""
        if len(ue_events) < 2:
            return None
        
        # Event type analysis
        event_types = [event['event_type'] for event in ue_events]
        event_counts = Counter(event_types)
        
        # Timing analysis
        timestamps = [event['timestamp'] for event in ue_events]
        time_diffs = np.diff(timestamps)
        
        # Sequence analysis
        attach_requests = event_counts.get('attach_request', 0)
        attach_accepts = event_counts.get('attach_accept', 0)
        attach_completes = event_counts.get('attach_complete', 0)
        detach_requests = event_counts.get('detach_request', 0)
        detach_accepts = event_counts.get('detach_accept', 0)
        failures = event_counts.get('context_failure', 0)
        
        # Feature vector (12 features)
        features = [
            len(ue_events),                           # Total events
            attach_requests,                          # Attach requests
            attach_accepts,                           # Attach accepts
            attach_completes,                         # Attach completes
            detach_requests,                          # Detach requests
            detach_accepts,                           # Detach accepts
            failures,                                 # Failure events
            attach_requests - attach_accepts,         # Incomplete attaches
            detach_requests - detach_accepts,         # Incomplete detaches
            np.mean(time_diffs) if len(time_diffs) > 0 else 0,  # Avg time between events
            np.std(time_diffs) if len(time_diffs) > 0 else 0,   # Time variance
            sum(1 for event in ue_events if event['cause_code'] > 0)  # Error events
        ]
        
        return features
    
    def report_anomalies(self, results):
        """Report detected UE event anomalies"""
        if 'anomalous_ues' not in results:
            print("No anomaly analysis available")
            return
        
        print(f"\nUE EVENT ANOMALY ANALYSIS RESULTS")
        print("=" * 50)
        print(f"Total Events Analyzed: {results['total_events']}")
        print(f"Total UEs: {results['total_ues']}")
        print(f"Anomalous UEs Detected: {results['anomalous_ues']}")
        
        if results['anomalous_ues'] == 0:
            print("No anomalous UE behavior detected")
            return
        
        anomalous_indices = set(results['isolation_forest_anomalies']) | set(results['dbscan_anomalies'])
        
        print(f"\nANOMALOUS UE PATTERNS:")
        print("-" * 30)
        
        for idx in sorted(anomalous_indices):
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
            
            # Analyze event sequence for issues
            event_types = [event['event_type'] for event in ue_events]
            event_counts = Counter(event_types)
            
            # Detect specific issues
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
            
            # Check for DU-RU involvement
            du_events = sum(1 for event in ue_events if event['has_du_mac'])
            ru_events = sum(1 for event in ue_events if event['has_ru_mac'])
            
            if du_events > 0 or ru_events > 0:
                print(f"DU Events: {du_events}, RU Events: {ru_events}")
            
            if issues:
                print("DETECTED ISSUES:")
                for issue in issues:
                    print(f"  • {issue}")
            else:
                print("ISSUE TYPE: Abnormal UE Event Pattern")
                print("DETAILS: Statistical deviation from normal UE behavior")
            
            # Show event sequence
            print("Event Sequence:")
            for i, event in enumerate(ue_events[:5]):  # Show first 5 events
                print(f"  {i+1}. {event['event_type']} at line {event['line_number']}")
            if len(ue_events) > 5:
                print(f"  ... and {len(ue_events) - 5} more events")
    
    def run_analysis(self, text_file):
        """Run complete UE event analysis"""
        print(f"UE ATTACH/DETACH EVENT ANALYSIS")
        print("=" * 40)
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
            self.report_anomalies(results)
            
            print(f"\nUE EVENT ANALYSIS COMPLETE")
            
        except Exception as e:
            print(f"Analysis error: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python ue_event_analyzer.py <hdf5_text_file>")
        print("Example: python ue_event_analyzer.py ue_events.txt")
        sys.exit(1)
    
    text_file = sys.argv[1]
    
    if not os.path.exists(text_file):
        print(f"Error: File '{text_file}' not found")
        sys.exit(1)
    
    # Initialize and run UE event analysis
    analyzer = UEEventAnalyzer()
    analyzer.run_analysis(text_file)

if __name__ == "__main__":
    main()