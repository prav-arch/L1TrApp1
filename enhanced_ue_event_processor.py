#!/usr/bin/env python3
"""
Enhanced UE Event Processor - Dual Format Support
Handles both PCAP files and HDF5-converted text for UE Attach/Detach events
Integrates with hybrid supervised+unsupervised ML training system
"""

import os
import re
import json
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union
import warnings
warnings.filterwarnings('ignore')

# Try to import PCAP processing libraries
try:
    from scapy.all import rdpcap, IP, UDP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available - PCAP processing will be limited")

class UEEventProcessor:
    def __init__(self):
        self.ue_event_patterns = {
            # RRC Connection patterns
            'rrc_connection_request': r'RRC.*Connection.*Request|RRCConnectionRequest',
            'rrc_connection_setup': r'RRC.*Connection.*Setup|RRCConnectionSetup',
            'rrc_connection_release': r'RRC.*Connection.*Release|RRCConnectionRelease',
            
            # Attach/Detach patterns
            'attach_request': r'Attach.*Request|ATTACH_REQUEST|EMM.*Attach',
            'attach_complete': r'Attach.*Complete|ATTACH_COMPLETE|EMM.*Attach.*Complete',
            'detach_request': r'Detach.*Request|DETACH_REQUEST|EMM.*Detach',
            'detach_accept': r'Detach.*Accept|DETACH_ACCEPT|EMM.*Detach.*Accept',
            
            # Handover patterns
            'handover_request': r'Handover.*Request|HO.*Request|X2.*Handover',
            'handover_complete': r'Handover.*Complete|HO.*Complete|Handover.*Success',
            'handover_failure': r'Handover.*Fail|HO.*Fail|Handover.*Error',
            
            # TAU (Tracking Area Update) patterns
            'tau_request': r'TAU.*Request|Tracking.*Area.*Update.*Request',
            'tau_complete': r'TAU.*Complete|Tracking.*Area.*Update.*Complete',
            
            # Measurement patterns (HDF5 text specific)
            'rsrp_measurement': r'RSRP[:\s]*(-?\d+\.?\d*)|rsrp[:\s]*(-?\d+\.?\d*)',
            'rsrq_measurement': r'RSRQ[:\s]*(-?\d+\.?\d*)|rsrq[:\s]*(-?\d+\.?\d*)',
            'sinr_measurement': r'SINR[:\s]*(-?\d+\.?\d*)|sinr[:\s]*(-?\d+\.?\d*)',
            'cell_id': r'Cell[_\s]*ID[:\s]*(\d+)|CellId[:\s]*(\d+)|PCI[:\s]*(\d+)',
            
            # Timing patterns
            'timing_advance': r'TA[:\s]*(\d+)|Timing.*Advance[:\s]*(\d+)',
            'timestamp': r'(\d{4}-\d{2}-\d{2}[\s\T]\d{2}:\d{2}:\d{2})|(\d{2}:\d{2}:\d{2}\.\d{3})'
        }
        
        self.ue_event_types = {
            'attach_procedure': ['attach_request', 'attach_complete'],
            'detach_procedure': ['detach_request', 'detach_accept'],
            'rrc_procedure': ['rrc_connection_request', 'rrc_connection_setup', 'rrc_connection_release'],
            'handover_procedure': ['handover_request', 'handover_complete', 'handover_failure'],
            'tau_procedure': ['tau_request', 'tau_complete'],
            'measurements': ['rsrp_measurement', 'rsrq_measurement', 'sinr_measurement']
        }
        
        print("Enhanced UE Event Processor initialized")
        print(f"PCAP processing available: {SCAPY_AVAILABLE}")
    
    def detect_file_format(self, file_path: str) -> str:
        """Auto-detect file format (PCAP, HDF5 text, or regular text)"""
        try:
            # Check file extension first
            _, ext = os.path.splitext(file_path.lower())
            
            if ext in ['.pcap', '.pcapng']:
                return 'pcap'
            
            # Check file content for format indicators
            with open(file_path, 'rb') as f:
                header = f.read(1024)
            
            # PCAP magic numbers
            pcap_magic = [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\x0a\x0d\x0d\x0a']
            for magic in pcap_magic:
                if header.startswith(magic):
                    return 'pcap'
            
            # Try to read as text
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2048)
                
                # HDF5 converted text indicators
                hdf5_indicators = [
                    'HDF5', 'h5dump', 'dataset', 'dataspace',
                    'RSRP', 'RSRQ', 'SINR', 'Cell_ID',
                    'measurement_report', 'ue_measurement'
                ]
                
                if any(indicator.lower() in content.lower() for indicator in hdf5_indicators):
                    return 'hdf5_text'
                
                return 'text'
                
            except:
                return 'unknown'
                
        except Exception as e:
            print(f"Error detecting file format for {file_path}: {e}")
            return 'unknown'
    
    def process_pcap_ue_events(self, pcap_file: str) -> Dict:
        """Process PCAP file for UE events"""
        if not SCAPY_AVAILABLE:
            print("Scapy not available - cannot process PCAP files")
            return {}
        
        try:
            print(f"Processing PCAP file: {pcap_file}")
            packets = rdpcap(pcap_file)
            
            ue_events = {
                'total_packets': len(packets),
                'rrc_events': [],
                'attach_events': [],
                'handover_events': [],
                'timing_events': [],
                'protocol_distribution': {},
                'ue_features': []
            }
            
            protocol_count = {}
            
            for i, packet in enumerate(packets):
                packet_info = {
                    'packet_number': i + 1,
                    'timestamp': float(packet.time) if hasattr(packet, 'time') else 0,
                    'size': len(packet),
                    'protocols': []
                }
                
                # Extract protocol information
                if IP in packet:
                    packet_info['protocols'].append('IP')
                    packet_info['src_ip'] = packet[IP].src
                    packet_info['dst_ip'] = packet[IP].dst
                
                if UDP in packet:
                    packet_info['protocols'].append('UDP')
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                
                if TCP in packet:
                    packet_info['protocols'].append('TCP')
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                
                # Count protocols
                for proto in packet_info['protocols']:
                    protocol_count[proto] = protocol_count.get(proto, 0) + 1
                
                # Extract payload for UE event analysis
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Search for UE events in payload
                    for event_type, pattern in self.ue_event_patterns.items():
                        matches = re.findall(pattern, payload, re.IGNORECASE)
                        if matches:
                            event_data = {
                                'packet_number': i + 1,
                                'timestamp': packet_info['timestamp'],
                                'event_type': event_type,
                                'matches': matches,
                                'payload_size': len(payload)
                            }
                            
                            # Categorize events
                            if 'rrc' in event_type:
                                ue_events['rrc_events'].append(event_data)
                            elif 'attach' in event_type or 'detach' in event_type:
                                ue_events['attach_events'].append(event_data)
                            elif 'handover' in event_type:
                                ue_events['handover_events'].append(event_data)
                            elif 'timing' in event_type or 'tau' in event_type:
                                ue_events['timing_events'].append(event_data)
                
                # Extract numerical features for ML
                features = self.extract_pcap_packet_features(packet_info)
                ue_events['ue_features'].append(features)
            
            ue_events['protocol_distribution'] = protocol_count
            
            print(f"PCAP Analysis Complete:")
            print(f"  Total packets: {len(packets)}")
            print(f"  RRC events: {len(ue_events['rrc_events'])}")
            print(f"  Attach/Detach events: {len(ue_events['attach_events'])}")
            print(f"  Handover events: {len(ue_events['handover_events'])}")
            
            return ue_events
            
        except Exception as e:
            print(f"Error processing PCAP file: {e}")
            return {}
    
    def process_hdf5_text_ue_events(self, text_file: str) -> Dict:
        """Process HDF5 converted text file for UE events"""
        try:
            print(f"Processing HDF5 text file: {text_file}")
            
            with open(text_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            ue_events = {
                'total_lines': len(lines),
                'measurements': [],
                'mobility_events': [],
                'cell_changes': [],
                'timing_events': [],
                'ue_features': []
            }
            
            current_timestamp = None
            cell_history = []
            
            for i, line in enumerate(lines):
                if not line.strip():
                    continue
                
                line_events = {}
                
                # Extract timestamp
                timestamp_match = re.search(self.ue_event_patterns['timestamp'], line)
                if timestamp_match:
                    current_timestamp = timestamp_match.group(1) or timestamp_match.group(2)
                
                # Extract measurements
                rsrp_match = re.search(self.ue_event_patterns['rsrp_measurement'], line)
                if rsrp_match:
                    rsrp_value = float(rsrp_match.group(1) or rsrp_match.group(2))
                    line_events['rsrp'] = rsrp_value
                
                rsrq_match = re.search(self.ue_event_patterns['rsrq_measurement'], line)
                if rsrq_match:
                    rsrq_value = float(rsrq_match.group(1) or rsrq_match.group(2))
                    line_events['rsrq'] = rsrq_value
                
                sinr_match = re.search(self.ue_event_patterns['sinr_measurement'], line)
                if sinr_match:
                    sinr_value = float(sinr_match.group(1) or sinr_match.group(2))
                    line_events['sinr'] = sinr_value
                
                # Extract cell information
                cell_match = re.search(self.ue_event_patterns['cell_id'], line)
                if cell_match:
                    cell_id = int(cell_match.group(1) or cell_match.group(2) or cell_match.group(3))
                    line_events['cell_id'] = cell_id
                    
                    # Track cell changes
                    if cell_history and cell_id != cell_history[-1]:
                        ue_events['cell_changes'].append({
                            'line_number': i + 1,
                            'timestamp': current_timestamp,
                            'old_cell': cell_history[-1],
                            'new_cell': cell_id
                        })
                    cell_history.append(cell_id)
                
                # Extract timing advance
                ta_match = re.search(self.ue_event_patterns['timing_advance'], line)
                if ta_match:
                    ta_value = int(ta_match.group(1) or ta_match.group(2))
                    line_events['timing_advance'] = ta_value
                
                # Search for mobility events
                for event_type, pattern in self.ue_event_patterns.items():
                    if event_type in ['attach_request', 'attach_complete', 'detach_request', 'handover_request']:
                        if re.search(pattern, line, re.IGNORECASE):
                            ue_events['mobility_events'].append({
                                'line_number': i + 1,
                                'timestamp': current_timestamp,
                                'event_type': event_type,
                                'line_content': line[:100]  # First 100 chars
                            })
                
                # Store measurements
                if any(key in line_events for key in ['rsrp', 'rsrq', 'sinr', 'cell_id']):
                    measurement = {
                        'line_number': i + 1,
                        'timestamp': current_timestamp,
                        **line_events
                    }
                    ue_events['measurements'].append(measurement)
                
                # Extract features for ML
                features = self.extract_hdf5_line_features(line, line_events, i)
                ue_events['ue_features'].append(features)
            
            print(f"HDF5 Text Analysis Complete:")
            print(f"  Total lines: {len(lines)}")
            print(f"  Measurements: {len(ue_events['measurements'])}")
            print(f"  Cell changes: {len(ue_events['cell_changes'])}")
            print(f"  Mobility events: {len(ue_events['mobility_events'])}")
            
            return ue_events
            
        except Exception as e:
            print(f"Error processing HDF5 text file: {e}")
            return {}
    
    def extract_pcap_packet_features(self, packet_info: Dict) -> List[float]:
        """Extract ML features from PCAP packet information"""
        features = [
            packet_info.get('size', 0),  # Packet size
            len(packet_info.get('protocols', [])),  # Number of protocols
            packet_info.get('src_port', 0) if 'src_port' in packet_info else 0,  # Source port
            packet_info.get('dst_port', 0) if 'dst_port' in packet_info else 0,  # Destination port
            1 if 'UDP' in packet_info.get('protocols', []) else 0,  # UDP flag
            1 if 'TCP' in packet_info.get('protocols', []) else 0,  # TCP flag
            packet_info.get('timestamp', 0) % 86400,  # Time of day in seconds
            len(str(packet_info.get('src_ip', ''))),  # Source IP length indicator
        ]
        
        # Pad to fixed size
        while len(features) < 15:
            features.append(0.0)
        
        return features[:15]
    
    def extract_hdf5_line_features(self, line: str, line_events: Dict, line_number: int) -> List[float]:
        """Extract ML features from HDF5 text line"""
        features = [
            len(line),  # Line length
            len(line.split()),  # Word count
            line_events.get('rsrp', -999) if 'rsrp' in line_events else -999,  # RSRP value
            line_events.get('rsrq', -999) if 'rsrq' in line_events else -999,  # RSRQ value
            line_events.get('sinr', -999) if 'sinr' in line_events else -999,  # SINR value
            line_events.get('cell_id', 0) if 'cell_id' in line_events else 0,  # Cell ID
            line_events.get('timing_advance', 0) if 'timing_advance' in line_events else 0,  # TA
            sum(1 for c in line if c.isdigit()),  # Digit count
            sum(1 for c in line if c.isalpha()),  # Alpha count
            line_number,  # Line position
        ]
        
        # Pad to fixed size
        while len(features) < 15:
            features.append(0.0)
        
        return features[:15]
    
    def detect_ue_anomalies(self, ue_events: Dict, file_format: str) -> List[Dict]:
        """Detect UE-specific anomalies based on extracted events"""
        anomalies = []
        
        if file_format == 'pcap':
            # PCAP-specific anomaly detection
            anomalies.extend(self.detect_pcap_ue_anomalies(ue_events))
        elif file_format == 'hdf5_text':
            # HDF5 text-specific anomaly detection
            anomalies.extend(self.detect_hdf5_ue_anomalies(ue_events))
        
        return anomalies
    
    def detect_pcap_ue_anomalies(self, ue_events: Dict) -> List[Dict]:
        """Detect anomalies in PCAP UE events"""
        anomalies = []
        
        # Incomplete attach procedures
        attach_requests = len([e for e in ue_events['attach_events'] if 'request' in e['event_type']])
        attach_completes = len([e for e in ue_events['attach_events'] if 'complete' in e['event_type']])
        
        if attach_requests > attach_completes:
            anomalies.append({
                'type': 'incomplete_attach_procedure',
                'description': f'Found {attach_requests} attach requests but only {attach_completes} completions',
                'severity': 'high',
                'confidence': 0.9
            })
        
        # Handover failures
        handover_requests = len([e for e in ue_events['handover_events'] if 'request' in e['event_type']])
        handover_failures = len([e for e in ue_events['handover_events'] if 'failure' in e['event_type']])
        
        if handover_failures > 0:
            failure_rate = handover_failures / max(handover_requests, 1)
            if failure_rate > 0.1:  # More than 10% failure rate
                anomalies.append({
                    'type': 'high_handover_failure_rate',
                    'description': f'Handover failure rate: {failure_rate:.2%}',
                    'severity': 'medium',
                    'confidence': 0.8
                })
        
        return anomalies
    
    def detect_hdf5_ue_anomalies(self, ue_events: Dict) -> List[Dict]:
        """Detect anomalies in HDF5 text UE events"""
        anomalies = []
        
        # Signal quality anomalies
        measurements = ue_events['measurements']
        if measurements:
            rsrp_values = [m['rsrp'] for m in measurements if 'rsrp' in m]
            if rsrp_values:
                avg_rsrp = np.mean(rsrp_values)
                if avg_rsrp < -120:  # Very poor signal
                    anomalies.append({
                        'type': 'poor_signal_quality',
                        'description': f'Average RSRP: {avg_rsrp:.1f} dBm (very poor)',
                        'severity': 'high',
                        'confidence': 0.85
                    })
        
        # Excessive cell changes
        cell_changes = len(ue_events['cell_changes'])
        if cell_changes > 10:  # More than 10 cell changes
            anomalies.append({
                'type': 'excessive_cell_changes',
                'description': f'Detected {cell_changes} cell changes (possible ping-pong)',
                'severity': 'medium',
                'confidence': 0.75
            })
        
        return anomalies
    
    def process_ue_file(self, file_path: str) -> Dict:
        """Main processing function - auto-detects format and processes accordingly"""
        print(f"\nProcessing UE event file: {os.path.basename(file_path)}")
        
        # Detect file format
        file_format = self.detect_file_format(file_path)
        print(f"Detected format: {file_format}")
        
        # Process based on format
        if file_format == 'pcap':
            ue_events = self.process_pcap_ue_events(file_path)
        elif file_format == 'hdf5_text':
            ue_events = self.process_hdf5_text_ue_events(file_path)
        elif file_format == 'text':
            # Fallback to HDF5 text processing for regular text files
            ue_events = self.process_hdf5_text_ue_events(file_path)
        else:
            print(f"Unsupported file format: {file_format}")
            return {}
        
        # Detect UE-specific anomalies
        anomalies = self.detect_ue_anomalies(ue_events, file_format)
        
        # Compile results
        results = {
            'file_path': file_path,
            'file_format': file_format,
            'processing_timestamp': datetime.now().isoformat(),
            'ue_events': ue_events,
            'anomalies': anomalies,
            'summary': {
                'total_anomalies': len(anomalies),
                'high_severity': len([a for a in anomalies if a['severity'] == 'high']),
                'medium_severity': len([a for a in anomalies if a['severity'] == 'medium']),
                'features_extracted': len(ue_events.get('ue_features', []))
            }
        }
        
        return results

def main():
    """Main execution for standalone UE event processing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced UE Event Processor')
    parser.add_argument('input_path', help='PCAP file or HDF5 text file to process')
    parser.add_argument('--output', help='Output JSON file for results')
    parser.add_argument('--format', choices=['auto', 'pcap', 'hdf5_text'], default='auto',
                       help='Force specific file format')
    
    args = parser.parse_args()
    
    # Create processor
    processor = UEEventProcessor()
    
    # Process file
    results = processor.process_ue_file(args.input_path)
    
    if results:
        # Display summary
        print(f"\nUE EVENT PROCESSING SUMMARY")
        print(f"=" * 50)
        print(f"File: {os.path.basename(args.input_path)}")
        print(f"Format: {results['file_format']}")
        print(f"Total anomalies: {results['summary']['total_anomalies']}")
        print(f"High severity: {results['summary']['high_severity']}")
        print(f"Medium severity: {results['summary']['medium_severity']}")
        print(f"Features extracted: {results['summary']['features_extracted']}")
        
        # Show detected anomalies
        if results['anomalies']:
            print(f"\nDETECTED ANOMALIES:")
            for i, anomaly in enumerate(results['anomalies'], 1):
                print(f"  {i}. {anomaly['type']}: {anomaly['description']} "
                      f"(Severity: {anomaly['severity']}, Confidence: {anomaly['confidence']:.2f})")
        
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")
    
    else:
        print("Processing failed - no results generated")

if __name__ == "__main__":
    main()