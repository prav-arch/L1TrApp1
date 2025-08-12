#!/usr/bin/env python3
"""
Simple Anomaly Detection Runner for Log Folders
Analyzes PCAP files and log files in a directory to find network anomalies
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Import the existing anomaly detection modules
try:
    from folder_anomaly_analyzer_clickhouse import FolderAnomalyAnalyzer
    from unified_l1_analyzer import UnifiedL1Analyzer
except ImportError:
    print("Warning: Some analyzer modules not found. Using basic analysis.")

def analyze_folder_simple(folder_path):
    """Simple folder analysis without ML dependencies"""
    print(f"Analyzing folder: {folder_path}")
    
    if not os.path.exists(folder_path):
        print(f"ERROR: Folder not found: {folder_path}")
        return
    
    # Find all supported files
    supported_extensions = ['.pcap', '.cap', '.txt', '.log']
    files = []
    
    for root, dirs, filenames in os.walk(folder_path):
        for filename in filenames:
            if any(filename.lower().endswith(ext) for ext in supported_extensions):
                files.append(os.path.join(root, filename))
    
    if not files:
        print(f"ERROR: No supported files found in {folder_path}")
        print("   Supported formats: .pcap, .cap, .txt, .log")
        return
    
    print(f"Found {len(files)} files to analyze:")
    
    anomalies_found = []
    total_files = 0
    
    for file_path in files:
        print(f"\nAnalyzing: {os.path.basename(file_path)}")
        file_size = os.path.getsize(file_path)
        print(f"   Size: {file_size:,} bytes")
        
        # Basic anomaly detection based on file patterns
        file_anomalies = analyze_file_patterns(file_path)
        
        if file_anomalies:
            anomalies_found.extend(file_anomalies)
            print(f"   Found {len(file_anomalies)} anomalies")
        else:
            print("   No obvious anomalies detected")
        
        total_files += 1
    
    # Summary
    print(f"\nAnalysis Summary:")
    print(f"   Files analyzed: {total_files}")
    print(f"   Total anomalies: {len(anomalies_found)}")
    
    if anomalies_found:
        print(f"\nDetected Anomalies:")
        for i, anomaly in enumerate(anomalies_found[:10]):  # Show first 10
            print(f"   {i+1}. {anomaly['type']}: {anomaly['description']}")
            print(f"      File: {anomaly['source_file']}")
            if 'packet_number' in anomaly:
                print(f"      Packet: #{anomaly['packet_number']}")
            print()
    
    return anomalies_found

def analyze_file_patterns(file_path):
    """Analyze file for common anomaly patterns"""
    anomalies = []
    filename = os.path.basename(file_path)
    
    try:
        # Check file extension
        if file_path.lower().endswith('.pcap') or file_path.lower().endswith('.cap'):
            # PCAP file analysis
            anomalies.extend(analyze_pcap_basic(file_path))
        else:
            # Log file analysis
            anomalies.extend(analyze_log_basic(file_path))
            
    except Exception as e:
        print(f"   ⚠️  Error analyzing {filename}: {e}")
        
    return anomalies

def analyze_pcap_basic(file_path):
    """Basic PCAP analysis without scapy dependencies"""
    anomalies = []
    filename = os.path.basename(file_path)
    
    # Check for suspicious filename patterns
    suspicious_keywords = ['error', 'fail', 'timeout', 'drop', 'loss', 'violation', 'anomaly']
    
    if any(keyword in filename.lower() for keyword in suspicious_keywords):
        anomalies.append({
            'type': 'File Pattern Anomaly',
            'description': f'Suspicious filename pattern detected: {filename}',
            'source_file': filename,
            'packet_number': 1,
            'severity': 'medium',
            'timestamp': datetime.now().isoformat()
        })
    
    # Check file size (very small or very large files might be suspicious)
    file_size = os.path.getsize(file_path)
    if file_size < 1000:  # Very small PCAP
        anomalies.append({
            'type': 'Small PCAP File',
            'description': f'Unusually small PCAP file ({file_size} bytes)',
            'source_file': filename,
            'packet_number': 1,
            'severity': 'low',
            'timestamp': datetime.now().isoformat()
        })
    elif file_size > 100 * 1024 * 1024:  # Very large PCAP (>100MB)
        anomalies.append({
            'type': 'Large PCAP File',
            'description': f'Large PCAP file ({file_size:,} bytes) - may contain extensive traffic',
            'source_file': filename,
            'packet_number': 1,
            'severity': 'low',
            'timestamp': datetime.now().isoformat()
        })
    
    return anomalies

def analyze_log_basic(file_path):
    """Basic log file analysis"""
    anomalies = []
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        error_count = 0
        failure_count = 0
        timeout_count = 0
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Check for error patterns
            if any(word in line_lower for word in ['error', 'err', 'failed', 'fail']):
                error_count += 1
                if error_count <= 5:  # Report first 5 errors
                    anomalies.append({
                        'type': 'Error Pattern',
                        'description': f'Error detected in log: {line.strip()[:100]}...',
                        'source_file': filename,
                        'line_number': line_num,
                        'severity': 'high',
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Check for timeout patterns
            if any(word in line_lower for word in ['timeout', 'timed out', 'time out']):
                timeout_count += 1
                if timeout_count <= 3:  # Report first 3 timeouts
                    anomalies.append({
                        'type': 'Timeout Event',
                        'description': f'Timeout detected: {line.strip()[:100]}...',
                        'source_file': filename,
                        'line_number': line_num,
                        'severity': 'medium',
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Check for DU-RU communication issues
            if 'du' in line_lower and 'ru' in line_lower and any(word in line_lower for word in ['fail', 'error', 'timeout', 'drop']):
                anomalies.append({
                    'type': 'DU-RU Communication Issue',
                    'description': f'DU-RU communication problem: {line.strip()[:100]}...',
                    'source_file': filename,
                    'line_number': line_num,
                    'severity': 'critical',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Check for UE-related issues
            if any(word in line_lower for word in ['ue attach', 'ue detach', 'handover']) and any(word in line_lower for word in ['fail', 'error', 'timeout']):
                anomalies.append({
                    'type': 'UE Event Anomaly',
                    'description': f'UE event issue detected: {line.strip()[:100]}...',
                    'source_file': filename,
                    'line_number': line_num,
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat()
                })
        
        # Summary anomaly if too many errors
        if error_count > 10:
            anomalies.append({
                'type': 'High Error Rate',
                'description': f'High error rate detected: {error_count} errors in {len(lines)} lines',
                'source_file': filename,
                'severity': 'critical',
                'timestamp': datetime.now().isoformat()
            })
            
    except Exception as e:
        anomalies.append({
            'type': 'File Read Error',
            'description': f'Could not read log file: {str(e)}',
            'source_file': filename,
            'severity': 'medium',
            'timestamp': datetime.now().isoformat()
        })
    
    return anomalies

def run_advanced_analysis(folder_path):
    """Run advanced analysis using existing analyzers if available"""
    print(f"Running advanced analysis on: {folder_path}")
    
    try:
        # Try using the ClickHouse analyzer first
        analyzer = FolderAnomalyAnalyzer()
        results = analyzer.analyze_folder(folder_path)
        
        print(f"Advanced analysis completed")
        return results
        
    except Exception as e:
        print(f"WARNING: Advanced analyzer not available: {e}")
        print("Falling back to basic analysis...")
        return analyze_folder_simple(folder_path)

def save_results(anomalies, output_file):
    """Save anomaly results to JSON file"""
    try:
        results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_anomalies': len(anomalies),
            'anomalies': anomalies
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"Results saved to: {output_file}")
        
    except Exception as e:
        print(f"ERROR: Failed to save results: {e}")

def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(description='Analyze log folders for network anomalies')
    parser.add_argument('folder_path', help='Path to folder containing log files and PCAP files')
    parser.add_argument('--output', '-o', help='Output JSON file for results')
    parser.add_argument('--advanced', '-a', action='store_true', help='Use advanced ML analysis (requires trained models)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("L1 Network Anomaly Detection")
    print("=" * 40)
    
    # Validate folder path
    if not os.path.exists(args.folder_path):
        print(f"ERROR: Folder not found: {args.folder_path}")
        sys.exit(1)
    
    # Run analysis
    if args.advanced:
        anomalies = run_advanced_analysis(args.folder_path)
    else:
        anomalies = analyze_folder_simple(args.folder_path)
    
    # Save results if requested
    if args.output:
        save_results(anomalies, args.output)
    
    # Summary
    print(f"\nFinal Results:")
    print(f"   Total anomalies found: {len(anomalies) if anomalies else 0}")
    
    if anomalies:
        severity_counts = {}
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("   Severity breakdown:")
        for severity, count in severity_counts.items():
            print(f"     {severity}: {count}")

if __name__ == "__main__":
    main()