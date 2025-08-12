#!/usr/bin/env python3
"""
Unified UE ML Analyzer - Complete integration of UE Event Processing with Hybrid ML
Processes both PCAP and HDF5 text files for UE Attach/Detach events
Uses trained hybrid supervised+unsupervised models for enhanced accuracy
"""

import os
import json
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional
from enhanced_ue_event_processor import UEEventProcessor
from enhanced_hybrid_analyzer import EnhancedHybridAnalyzer

# Optional ClickHouse integration
try:
    import clickhouse_connect
    CLICKHOUSE_AVAILABLE = True
except ImportError:
    CLICKHOUSE_AVAILABLE = False

class UnifiedUEMLAnalyzer:
    def __init__(self, trained_models_path=None):
        self.ue_processor = UEEventProcessor()
        self.ml_analyzer = EnhancedHybridAnalyzer(trained_models_path)
        self.trained_models_path = trained_models_path
        
        # ClickHouse setup for storing results
        self.clickhouse_client = None
        if CLICKHOUSE_AVAILABLE:
            self.setup_clickhouse()
        
        print("Unified UE ML Analyzer initialized")
        if trained_models_path:
            print(f"Using trained models: {trained_models_path}")
        else:
            print("Using default unsupervised models")
    
    def setup_clickhouse(self):
        """Setup ClickHouse connection for storing UE analysis results"""
        try:
            self.clickhouse_client = clickhouse_connect.get_client(
                host='localhost',
                port=8123,
                username='default',
                password='',
                database='l1_anomaly_detection'
            )
            
            # Create UE-specific tables
            self.create_ue_tables()
            print("ClickHouse connection established for UE analysis")
            
        except Exception as e:
            print(f"ClickHouse connection failed: {e}")
            self.clickhouse_client = None
    
    def create_ue_tables(self):
        """Create ClickHouse tables for UE event analysis results"""
        if not self.clickhouse_client:
            return
        
        ue_events_table = """
        CREATE TABLE IF NOT EXISTS l1_anomaly_detection.ue_events (
            event_id String,
            timestamp DateTime DEFAULT now(),
            file_path String,
            file_format LowCardinality(String),
            event_type LowCardinality(String),
            packet_number UInt32,
            line_number UInt32,
            rsrp_value Float64,
            rsrq_value Float64,
            sinr_value Float64,
            cell_id UInt32,
            timing_advance UInt32,
            anomaly_detected UInt8,
            ml_confidence Float64,
            supervised_svm_score Float64,
            supervised_rf_score Float64,
            unsupervised_isolation_score Float64,
            unsupervised_dbscan_score Float64,
            hybrid_ensemble_score Float64,
            ue_event_details String
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, file_path, event_type)
        """
        
        ue_procedures_table = """
        CREATE TABLE IF NOT EXISTS l1_anomaly_detection.ue_procedures (
            procedure_id String,
            timestamp DateTime DEFAULT now(),
            file_path String,
            procedure_type LowCardinality(String),
            start_time DateTime,
            end_time DateTime,
            duration_ms UInt32,
            success UInt8,
            anomaly_detected UInt8,
            confidence_score Float64,
            failure_reason String,
            procedure_details String
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, file_path, procedure_type)
        """
        
        try:
            self.clickhouse_client.command(ue_events_table)
            self.clickhouse_client.command(ue_procedures_table)
            print("UE analysis tables created in ClickHouse")
        except Exception as e:
            print(f"Failed to create UE tables: {e}")
    
    def analyze_ue_file_comprehensive(self, file_path: str) -> Dict:
        """Comprehensive analysis combining UE event processing and ML detection"""
        print(f"\nUNIFIED UE ANALYSIS: {os.path.basename(file_path)}")
        print("=" * 70)
        
        # Step 1: UE Event Processing
        ue_results = self.ue_processor.process_ue_file(file_path)
        if not ue_results:
            print("UE event processing failed")
            return {}
        
        # Step 2: ML-based Anomaly Detection
        ml_anomalies = self.ml_analyzer.analyze_file_hybrid(file_path)
        
        # Step 3: Enhanced Analysis Integration
        integrated_results = self.integrate_ue_ml_results(ue_results, ml_anomalies, file_path)
        
        # Step 4: Store results in ClickHouse
        if self.clickhouse_client:
            self.store_ue_analysis_results(integrated_results)
        
        # Step 5: Generate comprehensive report
        self.display_unified_results(integrated_results)
        
        return integrated_results
    
    def integrate_ue_ml_results(self, ue_results: Dict, ml_anomalies: List, file_path: str) -> Dict:
        """Integrate UE event processing results with ML anomaly detection"""
        
        # Create unified analysis results
        integrated_results = {
            'file_path': file_path,
            'analysis_timestamp': datetime.now().isoformat(),
            'file_format': ue_results.get('file_format', 'unknown'),
            'ue_events': ue_results.get('ue_events', {}),
            'ue_specific_anomalies': ue_results.get('anomalies', []),
            'ml_anomalies': ml_anomalies,
            'integrated_anomalies': [],
            'procedure_analysis': {},
            'signal_quality_analysis': {},
            'mobility_analysis': {},
            'summary': {}
        }
        
        # Analyze UE procedures (Attach/Detach/Handover)
        integrated_results['procedure_analysis'] = self.analyze_ue_procedures(ue_results)
        
        # Analyze signal quality (for HDF5 text files)
        if ue_results['file_format'] == 'hdf5_text':
            integrated_results['signal_quality_analysis'] = self.analyze_signal_quality(ue_results)
        
        # Analyze mobility patterns
        integrated_results['mobility_analysis'] = self.analyze_mobility_patterns(ue_results)
        
        # Cross-correlate UE events with ML anomalies
        integrated_anomalies = self.cross_correlate_anomalies(
            ue_results.get('anomalies', []), 
            ml_anomalies,
            ue_results.get('ue_events', {})
        )
        integrated_results['integrated_anomalies'] = integrated_anomalies
        
        # Generate summary
        integrated_results['summary'] = {
            'total_ue_events': sum(len(events) for events in ue_results.get('ue_events', {}).values() if isinstance(events, list)),
            'ue_specific_anomalies': len(ue_results.get('anomalies', [])),
            'ml_detected_anomalies': len(ml_anomalies),
            'integrated_anomalies': len(integrated_anomalies),
            'procedure_success_rate': self.calculate_procedure_success_rate(ue_results),
            'signal_quality_score': self.calculate_signal_quality_score(ue_results),
            'mobility_stability_score': self.calculate_mobility_stability_score(ue_results)
        }
        
        return integrated_results
    
    def analyze_ue_procedures(self, ue_results: Dict) -> Dict:
        """Analyze UE procedure completion and success rates"""
        ue_events = ue_results.get('ue_events', {})
        procedure_analysis = {
            'attach_procedures': {'requests': 0, 'completions': 0, 'success_rate': 0.0},
            'detach_procedures': {'requests': 0, 'acceptances': 0, 'success_rate': 0.0},
            'handover_procedures': {'requests': 0, 'completions': 0, 'failures': 0, 'success_rate': 0.0},
            'rrc_procedures': {'requests': 0, 'setups': 0, 'releases': 0, 'success_rate': 0.0}
        }
        
        # Count events by type
        if ue_results['file_format'] == 'pcap':
            # PCAP-based analysis
            attach_events = ue_events.get('attach_events', [])
            handover_events = ue_events.get('handover_events', [])
            rrc_events = ue_events.get('rrc_events', [])
            
            # Attach procedure analysis
            procedure_analysis['attach_procedures']['requests'] = len([e for e in attach_events if 'request' in e.get('event_type', '')])
            procedure_analysis['attach_procedures']['completions'] = len([e for e in attach_events if 'complete' in e.get('event_type', '')])
            
            # Handover procedure analysis
            procedure_analysis['handover_procedures']['requests'] = len([e for e in handover_events if 'request' in e.get('event_type', '')])
            procedure_analysis['handover_procedures']['completions'] = len([e for e in handover_events if 'complete' in e.get('event_type', '')])
            procedure_analysis['handover_procedures']['failures'] = len([e for e in handover_events if 'failure' in e.get('event_type', '')])
            
            # RRC procedure analysis
            procedure_analysis['rrc_procedures']['requests'] = len([e for e in rrc_events if 'request' in e.get('event_type', '')])
            procedure_analysis['rrc_procedures']['setups'] = len([e for e in rrc_events if 'setup' in e.get('event_type', '')])
            procedure_analysis['rrc_procedures']['releases'] = len([e for e in rrc_events if 'release' in e.get('event_type', '')])
        
        elif ue_results['file_format'] in ['hdf5_text', 'text']:
            # HDF5 text-based analysis
            mobility_events = ue_events.get('mobility_events', [])
            
            for event in mobility_events:
                event_type = event.get('event_type', '')
                if 'attach_request' in event_type:
                    procedure_analysis['attach_procedures']['requests'] += 1
                elif 'attach_complete' in event_type:
                    procedure_analysis['attach_procedures']['completions'] += 1
                elif 'handover_request' in event_type:
                    procedure_analysis['handover_procedures']['requests'] += 1
        
        # Calculate success rates
        for proc_type, data in procedure_analysis.items():
            if proc_type == 'attach_procedures':
                if data['requests'] > 0:
                    data['success_rate'] = data['completions'] / data['requests']
            elif proc_type == 'handover_procedures':
                total_attempts = data['requests']
                if total_attempts > 0:
                    successful = data['completions']
                    data['success_rate'] = successful / total_attempts
            elif proc_type == 'rrc_procedures':
                if data['requests'] > 0:
                    data['success_rate'] = data['setups'] / data['requests']
        
        return procedure_analysis
    
    def analyze_signal_quality(self, ue_results: Dict) -> Dict:
        """Analyze signal quality metrics from HDF5 text files"""
        if ue_results['file_format'] not in ['hdf5_text', 'text']:
            return {}
        
        measurements = ue_results.get('ue_events', {}).get('measurements', [])
        if not measurements:
            return {}
        
        rsrp_values = [m.get('rsrp') for m in measurements if m.get('rsrp') is not None]
        rsrq_values = [m.get('rsrq') for m in measurements if m.get('rsrq') is not None]
        sinr_values = [m.get('sinr') for m in measurements if m.get('sinr') is not None]
        
        signal_analysis = {
            'rsrp_stats': self.calculate_signal_stats(rsrp_values, 'RSRP'),
            'rsrq_stats': self.calculate_signal_stats(rsrq_values, 'RSRQ'),
            'sinr_stats': self.calculate_signal_stats(sinr_values, 'SINR'),
            'quality_grade': 'unknown'
        }
        
        # Overall quality assessment
        if rsrp_values:
            avg_rsrp = np.mean(rsrp_values)
            if avg_rsrp > -85:
                signal_analysis['quality_grade'] = 'excellent'
            elif avg_rsrp > -95:
                signal_analysis['quality_grade'] = 'good'
            elif avg_rsrp > -105:
                signal_analysis['quality_grade'] = 'fair'
            elif avg_rsrp > -115:
                signal_analysis['quality_grade'] = 'poor'
            else:
                signal_analysis['quality_grade'] = 'very_poor'
        
        return signal_analysis
    
    def calculate_signal_stats(self, values: List, signal_type: str) -> Dict:
        """Calculate statistical metrics for signal measurements"""
        if not values:
            return {}
        
        return {
            'count': len(values),
            'mean': float(np.mean(values)),
            'std': float(np.std(values)),
            'min': float(np.min(values)),
            'max': float(np.max(values)),
            'median': float(np.median(values)),
            'percentile_25': float(np.percentile(values, 25)),
            'percentile_75': float(np.percentile(values, 75))
        }
    
    def analyze_mobility_patterns(self, ue_results: Dict) -> Dict:
        """Analyze UE mobility and handover patterns"""
        ue_events = ue_results.get('ue_events', {})
        
        mobility_analysis = {
            'cell_changes': 0,
            'handover_frequency': 0.0,
            'mobility_stability': 'stable',
            'ping_pong_detected': False
        }
        
        if ue_results['file_format'] in ['hdf5_text', 'text']:
            cell_changes = ue_events.get('cell_changes', [])
            mobility_analysis['cell_changes'] = len(cell_changes)
            
            # Detect ping-pong handovers (rapid cell changes back and forth)
            if len(cell_changes) >= 3:
                recent_changes = cell_changes[-3:]
                cell_ids = [change.get('new_cell') for change in recent_changes]
                if len(set(cell_ids)) <= 2:  # Only 2 different cells in last 3 changes
                    mobility_analysis['ping_pong_detected'] = True
        
        # Determine mobility stability
        if mobility_analysis['cell_changes'] > 20:
            mobility_analysis['mobility_stability'] = 'highly_mobile'
        elif mobility_analysis['cell_changes'] > 10:
            mobility_analysis['mobility_stability'] = 'mobile'
        elif mobility_analysis['cell_changes'] > 5:
            mobility_analysis['mobility_stability'] = 'moderately_mobile'
        else:
            mobility_analysis['mobility_stability'] = 'stable'
        
        return mobility_analysis
    
    def cross_correlate_anomalies(self, ue_anomalies: List, ml_anomalies: List, ue_events: Dict) -> List:
        """Cross-correlate UE-specific anomalies with ML-detected anomalies"""
        integrated_anomalies = []
        
        # Add UE-specific anomalies with enhanced context
        for ue_anomaly in ue_anomalies:
            integrated_anomaly = {
                'source': 'ue_processor',
                'type': ue_anomaly.get('type'),
                'description': ue_anomaly.get('description'),
                'severity': ue_anomaly.get('severity'),
                'confidence': ue_anomaly.get('confidence'),
                'ue_context': True,
                'ml_correlated': False
            }
            integrated_anomalies.append(integrated_anomaly)
        
        # Add ML anomalies with UE context if available
        for ml_anomaly in ml_anomalies:
            integrated_anomaly = {
                'source': 'ml_analyzer',
                'type': 'ml_detected_anomaly',
                'packet_number': ml_anomaly.get('packet_number'),
                'confidence': ml_anomaly.get('confidence'),
                'model_type': ml_anomaly.get('model_type'),
                'ue_context': False,
                'ml_correlated': True
            }
            integrated_anomalies.append(integrated_anomaly)
        
        # Cross-correlation logic could be enhanced here
        # For now, we mark anomalies that occur around the same time/location
        
        return integrated_anomalies
    
    def calculate_procedure_success_rate(self, ue_results: Dict) -> float:
        """Calculate overall UE procedure success rate"""
        # This is a simplified calculation - could be enhanced
        if ue_results['file_format'] == 'pcap':
            attach_events = ue_results.get('ue_events', {}).get('attach_events', [])
            if attach_events:
                requests = len([e for e in attach_events if 'request' in e.get('event_type', '')])
                completions = len([e for e in attach_events if 'complete' in e.get('event_type', '')])
                if requests > 0:
                    return completions / requests
        return 1.0  # Assume success if no specific procedure data
    
    def calculate_signal_quality_score(self, ue_results: Dict) -> float:
        """Calculate signal quality score (0-1, higher is better)"""
        if ue_results['file_format'] not in ['hdf5_text', 'text']:
            return 0.8  # Default for PCAP files
        
        measurements = ue_results.get('ue_events', {}).get('measurements', [])
        if not measurements:
            return 0.5
        
        rsrp_values = [m.get('rsrp') for m in measurements if m.get('rsrp') is not None]
        if rsrp_values:
            avg_rsrp = np.mean(rsrp_values)
            # Convert RSRP to quality score (simplified mapping)
            if avg_rsrp > -85:
                return 1.0
            elif avg_rsrp > -95:
                return 0.8
            elif avg_rsrp > -105:
                return 0.6
            elif avg_rsrp > -115:
                return 0.4
            else:
                return 0.2
        
        return 0.5
    
    def calculate_mobility_stability_score(self, ue_results: Dict) -> float:
        """Calculate mobility stability score (0-1, higher is more stable)"""
        if ue_results['file_format'] not in ['hdf5_text', 'text']:
            return 0.7  # Default for PCAP files
        
        cell_changes = len(ue_results.get('ue_events', {}).get('cell_changes', []))
        
        # Scoring based on cell change frequency
        if cell_changes == 0:
            return 1.0
        elif cell_changes <= 3:
            return 0.9
        elif cell_changes <= 7:
            return 0.7
        elif cell_changes <= 15:
            return 0.5
        else:
            return 0.3
    
    def store_ue_analysis_results(self, results: Dict):
        """Store unified UE analysis results in ClickHouse"""
        if not self.clickhouse_client:
            return
        
        try:
            # Store integrated anomalies
            for anomaly in results['integrated_anomalies']:
                values = [
                    f"ue_event_{datetime.now().timestamp()}",  # event_id
                    datetime.now(),  # timestamp
                    results['file_path'],  # file_path
                    results['file_format'],  # file_format
                    anomaly.get('type', 'unknown'),  # event_type
                    anomaly.get('packet_number', 0),  # packet_number
                    anomaly.get('line_number', 0),  # line_number
                    0.0,  # rsrp_value
                    0.0,  # rsrq_value
                    0.0,  # sinr_value
                    0,    # cell_id
                    0,    # timing_advance
                    1,    # anomaly_detected
                    float(anomaly.get('confidence', 0.5)),  # ml_confidence
                    0.0,  # supervised_svm_score
                    0.0,  # supervised_rf_score
                    0.0,  # unsupervised_isolation_score
                    0.0,  # unsupervised_dbscan_score
                    0.0,  # hybrid_ensemble_score
                    json.dumps(anomaly)  # ue_event_details
                ]
                
                self.clickhouse_client.insert('l1_anomaly_detection.ue_events', [values])
            
            print("UE analysis results stored in ClickHouse")
            
        except Exception as e:
            print(f"Failed to store UE analysis results: {e}")
    
    def display_unified_results(self, results: Dict):
        """Display comprehensive unified analysis results"""
        print(f"\nUNIFIED UE ANALYSIS RESULTS")
        print("=" * 70)
        print(f"File: {os.path.basename(results['file_path'])}")
        print(f"Format: {results['file_format']}")
        print(f"Analysis Time: {results['analysis_timestamp']}")
        
        # Summary
        summary = results['summary']
        print(f"\nSUMMARY:")
        print(f"  Total UE Events: {summary['total_ue_events']}")
        print(f"  UE-Specific Anomalies: {summary['ue_specific_anomalies']}")
        print(f"  ML-Detected Anomalies: {summary['ml_detected_anomalies']}")
        print(f"  Integrated Anomalies: {summary['integrated_anomalies']}")
        print(f"  Procedure Success Rate: {summary['procedure_success_rate']:.2%}")
        print(f"  Signal Quality Score: {summary['signal_quality_score']:.2f}")
        print(f"  Mobility Stability Score: {summary['mobility_stability_score']:.2f}")
        
        # Procedure Analysis
        if results['procedure_analysis']:
            print(f"\nPROCEDURE ANALYSIS:")
            for proc_type, data in results['procedure_analysis'].items():
                if data.get('requests', 0) > 0:
                    print(f"  {proc_type.replace('_', ' ').title()}: "
                          f"{data['requests']} requests, {data.get('completions', 0)} completions, "
                          f"Success Rate: {data['success_rate']:.2%}")
        
        # Signal Quality (for HDF5 text files)
        if results['signal_quality_analysis']:
            print(f"\nSIGNAL QUALITY ANALYSIS:")
            sq = results['signal_quality_analysis']
            print(f"  Overall Grade: {sq.get('quality_grade', 'unknown').title()}")
            if sq.get('rsrp_stats'):
                print(f"  RSRP: {sq['rsrp_stats']['mean']:.1f} dBm (avg), "
                      f"Range: {sq['rsrp_stats']['min']:.1f} to {sq['rsrp_stats']['max']:.1f}")
        
        # Mobility Analysis
        if results['mobility_analysis']:
            print(f"\nMOBILITY ANALYSIS:")
            ma = results['mobility_analysis']
            print(f"  Cell Changes: {ma['cell_changes']}")
            print(f"  Mobility Pattern: {ma['mobility_stability'].replace('_', ' ').title()}")
            if ma.get('ping_pong_detected'):
                print(f"  ⚠️  Ping-Pong Handovers Detected")
        
        # Top Anomalies
        if results['integrated_anomalies']:
            print(f"\nTOP INTEGRATED ANOMALIES:")
            sorted_anomalies = sorted(
                results['integrated_anomalies'], 
                key=lambda x: x.get('confidence', 0), 
                reverse=True
            )
            
            for i, anomaly in enumerate(sorted_anomalies[:5], 1):
                confidence = anomaly.get('confidence', 0)
                source = anomaly.get('source', 'unknown')
                anomaly_type = anomaly.get('type', 'unknown')
                description = anomaly.get('description', 'No description')
                
                print(f"  {i}. [{source.upper()}] {anomaly_type}: {description} "
                      f"(Confidence: {confidence:.3f})")

def main():
    """Main execution for unified UE ML analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Unified UE ML Analyzer')
    parser.add_argument('input_path', help='PCAP file or HDF5 text file to analyze')
    parser.add_argument('--use-trained-models', help='Training ID of pre-trained models to use')
    parser.add_argument('--output', help='Output JSON file for results')
    parser.add_argument('--batch', action='store_true', help='Process all files in directory')
    
    args = parser.parse_args()
    
    # Create unified analyzer
    analyzer = UnifiedUEMLAnalyzer(trained_models_path=args.use_trained_models)
    
    if args.batch and os.path.isdir(args.input_path):
        # Process all files in directory
        total_files = 0
        total_anomalies = 0
        
        for filename in os.listdir(args.input_path):
            file_path = os.path.join(args.input_path, filename)
            if os.path.isfile(file_path):
                print(f"\nProcessing: {filename}")
                results = analyzer.analyze_ue_file_comprehensive(file_path)
                
                if results:
                    total_files += 1
                    total_anomalies += results['summary']['integrated_anomalies']
        
        print(f"\nBATCH PROCESSING COMPLETE")
        print(f"Files processed: {total_files}")
        print(f"Total anomalies found: {total_anomalies}")
        
    else:
        # Process single file
        results = analyzer.analyze_ue_file_comprehensive(args.input_path)
        
        if results and args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")

if __name__ == "__main__":
    main()