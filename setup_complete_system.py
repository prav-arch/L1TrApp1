#!/usr/bin/env python3
"""
Complete System Setup Script
Sets up ClickHouse database with enhanced schema for ML algorithm tracking
"""

import clickhouse_connect
import json
from datetime import datetime

def setup_enhanced_clickhouse():
    """Setup ClickHouse with enhanced schema for ML tracking"""
    
    try:
        # Connect to ClickHouse
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password=''
        )
        
        print("Setting up enhanced ClickHouse database...")
        
        # Create database
        client.command("CREATE DATABASE IF NOT EXISTS l1_anomaly_detection")
        client.command("USE l1_anomaly_detection")
        
        # Enhanced anomalies table with ML algorithm details
        client.command("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id UUID DEFAULT generateUUIDv4(),
                timestamp DateTime,
                anomaly_type String,
                description String,
                severity Enum('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
                source_file String,
                packet_number UInt32 DEFAULT 0,
                mac_address String DEFAULT '',
                ue_id String DEFAULT '',
                session_id String,
                confidence_score Float32 DEFAULT 0.0,
                ml_algorithm_details String DEFAULT '{}',
                model_agreement UInt8 DEFAULT 0,
                individual_model_scores String DEFAULT '{}',
                status Enum('active' = 1, 'resolved' = 2, 'investigating' = 3) DEFAULT 'active',
                created_at DateTime,
                updated_at DateTime
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, severity, anomaly_type)
            TTL timestamp + INTERVAL 90 DAY
        """)
        
        # Enhanced processed files table
        client.command("""
            CREATE TABLE IF NOT EXISTS processed_files (
                id UUID DEFAULT generateUUIDv4(),
                filename String,
                file_path String DEFAULT '',
                file_size UInt64 DEFAULT 0,
                processing_time DateTime,
                total_samples UInt32,
                anomalies_detected UInt32,
                session_id String,
                processing_status Enum('pending' = 1, 'processing' = 2, 'completed' = 3, 'failed' = 4),
                ml_models_used Array(String) DEFAULT [],
                average_confidence Float32 DEFAULT 0.0,
                processing_duration_ms UInt32 DEFAULT 0,
                created_at DateTime
            ) ENGINE = MergeTree()
            ORDER BY (processing_time, session_id)
            TTL processing_time + INTERVAL 30 DAY
        """)
        
        # Enhanced sessions table
        client.command("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id String,
                start_time DateTime,
                end_time DateTime DEFAULT '1900-01-01 00:00:00',
                files_to_process UInt32,
                files_completed UInt32 DEFAULT 0,
                total_anomalies UInt32 DEFAULT 0,
                status Enum('pending' = 1, 'processing' = 2, 'completed' = 3, 'failed' = 4),
                ml_model_versions String DEFAULT '{}',
                analysis_parameters String DEFAULT '{}',
                created_at DateTime
            ) ENGINE = MergeTree()
            ORDER BY start_time
            TTL start_time + INTERVAL 7 DAY
        """)
        
        # ML model performance tracking table
        client.command("""
            CREATE TABLE IF NOT EXISTS ml_model_performance (
                id UUID DEFAULT generateUUIDv4(),
                model_name String,
                session_id String,
                timestamp DateTime,
                total_predictions UInt32,
                anomalies_detected UInt32,
                average_confidence Float32,
                false_positive_rate Float32 DEFAULT 0.0,
                false_negative_rate Float32 DEFAULT 0.0,
                accuracy_score Float32 DEFAULT 0.0,
                model_version String DEFAULT '',
                created_at DateTime
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, model_name)
        """)
        
        # Insert comprehensive test data with ML algorithm details
        print("Inserting enhanced test data...")
        
        # Test anomalies with ML algorithm details
        test_anomalies = [
            {
                'anomaly_type': 'DU-RU Communication',
                'description': 'ML detected DU-RU timeout with high confidence',
                'severity': 'critical',
                'source_file': 'fronthaul_001.pcap',
                'packet_number': 150,
                'mac_address': '00:11:22:33:44:67',
                'session_id': 'ml_test_session_001',
                'confidence_score': 0.94,
                'model_agreement': 4,
                'ml_algorithm_details': json.dumps({
                    'isolation_forest': {'prediction': 1, 'confidence': 0.92},
                    'dbscan': {'prediction': 1, 'confidence': 0.88},
                    'one_class_svm': {'prediction': 1, 'confidence': 0.91},
                    'random_forest': {'prediction': 1, 'confidence': 0.96}
                }),
                'individual_model_scores': json.dumps({
                    'isolation_forest': 0.92,
                    'dbscan': 0.88,
                    'one_class_svm': 0.91,
                    'random_forest': 0.96
                })
            },
            {
                'anomaly_type': 'UE Event Pattern',
                'description': 'ML detected UE attach failure pattern',
                'severity': 'high',
                'source_file': 'ue_events_002.txt',
                'packet_number': 75,
                'ue_id': '460110123456789',
                'session_id': 'ml_test_session_001',
                'confidence_score': 0.87,
                'model_agreement': 3,
                'ml_algorithm_details': json.dumps({
                    'isolation_forest': {'prediction': 1, 'confidence': 0.85},
                    'dbscan': {'prediction': 0, 'confidence': 0.45},
                    'one_class_svm': {'prediction': 1, 'confidence': 0.82},
                    'random_forest': {'prediction': 1, 'confidence': 0.93}
                }),
                'individual_model_scores': json.dumps({
                    'isolation_forest': 0.85,
                    'dbscan': 0.45,
                    'one_class_svm': 0.82,
                    'random_forest': 0.93
                })
            },
            {
                'anomaly_type': 'Timing Synchronization',
                'description': 'ML detected timing violation >100μs',
                'severity': 'high',
                'source_file': 'timing_sync_003.pcap',
                'packet_number': 203,
                'mac_address': '00:11:22:33:44:67',
                'session_id': 'ml_test_session_002',
                'confidence_score': 0.89,
                'model_agreement': 3,
                'ml_algorithm_details': json.dumps({
                    'isolation_forest': {'prediction': 1, 'confidence': 0.87},
                    'dbscan': {'prediction': 1, 'confidence': 0.78},
                    'one_class_svm': {'prediction': 0, 'confidence': 0.38},
                    'random_forest': {'prediction': 1, 'confidence': 0.91}
                }),
                'individual_model_scores': json.dumps({
                    'isolation_forest': 0.87,
                    'dbscan': 0.78,
                    'one_class_svm': 0.38,
                    'random_forest': 0.91
                })
            }
        ]
        
        for anomaly in test_anomalies:
            client.insert('anomalies', [anomaly])
        
        # Test processed files
        test_files = [
            {
                'filename': 'fronthaul_001.pcap',
                'file_size': 2048576,
                'total_samples': 1250,
                'anomalies_detected': 5,
                'session_id': 'ml_test_session_001',
                'processing_status': 'completed',
                'ml_models_used': ['isolation_forest', 'dbscan', 'one_class_svm', 'random_forest'],
                'average_confidence': 0.89,
                'processing_duration_ms': 1500
            },
            {
                'filename': 'ue_events_002.txt',
                'file_size': 45832,
                'total_samples': 450,
                'anomalies_detected': 3,
                'session_id': 'ml_test_session_001',
                'processing_status': 'completed',
                'ml_models_used': ['isolation_forest', 'dbscan', 'one_class_svm', 'random_forest'],
                'average_confidence': 0.84,
                'processing_duration_ms': 850
            }
        ]
        
        for file_record in test_files:
            client.insert('processed_files', [file_record])
        
        # Test sessions
        test_sessions = [
            {
                'session_id': 'ml_test_session_001',
                'files_to_process': 5,
                'files_completed': 5,
                'total_anomalies': 12,
                'status': 'completed',
                'ml_model_versions': json.dumps({
                    'isolation_forest': '1.0.0',
                    'dbscan': '1.0.0',
                    'one_class_svm': '1.0.0',
                    'random_forest': '1.0.0'
                }),
                'analysis_parameters': json.dumps({
                    'confidence_threshold': 0.7,
                    'ensemble_voting': True,
                    'min_agreement': 2
                })
            }
        ]
        
        for session in test_sessions:
            client.insert('sessions', [session])
        
        # Test ML model performance
        test_performance = [
            {
                'model_name': 'isolation_forest',
                'session_id': 'ml_test_session_001',
                'total_predictions': 1700,
                'anomalies_detected': 8,
                'average_confidence': 0.86,
                'accuracy_score': 0.91,
                'model_version': '1.0.0'
            },
            {
                'model_name': 'random_forest',
                'session_id': 'ml_test_session_001',
                'total_predictions': 1700,
                'anomalies_detected': 12,
                'average_confidence': 0.92,
                'accuracy_score': 0.94,
                'model_version': '1.0.0'
            }
        ]
        
        for perf in test_performance:
            client.insert('ml_model_performance', [perf])
        
        print("Enhanced ClickHouse setup completed successfully!")
        print("Database includes:")
        print("- Enhanced anomalies table with ML algorithm details")
        print("- ML model performance tracking")
        print("- Comprehensive test data with algorithm scores")
        print("- Session tracking with model versions")
        
        # Verify setup
        anomaly_count = client.query("SELECT count() FROM anomalies").result_rows[0][0]
        print(f"Test anomalies inserted: {anomaly_count}")
        
        return True
        
    except Exception as e:
        print(f"Setup failed: {e}")
        return False

if __name__ == "__main__":
    setup_enhanced_clickhouse()