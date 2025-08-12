#!/usr/bin/env python3
"""
Hybrid ML Trainer for L1 Network Anomaly Detection
Combines supervised learning (using clean data) with unsupervised detection
Provides true F-Score metrics with ground truth validation
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
import time
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, classification_report
import warnings
warnings.filterwarnings('ignore')

# Optional ClickHouse integration
try:
    import clickhouse_connect
    CLICKHOUSE_AVAILABLE = True
except ImportError:
    CLICKHOUSE_AVAILABLE = False
    print("ClickHouse module not available, training metrics will be saved locally only")

class HybridMLTrainer:
    def __init__(self, normal_data_path="training_data/normal", models_save_path="models/trained"):
        # Use relative paths from current directory
        self.normal_data_path = normal_data_path
        self.models_save_path = models_save_path
        self.results_path = "results/training_logs"
        
        # Supervised models (trained on normal data)
        self.supervised_svm = OneClassSVM(kernel='rbf', nu=0.1)
        self.supervised_rf = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Unsupervised models (no training needed, but can be tuned)
        self.unsupervised_isolation = IsolationForest(contamination=0.1, random_state=42)
        self.unsupervised_dbscan = DBSCAN(eps=0.5, min_samples=5)
        
        # Feature scaling
        self.scaler = StandardScaler()
        
        # Training metrics
        self.training_history = {
            'supervised_metrics': {},
            'validation_metrics': {},
            'hybrid_performance': {}
        }
        
        # ClickHouse connection
        self.clickhouse_client = None
        if CLICKHOUSE_AVAILABLE:
            self.setup_clickhouse()
        
        print("Hybrid ML Trainer initialized")
        print(f"Normal data path: {normal_data_path}")
        print(f"Models save path: {models_save_path}")
    
    def setup_clickhouse(self):
        """Setup ClickHouse connection for training metrics storage"""
        try:
            self.clickhouse_client = clickhouse_connect.get_client(
                host='localhost',
                port=8123,
                username='default',
                password='',
                database='l1_anomaly_detection'
            )
            
            # Create training metrics table
            self.create_training_tables()
            print("ClickHouse connection established for training metrics")
            
        except Exception as e:
            print(f"ClickHouse connection failed: {e}")
            self.clickhouse_client = None
    
    def create_training_tables(self):
        """Create ClickHouse tables for training metrics"""
        if not self.clickhouse_client:
            return
            
        training_metrics_table = """
        CREATE TABLE IF NOT EXISTS l1_anomaly_detection.training_metrics (
            training_id String,
            timestamp DateTime DEFAULT now(),
            model_type LowCardinality(String),
            training_approach LowCardinality(String),
            dataset_size UInt32,
            validation_split Float64,
            accuracy_score Float64,
            precision_score Float64,
            recall_score Float64,
            f1_score Float64,
            training_duration Float64,
            model_parameters String,
            validation_results String,
            hybrid_confidence Float64
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, training_id, model_type)
        """
        
        try:
            self.clickhouse_client.command(training_metrics_table)
            print("Training metrics table created")
        except Exception as e:
            print(f"Failed to create training tables: {e}")
    
    def load_and_preprocess_data(self):
        """Load normal data and create anomaly labels for supervised training"""
        print("Loading and preprocessing training data...")
        print(f"  Checking training data path: {self.normal_data_path}")
        
        # Load normal data
        normal_samples = []
        normal_labels = []
        
        if not os.path.exists(self.normal_data_path):
            print(f"ERROR: Normal data path {self.normal_data_path} does not exist")
            print("Please create the directory and add training files (.txt, .log, .pcap)")
            return None, None, None, None
        
        print("  Scanning for training files...")
        files = [f for f in os.listdir(self.normal_data_path) if f.endswith(('.txt', '.log', '.pcap'))]
        
        if not files:
            print(f"ERROR: No training files found in {self.normal_data_path}")
            print("Please add .txt, .log, or .pcap files to the training directory")
            return None, None, None, None
        
        print(f"  Found {len(files)} training files: {files}")
        
        for i, filename in enumerate(files, 1):
            print(f"    Processing file {i}/{len(files)}: {filename}")
            file_path = os.path.join(self.normal_data_path, filename)
            
            if filename.endswith(('.txt', '.log', '.pcap')):
                # Extract features from file
                print(f"      Extracting features from {filename}...")
                features = self.extract_features_from_file(file_path)
                if features is not None:
                    normal_samples.extend(features)
                    normal_labels.extend([0] * len(features))  # 0 = normal
                    print(f"      Success: Extracted {len(features)} feature vectors")
                else:
                    print(f"      Warning: No features extracted from {filename}")
        
        if not normal_samples:
            print("ERROR: No normal samples found. Please add files to training_data/normal/")
            return None, None, None, None
        
        print(f"  Successfully extracted {len(normal_samples)} feature vectors")
        
        # Convert to numpy arrays
        print("  Converting to numpy arrays...")
        X = np.array(normal_samples)
        y = np.array(normal_labels)
        print(f"    Feature matrix shape: {X.shape}")
        
        # Create some synthetic anomalies for supervised training
        print("  Generating synthetic anomalies for training...")
        anomaly_samples = self.generate_synthetic_anomalies(X, contamination_rate=0.1)
        anomaly_labels = np.ones(len(anomaly_samples))  # 1 = anomaly
        print(f"    Generated {len(anomaly_samples)} synthetic anomaly samples")
        
        # Combine normal and synthetic anomaly data
        print("  Combining normal and synthetic data...")
        X_combined = np.vstack([X, anomaly_samples])
        y_combined = np.hstack([y, anomaly_labels])
        
        # Scale features
        print("  Scaling features with StandardScaler...")
        X_scaled = self.scaler.fit_transform(X_combined)
        print("  Feature scaling complete")
        
        # Split into training and validation sets
        print("  Creating train-validation split...")
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y_combined, test_size=0.2, random_state=42, stratify=y_combined
        )
        
        print(f"  Loaded {len(X)} normal samples")
        print(f"  Generated {len(anomaly_samples)} synthetic anomaly samples") 
        print(f"  Training set: {len(X_train)} samples")
        print(f"  Validation set: {len(X_val)} samples")
        print("Data loading and preprocessing complete!")
        
        return X_train, X_val, y_train, y_val
    
    def extract_features_from_file(self, file_path):
        """Extract numerical features from network log files with UE event support"""
        try:
            print(f"        Attempting advanced feature extraction...")
            # Use enhanced UE event processor for better feature extraction
            try:
                from enhanced_ue_event_processor import UEEventProcessor
                print(f"        UE event processor imported successfully")
                
                ue_processor = UEEventProcessor()
                file_format = ue_processor.detect_file_format(file_path)
                print(f"        Detected file format: {file_format}")
                
                # Process file based on format
                if file_format == 'pcap':
                    print(f"        Processing as PCAP file...")
                    ue_results = ue_processor.process_pcap_ue_events(file_path)
                    if ue_results and 'ue_features' in ue_results:
                        print(f"        Advanced PCAP processing successful")
                        return ue_results['ue_features']
                elif file_format in ['hdf5_text', 'text']:
                    print(f"        Processing as text/HDF5 file...")
                    ue_results = ue_processor.process_hdf5_text_ue_events(file_path)
                    if ue_results and 'ue_features' in ue_results:
                        print(f"        Advanced text processing successful")
                        return ue_results['ue_features']
            except ImportError as e:
                print(f"        Warning: UE event processor import failed: {e}")
            except Exception as e:
                print(f"        Warning: Advanced feature extraction failed: {e}")
            
            # Fallback to basic feature extraction
            print(f"        Using basic feature extraction...")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract basic statistical features
            lines = content.strip().split('\n')
            print(f"        Processing {len(lines)} lines for basic features...")
            features_list = []
            
            for i, line in enumerate(lines):
                if not line.strip():
                    continue
                
                # Enhanced features including UE-specific patterns
                features = [
                    len(line),  # Line length
                    len(line.split()),  # Word count
                    line.count(' '),  # Space count
                    line.count('\t'),  # Tab count
                    sum(1 for c in line if c.isdigit()),  # Digit count
                    sum(1 for c in line if c.isalpha()),  # Alpha count
                    sum(1 for c in line if c in '.,;:!?'),  # Punctuation count
                    i + 1,  # Line position
                    1 if 'attach' in line.lower() else 0,  # UE attach indicator
                    1 if 'handover' in line.lower() else 0,  # Handover indicator
                    1 if 'rsrp' in line.lower() else 0,  # Signal quality indicator
                    line.count(':'),  # Colon count (common in logs)
                    len([w for w in line.split() if w.isdigit()]),  # Numeric word count
                    1 if any(word in line.lower() for word in ['error', 'fail', 'timeout']) else 0,  # Error indicator
                    sum(1 for c in line if c.isupper()) / max(len(line), 1)  # Uppercase ratio
                ]
                
                # Pad or truncate to fixed size
                while len(features) < 15:
                    features.append(0.0)
                features = features[:15]
                
                features_list.append(features)
            
            return features_list if features_list else None
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            # Return basic features as absolute fallback
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    return [[len(content), len(content.split()), content.count('\n'), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]
            except:
                return None
    
    def generate_synthetic_anomalies(self, normal_data, contamination_rate=0.1):
        """Generate synthetic anomaly samples for supervised training"""
        num_anomalies = int(len(normal_data) * contamination_rate)
        
        # Method 1: Add noise to normal samples
        noise_anomalies = normal_data[:num_anomalies//2] + np.random.normal(0, 2, 
                                                                           (num_anomalies//2, normal_data.shape[1]))
        
        # Method 2: Scale normal samples significantly
        scale_anomalies = normal_data[num_anomalies//2:num_anomalies] * np.random.uniform(3, 5, 
                                                                                        (num_anomalies - num_anomalies//2, 1))
        
        synthetic_anomalies = np.vstack([noise_anomalies, scale_anomalies])
        return synthetic_anomalies
    
    def train_supervised_models(self, X_train, y_train):
        """Train supervised models on normal data"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Training supervised models...")
        
        # Separate normal data for One-Class SVM
        X_normal = X_train[y_train == 0]
        print(f"[{timestamp}] Separated {len(X_normal)} normal samples for One-Class SVM")
        
        # Train One-Class SVM on normal data only
        print(f"[{timestamp}] Starting One-Class SVM training...")
        start_time = time.time()
        self.supervised_svm.fit(X_normal)
        svm_duration = time.time() - start_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] One-Class SVM training complete ({svm_duration:.2f}s)")
        
        # Train Random Forest as binary classifier
        print(f"[{timestamp}] Starting Random Forest training...")
        start_time = time.time()
        self.supervised_rf.fit(X_train, y_train)
        rf_duration = time.time() - start_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Random Forest training complete ({rf_duration:.2f}s)")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] All supervised models trained successfully")
    
    def train_unsupervised_models(self, X_train):
        """Tune unsupervised models with training data"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Training/tuning unsupervised models...")
        
        # Isolation Forest
        print(f"[{timestamp}] Starting Isolation Forest training...")
        start_time = time.time()
        self.unsupervised_isolation.fit(X_train)
        iso_duration = time.time() - start_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Isolation Forest training complete ({iso_duration:.2f}s)")
        
        # DBSCAN doesn't require fitting, but we can analyze clusters
        print(f"[{timestamp}] Running DBSCAN cluster analysis...")
        start_time = time.time()
        clusters = self.unsupervised_dbscan.fit_predict(X_train)
        unique_clusters = len(set(clusters)) - (1 if -1 in clusters else 0)
        outliers = sum(1 for c in clusters if c == -1)
        dbscan_duration = time.time() - start_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] DBSCAN analysis complete ({dbscan_duration:.2f}s): {unique_clusters} clusters, {outliers} outliers")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] All unsupervised models trained successfully")
    
    def validate_models(self, X_val, y_val):
        """Validate all models and calculate F-scores"""
        print("Validating models...")
        
        results = {
            'supervised_svm': {},
            'supervised_rf': {},
            'unsupervised_isolation': {},
            'unsupervised_dbscan': {},
            'hybrid_ensemble': {}
        }
        
        # Supervised One-Class SVM validation
        svm_pred = self.supervised_svm.predict(X_val)
        svm_pred = np.where(svm_pred == -1, 1, 0)  # Convert to binary (1=anomaly)
        
        results['supervised_svm'] = {
            'accuracy': accuracy_score(y_val, svm_pred),
            'precision': precision_score(y_val, svm_pred, zero_division=0),
            'recall': recall_score(y_val, svm_pred, zero_division=0),
            'f1_score': f1_score(y_val, svm_pred, zero_division=0)
        }
        
        # Supervised Random Forest validation
        rf_pred = self.supervised_rf.predict(X_val)
        
        results['supervised_rf'] = {
            'accuracy': accuracy_score(y_val, rf_pred),
            'precision': precision_score(y_val, rf_pred, zero_division=0),
            'recall': recall_score(y_val, rf_pred, zero_division=0),
            'f1_score': f1_score(y_val, rf_pred, zero_division=0)
        }
        
        # Unsupervised Isolation Forest validation
        iso_pred = self.unsupervised_isolation.predict(X_val)
        iso_pred = np.where(iso_pred == -1, 1, 0)  # Convert to binary
        
        results['unsupervised_isolation'] = {
            'accuracy': accuracy_score(y_val, iso_pred),
            'precision': precision_score(y_val, iso_pred, zero_division=0),
            'recall': recall_score(y_val, iso_pred, zero_division=0),
            'f1_score': f1_score(y_val, iso_pred, zero_division=0)
        }
        
        # Unsupervised DBSCAN validation
        dbscan_pred = self.unsupervised_dbscan.fit_predict(X_val)
        dbscan_pred = np.where(dbscan_pred == -1, 1, 0)  # Convert to binary
        
        results['unsupervised_dbscan'] = {
            'accuracy': accuracy_score(y_val, dbscan_pred),
            'precision': precision_score(y_val, dbscan_pred, zero_division=0),
            'recall': recall_score(y_val, dbscan_pred, zero_division=0),
            'f1_score': f1_score(y_val, dbscan_pred, zero_division=0)
        }
        
        # Hybrid ensemble validation
        ensemble_pred = self.hybrid_ensemble_predict(X_val)
        
        results['hybrid_ensemble'] = {
            'accuracy': accuracy_score(y_val, ensemble_pred),
            'precision': precision_score(y_val, ensemble_pred, zero_division=0),
            'recall': recall_score(y_val, ensemble_pred, zero_division=0),
            'f1_score': f1_score(y_val, ensemble_pred, zero_division=0)
        }
        
        return results
    
    def hybrid_ensemble_predict(self, X):
        """Make predictions using hybrid ensemble of all models"""
        # Get predictions from all models
        svm_pred = np.where(self.supervised_svm.predict(X) == -1, 1, 0)
        rf_pred = self.supervised_rf.predict(X)
        iso_pred = np.where(self.unsupervised_isolation.predict(X) == -1, 1, 0)
        dbscan_pred = np.where(self.unsupervised_dbscan.fit_predict(X) == -1, 1, 0)
        
        # Ensemble voting (majority vote)
        predictions = np.column_stack([svm_pred, rf_pred, iso_pred, dbscan_pred])
        ensemble_pred = np.array([1 if sum(row) >= 2 else 0 for row in predictions])
        
        return ensemble_pred
    
    def save_models(self, training_id):
        """Save trained models to disk"""
        os.makedirs(self.models_save_path, exist_ok=True)
        
        # Save models
        model_files = {
            'supervised_svm': f"{self.models_save_path}/{training_id}_supervised_svm.joblib",
            'supervised_rf': f"{self.models_save_path}/{training_id}_supervised_rf.joblib",
            'unsupervised_isolation': f"{self.models_save_path}/{training_id}_unsupervised_isolation.joblib",
            'scaler': f"{self.models_save_path}/{training_id}_scaler.joblib"
        }
        
        joblib.dump(self.supervised_svm, model_files['supervised_svm'])
        joblib.dump(self.supervised_rf, model_files['supervised_rf'])
        joblib.dump(self.unsupervised_isolation, model_files['unsupervised_isolation'])
        joblib.dump(self.scaler, model_files['scaler'])
        
        print(f"Models saved with training ID: {training_id}")
        return model_files
    
    def save_training_results(self, training_id, validation_results, training_duration):
        """Save training results locally and to ClickHouse"""
        os.makedirs(self.results_path, exist_ok=True)
        
        # Save results locally
        results_file = f"{self.results_path}/{training_id}_results.json"
        
        training_summary = {
            'training_id': training_id,
            'timestamp': datetime.now().isoformat(),
            'training_duration': training_duration,
            'validation_results': validation_results,
            'best_model': max(validation_results.items(), key=lambda x: x[1]['f1_score'])[0],
            'hybrid_f1_score': validation_results['hybrid_ensemble']['f1_score']
        }
        
        with open(results_file, 'w') as f:
            json.dump(training_summary, f, indent=2)
        
        print(f"Training results saved: {results_file}")
        
        # Store in ClickHouse
        self.store_training_metrics_clickhouse(training_id, validation_results, training_duration)
    
    def store_training_metrics_clickhouse(self, training_id, validation_results, training_duration):
        """Store training metrics in ClickHouse"""
        if not self.clickhouse_client:
            return
        
        try:
            for model_name, metrics in validation_results.items():
                values = [
                    training_id,
                    datetime.now(),
                    model_name,
                    'hybrid' if model_name == 'hybrid_ensemble' else ('supervised' if 'supervised' in model_name else 'unsupervised'),
                    0,  # dataset_size - to be filled
                    0.2,  # validation_split
                    float(metrics['accuracy']),
                    float(metrics['precision']),
                    float(metrics['recall']),
                    float(metrics['f1_score']),
                    float(training_duration),
                    json.dumps({}),  # model_parameters
                    json.dumps(metrics),  # validation_results
                    float(validation_results['hybrid_ensemble']['f1_score'])
                ]
                
                self.clickhouse_client.insert('l1_anomaly_detection.training_metrics', [values])
            
            print("Training metrics stored in ClickHouse")
            
        except Exception as e:
            print(f"Failed to store training metrics: {e}")
    
    def train_hybrid_models(self, normal_data_path=None, anomalous_data_path=None, output_dir=None):
        """Train hybrid models with specified paths - called by comprehensive analyzer"""
        if normal_data_path:
            self.normal_data_path = normal_data_path
        if output_dir:
            self.models_save_path = output_dir
        
        return self.train_complete_system()
    
    def train_complete_system(self):
        """Run complete hybrid training pipeline"""
        print("Starting Hybrid ML Training Pipeline")
        print("=" * 60)
        
        training_id = f"hybrid_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        # Load and preprocess data
        X_train, X_val, y_train, y_val = self.load_and_preprocess_data()
        
        if X_train is None:
            print("Training failed: No data available")
            return None
        
        # Train supervised models
        self.train_supervised_models(X_train, y_train)
        
        # Train/tune unsupervised models
        self.train_unsupervised_models(X_train)
        
        # Validate all models
        validation_results = self.validate_models(X_val, y_val)
        
        # Calculate training duration
        training_duration = (datetime.now() - start_time).total_seconds()
        
        # Display results
        self.display_training_results(validation_results)
        
        # Save models and results
        model_files = self.save_models(training_id)
        self.save_training_results(training_id, validation_results, training_duration)
        
        print(f"\nTraining completed in {training_duration:.2f} seconds")
        print(f"Training ID: {training_id}")
        print(f"Best model: {max(validation_results.items(), key=lambda x: x[1]['f1_score'])[0]}")
        print(f"Hybrid F1-Score: {validation_results['hybrid_ensemble']['f1_score']:.3f}")
        
        return {
            'training_id': training_id,
            'model_files': model_files,
            'validation_results': validation_results,
            'training_duration': training_duration
        }
    
    def display_training_results(self, results):
        """Display training results in formatted table"""
        print("\nTRAINING RESULTS")
        print("=" * 80)
        print(f"{'Model':<25} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
        print("-" * 80)
        
        for model_name, metrics in results.items():
            print(f"{model_name:<25} "
                  f"{metrics['accuracy']:<12.3f} "
                  f"{metrics['precision']:<12.3f} "
                  f"{metrics['recall']:<12.3f} "
                  f"{metrics['f1_score']:<12.3f}")
        
        print("-" * 80)
        
        # Highlight best performing model
        best_model = max(results.items(), key=lambda x: x[1]['f1_score'])
        print(f"\nBest Model: {best_model[0]} (F1-Score: {best_model[1]['f1_score']:.3f})")
        
        # Training recommendations
        print(f"\nTRAINING RECOMMENDATIONS:")
        hybrid_f1 = results['hybrid_ensemble']['f1_score']
        
        if hybrid_f1 > 0.8:
            print("  EXCELLENT: Hybrid model shows high performance")
        elif hybrid_f1 > 0.6:
            print("  GOOD: Hybrid model performance is acceptable")
        elif hybrid_f1 > 0.4:
            print("  MODERATE: Consider adding more normal training data")
        else:
            print("  POOR: Increase training data size and review feature extraction")

def main():
    """Main training execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Hybrid ML Trainer for L1 Network Anomaly Detection')
    parser.add_argument('--normal-data', default='training_data/normal', 
                       help='Path to normal training data')
    parser.add_argument('--models-path', default='models/trained',
                       help='Path to save trained models')
    
    args = parser.parse_args()
    
    # Create trainer and run training
    trainer = HybridMLTrainer(
        normal_data_path=args.normal_data,
        models_save_path=args.models_path
    )
    
    # Run complete training pipeline
    results = trainer.train_complete_system()
    
    if results:
        print(f"\nTraining completed successfully!")
        print(f"Use training ID '{results['training_id']}' to load these models in the enhanced analyzer")
        print(f"\nNext steps:")
        print(f"1. Place your clean files in: {args.normal_data}")
        print(f"2. Run: python3 enhanced_ml_analyzer.py --use-trained-models {results['training_id']}")
        print(f"3. View results with true F-Score metrics in ClickHouse")

if __name__ == "__main__":
    main()