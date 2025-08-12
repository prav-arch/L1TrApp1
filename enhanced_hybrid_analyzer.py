#!/usr/bin/env python3
"""
Enhanced Hybrid ML Analyzer - Integration of Supervised + Unsupervised Learning
Uses trained models for improved accuracy and provides true F-Score metrics
"""

import os
import json
import joblib
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import warnings
warnings.filterwarnings('ignore')

# Optional ClickHouse integration
try:
    import clickhouse_connect
    CLICKHOUSE_AVAILABLE = True
except ImportError:
    CLICKHOUSE_AVAILABLE = False

class EnhancedHybridAnalyzer:
    def __init__(self, trained_models_path=None):
        self.trained_models_path = trained_models_path
        self.models_loaded = False
        
        # Initialize models (will be replaced if trained models are loaded)
        self.supervised_svm = OneClassSVM(kernel='rbf', nu=0.1)
        self.supervised_rf = RandomForestClassifier(n_estimators=100, random_state=42)
        self.unsupervised_isolation = IsolationForest(contamination=0.1, random_state=42)
        self.unsupervised_dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()
        
        # Load trained models if available
        if trained_models_path:
            self.load_trained_models()
        
        # ClickHouse setup
        self.clickhouse_client = None
        if CLICKHOUSE_AVAILABLE:
            self.setup_clickhouse()
            
        print("Enhanced Hybrid Analyzer initialized")
        if self.models_loaded:
            print("Using pre-trained models for improved accuracy")
        else:
            print("Using default unsupervised models")
    
    def setup_clickhouse(self):
        """Setup ClickHouse connection"""
        try:
            self.clickhouse_client = clickhouse_connect.get_client(
                host='localhost',
                port=8123,
                username='default',
                password='',
                database='l1_anomaly_detection'
            )
            print("ClickHouse connection established")
        except Exception as e:
            print(f"ClickHouse connection failed: {e}")
            self.clickhouse_client = None
    
    def load_trained_models(self):
        """Load pre-trained models from disk"""
        try:
            models_dir = f"models/trained"
            
            # Find model files by training ID
            model_files = {
                'supervised_svm': f"{models_dir}/{self.trained_models_path}_supervised_svm.joblib",
                'supervised_rf': f"{models_dir}/{self.trained_models_path}_supervised_rf.joblib",
                'unsupervised_isolation': f"{models_dir}/{self.trained_models_path}_unsupervised_isolation.joblib",
                'scaler': f"{models_dir}/{self.trained_models_path}_scaler.joblib"
            }
            
            # Load models if they exist
            if all(os.path.exists(path) for path in model_files.values()):
                self.supervised_svm = joblib.load(model_files['supervised_svm'])
                self.supervised_rf = joblib.load(model_files['supervised_rf'])
                self.unsupervised_isolation = joblib.load(model_files['unsupervised_isolation'])
                self.scaler = joblib.load(model_files['scaler'])
                
                self.models_loaded = True
                print(f"Trained models loaded: {self.trained_models_path}")
                
            else:
                missing_files = [f for f, path in model_files.items() if not os.path.exists(path)]
                print(f"Warning: Some model files missing: {missing_files}")
                print("Falling back to default unsupervised models")
                
        except Exception as e:
            print(f"Error loading trained models: {e}")
            print("Using default unsupervised models")
    
    def extract_features_from_file(self, file_path):
        """Extract features from file for ML analysis with UE event support"""
        try:
            # Use enhanced UE event processor for better feature extraction
            from enhanced_ue_event_processor import UEEventProcessor
            
            ue_processor = UEEventProcessor()
            file_format = ue_processor.detect_file_format(file_path)
            
            # Process file based on format for enhanced UE event features
            if file_format == 'pcap':
                ue_results = ue_processor.process_pcap_ue_events(file_path)
                if ue_results and 'ue_features' in ue_results:
                    return np.array(ue_results['ue_features'])
            elif file_format in ['hdf5_text', 'text']:
                ue_results = ue_processor.process_hdf5_text_ue_events(file_path)
                if ue_results and 'ue_features' in ue_results:
                    return np.array(ue_results['ue_features'])
            
            # Fallback to enhanced feature extraction
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.strip().split('\n')
            features_list = []
            
            for i, line in enumerate(lines):
                if not line.strip():
                    continue
                
                # Enhanced features matching training
                features = [
                    len(line),
                    len(line.split()),
                    line.count(' '),
                    line.count('\t'),
                    sum(1 for c in line if c.isdigit()),
                    sum(1 for c in line if c.isalpha()),
                    sum(1 for c in line if c in '.,;:!?'),
                    i + 1,
                    1 if 'attach' in line.lower() else 0,  # UE attach indicator
                    1 if 'handover' in line.lower() else 0,  # Handover indicator
                    1 if 'rsrp' in line.lower() else 0,  # Signal quality indicator
                    line.count(':'),  # Colon count
                    len([w for w in line.split() if w.isdigit()]),  # Numeric word count
                    1 if any(word in line.lower() for word in ['error', 'fail', 'timeout']) else 0,  # Error indicator
                    sum(1 for c in line if c.isupper()) / max(len(line), 1)  # Uppercase ratio
                ]
                
                # Pad or truncate to fixed size (must match training)
                while len(features) < 15:
                    features.append(0.0)
                features = features[:15]
                
                features_list.append(features)
            
            return np.array(features_list) if features_list else None
            
        except Exception as e:
            print(f"Error extracting features from {file_path}: {e}")
            # Return basic features as fallback
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    basic_features = [[len(content), len(content.split()), content.count('\n'), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]
                    return np.array(basic_features)
            except:
                return None
    
    def hybrid_predict_with_confidence(self, X):
        """Make hybrid predictions with confidence scoring"""
        if len(X) == 0:
            return [], []
        
        # Scale features
        X_scaled = self.scaler.transform(X) if self.models_loaded else self.scaler.fit_transform(X)
        
        # Get predictions from all models
        predictions = {}
        confidences = {}
        
        # Supervised One-Class SVM
        try:
            svm_pred = self.supervised_svm.predict(X_scaled)
            svm_decision = self.supervised_svm.decision_function(X_scaled)
            predictions['supervised_svm'] = np.where(svm_pred == -1, 1, 0)
            confidences['supervised_svm'] = np.abs(svm_decision)
        except:
            predictions['supervised_svm'] = np.zeros(len(X_scaled))
            confidences['supervised_svm'] = np.zeros(len(X_scaled))
        
        # Supervised Random Forest (if trained)
        try:
            if self.models_loaded:
                rf_pred = self.supervised_rf.predict(X_scaled)
                rf_proba = self.supervised_rf.predict_proba(X_scaled)
                predictions['supervised_rf'] = rf_pred
                confidences['supervised_rf'] = np.max(rf_proba, axis=1)
            else:
                predictions['supervised_rf'] = np.zeros(len(X_scaled))
                confidences['supervised_rf'] = np.zeros(len(X_scaled))
        except:
            predictions['supervised_rf'] = np.zeros(len(X_scaled))
            confidences['supervised_rf'] = np.zeros(len(X_scaled))
        
        # Unsupervised Isolation Forest
        try:
            iso_pred = self.unsupervised_isolation.predict(X_scaled)
            iso_decision = self.unsupervised_isolation.decision_function(X_scaled)
            predictions['unsupervised_isolation'] = np.where(iso_pred == -1, 1, 0)
            confidences['unsupervised_isolation'] = np.abs(iso_decision)
        except:
            if not self.models_loaded:
                self.unsupervised_isolation.fit(X_scaled)
                iso_pred = self.unsupervised_isolation.predict(X_scaled)
                iso_decision = self.unsupervised_isolation.decision_function(X_scaled)
                predictions['unsupervised_isolation'] = np.where(iso_pred == -1, 1, 0)
                confidences['unsupervised_isolation'] = np.abs(iso_decision)
            else:
                predictions['unsupervised_isolation'] = np.zeros(len(X_scaled))
                confidences['unsupervised_isolation'] = np.zeros(len(X_scaled))
        
        # Unsupervised DBSCAN
        try:
            dbscan_pred = self.unsupervised_dbscan.fit_predict(X_scaled)
            predictions['unsupervised_dbscan'] = np.where(dbscan_pred == -1, 1, 0)
            confidences['unsupervised_dbscan'] = np.ones(len(X_scaled))
        except:
            predictions['unsupervised_dbscan'] = np.zeros(len(X_scaled))
            confidences['unsupervised_dbscan'] = np.zeros(len(X_scaled))
        
        # Calculate ensemble predictions and confidence
        ensemble_predictions = []
        ensemble_confidences = []
        
        for i in range(len(X_scaled)):
            # Get votes for this sample
            votes = [predictions[model][i] for model in predictions.keys()]
            confs = [confidences[model][i] for model in confidences.keys()]
            
            # Ensemble decision (majority vote)
            anomaly_votes = sum(votes)
            total_models = len(votes)
            
            # Ensemble prediction
            ensemble_pred = 1 if anomaly_votes >= 2 else 0
            
            # Enhanced confidence calculation
            if anomaly_votes > 0:
                # Weight by model agreement and confidence
                avg_confidence = np.mean([confs[j] for j in range(len(votes)) if votes[j] == 1])
                model_agreement = anomaly_votes / total_models
                ensemble_conf = model_agreement * avg_confidence
            else:
                ensemble_conf = 0.0
            
            ensemble_predictions.append(ensemble_pred)
            ensemble_confidences.append(min(ensemble_conf, 1.0))
        
        return ensemble_predictions, ensemble_confidences
    
    def analyze_file_hybrid(self, filename):
        """Analyze file using hybrid approach"""
        print(f"\nHYBRID ANALYSIS: {filename}")
        print("=" * 60)
        
        # Extract features
        features = self.extract_features_from_file(filename)
        if features is None:
            print(f"Could not extract features from {filename}")
            return []
        
        # Get hybrid predictions
        predictions, confidences = self.hybrid_predict_with_confidence(features)
        
        # Process results
        anomalies = []
        for i, (pred, conf) in enumerate(zip(predictions, confidences)):
            if pred == 1:  # Anomaly detected
                anomaly = {
                    'packet_number': i + 1,
                    'confidence': conf,
                    'prediction': pred,
                    'source_file': filename,
                    'timestamp': datetime.now().isoformat(),
                    'model_type': 'hybrid_ensemble'
                }
                anomalies.append(anomaly)
        
        # Display results
        print(f"File: {os.path.basename(filename)}")
        print(f"Total samples analyzed: {len(features)}")
        print(f"Anomalies detected: {len(anomalies)}")
        
        if anomalies:
            print(f"Average confidence: {np.mean([a['confidence'] for a in anomalies]):.3f}")
            print(f"Max confidence: {max([a['confidence'] for a in anomalies]):.3f}")
            
            # Show top anomalies
            sorted_anomalies = sorted(anomalies, key=lambda x: x['confidence'], reverse=True)
            print(f"\nTop 5 Anomalies:")
            for i, anomaly in enumerate(sorted_anomalies[:5], 1):
                print(f"  {i}. Line {anomaly['packet_number']}: Confidence {anomaly['confidence']:.3f}")
        
        return anomalies
    
    def calculate_f_score_metrics(self, predictions, ground_truth):
        """Calculate true F-Score metrics with ground truth"""
        if len(predictions) == 0 or len(ground_truth) == 0:
            return None
        
        # Ensure same length
        min_len = min(len(predictions), len(ground_truth))
        pred = predictions[:min_len]
        truth = ground_truth[:min_len]
        
        # Calculate metrics
        accuracy = accuracy_score(truth, pred)
        precision = precision_score(truth, pred, zero_division=0)
        recall = recall_score(truth, pred, zero_division=0)
        f1 = f1_score(truth, pred, zero_division=0)
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'total_samples': len(truth),
            'true_positives': sum(1 for i in range(len(truth)) if truth[i] == 1 and pred[i] == 1),
            'false_positives': sum(1 for i in range(len(truth)) if truth[i] == 0 and pred[i] == 1),
            'false_negatives': sum(1 for i in range(len(truth)) if truth[i] == 1 and pred[i] == 0),
            'true_negatives': sum(1 for i in range(len(truth)) if truth[i] == 0 and pred[i] == 0)
        }
    
    def validate_with_test_data(self, test_normal_path, test_anomaly_path=None):
        """Validate model performance with test data"""
        print("\nMODEL VALIDATION WITH TEST DATA")
        print("=" * 50)
        
        all_predictions = []
        all_ground_truth = []
        
        # Process normal test files
        if os.path.exists(test_normal_path):
            for filename in os.listdir(test_normal_path):
                file_path = os.path.join(test_normal_path, filename)
                features = self.extract_features_from_file(file_path)
                
                if features is not None:
                    predictions, _ = self.hybrid_predict_with_confidence(features)
                    ground_truth = [0] * len(predictions)  # All normal
                    
                    all_predictions.extend(predictions)
                    all_ground_truth.extend(ground_truth)
        
        # Process anomalous test files (if available)
        if test_anomaly_path and os.path.exists(test_anomaly_path):
            for filename in os.listdir(test_anomaly_path):
                file_path = os.path.join(test_anomaly_path, filename)
                features = self.extract_features_from_file(file_path)
                
                if features is not None:
                    predictions, _ = self.hybrid_predict_with_confidence(features)
                    ground_truth = [1] * len(predictions)  # All anomalous
                    
                    all_predictions.extend(predictions)
                    all_ground_truth.extend(ground_truth)
        
        # Calculate F-Score metrics
        if all_predictions and all_ground_truth:
            metrics = self.calculate_f_score_metrics(all_predictions, all_ground_truth)
            
            if metrics:
                print(f"VALIDATION RESULTS:")
                print(f"  Accuracy:  {metrics['accuracy']:.3f}")
                print(f"  Precision: {metrics['precision']:.3f}")
                print(f"  Recall:    {metrics['recall']:.3f}")
                print(f"  F1-Score:  {metrics['f1_score']:.3f}")
                print(f"  Total Samples: {metrics['total_samples']}")
                print(f"  True Positives: {metrics['true_positives']}")
                print(f"  False Positives: {metrics['false_positives']}")
                print(f"  False Negatives: {metrics['false_negatives']}")
                print(f"  True Negatives: {metrics['true_negatives']}")
                
                return metrics
        
        print("No test data available for validation")
        return None

def main():
    """Main execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Hybrid ML Analyzer')
    parser.add_argument('input_path', help='File or directory to analyze')
    parser.add_argument('--use-trained-models', help='Training ID of pre-trained models to use')
    parser.add_argument('--validate', help='Path to validation data (normal files)')
    parser.add_argument('--validate-anomalies', help='Path to validation anomaly files')
    parser.add_argument('--confidence-threshold', type=float, default=0.5,
                       help='Confidence threshold for anomaly detection')
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = EnhancedHybridAnalyzer(trained_models_path=args.use_trained_models)
    
    # Run validation if requested
    if args.validate:
        metrics = analyzer.validate_with_test_data(args.validate, args.validate_anomalies)
        if metrics and metrics['f1_score'] > 0.0:
            print(f"\nValidation F1-Score: {metrics['f1_score']:.3f}")
    
    # Analyze input files
    if os.path.isfile(args.input_path):
        anomalies = analyzer.analyze_file_hybrid(args.input_path)
        print(f"\nAnalysis complete. Found {len(anomalies)} anomalies.")
        
    elif os.path.isdir(args.input_path):
        total_anomalies = 0
        for filename in os.listdir(args.input_path):
            file_path = os.path.join(args.input_path, filename)
            if os.path.isfile(file_path):
                anomalies = analyzer.analyze_file_hybrid(file_path)
                total_anomalies += len(anomalies)
        
        print(f"\nDirectory analysis complete. Found {total_anomalies} total anomalies.")
    
    else:
        print(f"Error: {args.input_path} is not a valid file or directory")

if __name__ == "__main__":
    main()