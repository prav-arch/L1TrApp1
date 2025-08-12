#!/usr/bin/env python3
"""
ML Model Trainer for L1 Network Troubleshooting System
Creates, trains, and evaluates machine learning models for anomaly detection
in 5G fronthaul networks and UE mobility patterns.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import pickle
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Any
import scapy.all as scapy

class L1NetworkMLTrainer:
    """
    Advanced ML trainer for L1 network anomaly detection
    Supports multiple algorithms with ensemble voting
    """
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        self.feature_columns = []
        self.training_history = []
        self.ensemble_weights = {
            'isolation_forest': 0.3,
            'dbscan': 0.2,
            'one_class_svm': 0.2,
            'random_forest': 0.3
        }
        
    def extract_pcap_features(self, pcap_file: str) -> pd.DataFrame:
        """Extract network features from PCAP files for ML training"""
        print(f"📦 Extracting features from {pcap_file}")
        
        features = []
        
        try:
            packets = scapy.rdpcap(pcap_file)
            
            for i, packet in enumerate(packets):
                feature_row = {
                    'packet_id': i,
                    'packet_size': len(packet),
                    'protocol': packet.proto if hasattr(packet, 'proto') else 0,
                    'src_port': packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else 0,
                    'dst_port': packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0,
                    'flags': packet[scapy.TCP].flags if packet.haslayer(scapy.TCP) else 0,
                    'window_size': packet[scapy.TCP].window if packet.haslayer(scapy.TCP) else 0,
                    'ttl': packet[scapy.IP].ttl if packet.haslayer(scapy.IP) else 0,
                    'fragment_offset': packet[scapy.IP].frag if packet.haslayer(scapy.IP) else 0,
                    'inter_arrival_time': 0,  # Calculate below
                    'payload_size': len(packet.payload) if hasattr(packet, 'payload') else 0
                }
                
                # Calculate inter-arrival time
                if i > 0 and hasattr(packet, 'time') and hasattr(packets[i-1], 'time'):
                    feature_row['inter_arrival_time'] = float(packet.time) - float(packets[i-1].time)
                
                # DU-RU specific features
                if packet.haslayer(scapy.Ether):
                    src_mac = packet[scapy.Ether].src
                    dst_mac = packet[scapy.Ether].dst
                    
                    # Known MAC addresses for DU and RU
                    du_mac = "00:11:22:33:44:67"
                    ru_mac = "6c:ad:ad:00:03:2a"
                    
                    feature_row['is_du_src'] = 1 if src_mac == du_mac else 0
                    feature_row['is_ru_src'] = 1 if src_mac == ru_mac else 0
                    feature_row['is_du_dst'] = 1 if dst_mac == du_mac else 0
                    feature_row['is_ru_dst'] = 1 if dst_mac == ru_mac else 0
                    feature_row['du_ru_communication'] = 1 if (src_mac == du_mac and dst_mac == ru_mac) or (src_mac == ru_mac and dst_mac == du_mac) else 0
                
                features.append(feature_row)
                
        except Exception as e:
            print(f"Error processing {pcap_file}: {e}")
            return pd.DataFrame()
        
        df = pd.DataFrame(features)
        print(f"✅ Extracted {len(df)} features from {len(packets)} packets")
        return df
    
    def extract_log_features(self, log_file: str) -> pd.DataFrame:
        """Extract UE event features from log files"""
        print(f"📄 Extracting UE event features from {log_file}")
        
        features = []
        
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                    
                feature_row = {
                    'line_number': i,
                    'line_length': len(line),
                    'contains_attach': 1 if 'attach' in line.lower() else 0,
                    'contains_detach': 1 if 'detach' in line.lower() else 0,
                    'contains_handover': 1 if 'handover' in line.lower() else 0,
                    'contains_context': 1 if 'context' in line.lower() else 0,
                    'contains_failure': 1 if any(word in line.lower() for word in ['fail', 'error', 'timeout', 'drop']) else 0,
                    'contains_success': 1 if any(word in line.lower() for word in ['success', 'complete', 'established']) else 0,
                    'numeric_count': sum(c.isdigit() for c in line),
                    'special_char_count': sum(not c.isalnum() and not c.isspace() for c in line),
                    'word_count': len(line.split()),
                    'contains_ue_id': 1 if any(part.isdigit() and len(part) > 10 for part in line.split()) else 0,
                    'contains_timestamp': 1 if any(char in line for char in [':']) and any(char.isdigit() for char in line) else 0
                }
                
                features.append(feature_row)
                
        except Exception as e:
            print(f"Error processing {log_file}: {e}")
            return pd.DataFrame()
        
        df = pd.DataFrame(features)
        print(f"✅ Extracted {len(df)} features from {len(lines)} log lines")
        return df
    
    def create_training_dataset(self, data_dir: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Create comprehensive training dataset from PCAP and log files"""
        print(f"🗂️  Creating training dataset from {data_dir}")
        
        all_features = []
        labels = []
        
        # Process PCAP files
        pcap_files = [f for f in os.listdir(data_dir) if f.endswith('.pcap')]
        for pcap_file in pcap_files:
            file_path = os.path.join(data_dir, pcap_file)
            features = self.extract_pcap_features(file_path)
            
            if not features.empty:
                # Label anomalies based on file naming convention
                is_anomaly = any(keyword in pcap_file.lower() for keyword in 
                               ['anomaly', 'error', 'violation', 'failure', 'timeout'])
                
                features['file_type'] = 'pcap'
                features['source_file'] = pcap_file
                features['label'] = 1 if is_anomaly else 0
                all_features.append(features)
        
        # Process log files
        log_files = [f for f in os.listdir(data_dir) if f.endswith('.txt') or f.endswith('.log')]
        for log_file in log_files:
            file_path = os.path.join(data_dir, log_file)
            features = self.extract_log_features(file_path)
            
            if not features.empty:
                is_anomaly = any(keyword in log_file.lower() for keyword in 
                               ['anomaly', 'error', 'violation', 'failure', 'timeout'])
                
                features['file_type'] = 'log'
                features['source_file'] = log_file
                features['label'] = 1 if is_anomaly else 0
                all_features.append(features)
        
        if not all_features:
            print("❌ No training data found")
            return pd.DataFrame(), pd.DataFrame()
        
        # Combine all features
        combined_df = pd.concat(all_features, ignore_index=True)
        
        # Separate features and labels
        feature_cols = [col for col in combined_df.columns if col not in ['label', 'source_file']]
        X = combined_df[feature_cols]
        y = combined_df['label']
        
        print(f"✅ Created dataset: {len(X)} samples, {len(feature_cols)} features")
        print(f"   Normal samples: {len(y[y == 0])}")
        print(f"   Anomaly samples: {len(y[y == 1])}")
        
        return X, y
    
    def train_isolation_forest(self, X_train: pd.DataFrame, contamination: float = 0.1) -> IsolationForest:
        """Train Isolation Forest for anomaly detection"""
        print("🌲 Training Isolation Forest...")
        
        # Grid search for best parameters
        param_grid = {
            'contamination': [0.05, 0.1, 0.15, 0.2],
            'n_estimators': [100, 200, 300],
            'max_samples': ['auto', 0.8, 1.0]
        }
        
        model = IsolationForest(random_state=42)
        grid_search = GridSearchCV(model, param_grid, cv=3, scoring='roc_auc')
        grid_search.fit(X_train)
        
        best_model = grid_search.best_estimator_
        print(f"   Best parameters: {grid_search.best_params_}")
        
        return best_model
    
    def train_dbscan(self, X_train: pd.DataFrame) -> DBSCAN:
        """Train DBSCAN clustering for anomaly detection"""
        print("🔗 Training DBSCAN...")
        
        # Find optimal eps using knee method
        from sklearn.neighbors import NearestNeighbors
        neighbors = NearestNeighbors(n_neighbors=5)
        neighbors_fit = neighbors.fit(X_train)
        distances, indices = neighbors_fit.kneighbors(X_train)
        distances = np.sort(distances[:, 4], axis=0)
        
        # Use elbow method to find optimal eps
        eps = np.percentile(distances, 95)
        
        model = DBSCAN(eps=eps, min_samples=5)
        model.fit(X_train)
        
        print(f"   Optimal eps: {eps:.4f}")
        print(f"   Clusters found: {len(set(model.labels_)) - (1 if -1 in model.labels_ else 0)}")
        
        return model
    
    def train_one_class_svm(self, X_train: pd.DataFrame) -> OneClassSVM:
        """Train One-Class SVM for anomaly detection"""
        print("🎯 Training One-Class SVM...")
        
        param_grid = {
            'nu': [0.01, 0.05, 0.1, 0.2],
            'gamma': ['scale', 'auto', 0.001, 0.01, 0.1]
        }
        
        model = OneClassSVM()
        grid_search = GridSearchCV(model, param_grid, cv=3, scoring='roc_auc')
        grid_search.fit(X_train)
        
        best_model = grid_search.best_estimator_
        print(f"   Best parameters: {grid_search.best_params_}")
        
        return best_model
    
    def train_random_forest(self, X_train: pd.DataFrame, y_train: pd.Series) -> RandomForestClassifier:
        """Train Random Forest classifier for supervised anomaly detection"""
        print("🌳 Training Random Forest...")
        
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        model = RandomForestClassifier(random_state=42)
        grid_search = GridSearchCV(model, param_grid, cv=5, scoring='roc_auc')
        grid_search.fit(X_train, y_train)
        
        best_model = grid_search.best_estimator_
        print(f"   Best parameters: {grid_search.best_params_}")
        
        return best_model
    
    def train_ensemble_models(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
        """Train all models in ensemble"""
        print("🤖 Training ML Ensemble for L1 Network Anomaly Detection")
        print("=" * 60)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=X_train.columns)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=X_test.columns)
        
        # Train models
        models = {}
        
        # Unsupervised models
        models['isolation_forest'] = self.train_isolation_forest(X_train_scaled)
        models['dbscan'] = self.train_dbscan(X_train_scaled)
        models['one_class_svm'] = self.train_one_class_svm(X_train_scaled)
        
        # Supervised model
        models['random_forest'] = self.train_random_forest(X_train_scaled, y_train)
        
        # Evaluate models
        print("\n📊 Model Evaluation Results:")
        print("-" * 40)
        
        evaluation_results = {}
        for name, model in models.items():
            if name == 'random_forest':
                y_pred = model.predict(X_test_scaled)
                y_score = model.predict_proba(X_test_scaled)[:, 1]
            elif name == 'dbscan':
                y_pred = (model.fit_predict(X_test_scaled) == -1).astype(int)
                y_score = y_pred  # DBSCAN doesn't provide probability scores
            else:
                y_pred = (model.predict(X_test_scaled) == -1).astype(int)
                y_score = model.decision_function(X_test_scaled)
            
            # Calculate metrics
            if name != 'dbscan':
                auc_score = roc_auc_score(y_test, y_score)
                evaluation_results[name] = {'auc': auc_score}
                print(f"{name}: AUC = {auc_score:.4f}")
            else:
                evaluation_results[name] = {'auc': 'N/A (no probability scores)'}
                print(f"{name}: Clustering-based detection")
            
            print(f"Classification Report for {name}:")
            print(classification_report(y_test, y_pred))
            print()
        
        # Store training metadata
        training_info = {
            'timestamp': datetime.now().isoformat(),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'feature_count': len(X.columns),
            'evaluation_results': evaluation_results
        }
        
        return {
            'models': models,
            'scaler': scaler,
            'training_info': training_info,
            'feature_columns': X.columns.tolist()
        }
    
    def save_trained_models(self, trained_data: Dict[str, Any], output_dir: str = 'trained_models'):
        """Save trained models and metadata"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save models
        for name, model in trained_data['models'].items():
            model_path = os.path.join(output_dir, f'{name}_model.pkl')
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            print(f"💾 Saved {name} model to {model_path}")
        
        # Save scaler
        scaler_path = os.path.join(output_dir, 'scaler.pkl')
        with open(scaler_path, 'wb') as f:
            pickle.dump(trained_data['scaler'], f)
        print(f"💾 Saved scaler to {scaler_path}")
        
        # Save metadata
        metadata_path = os.path.join(output_dir, 'training_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(trained_data['training_info'], f, indent=2)
        print(f"💾 Saved training metadata to {metadata_path}")
        
        # Save feature columns
        features_path = os.path.join(output_dir, 'feature_columns.json')
        with open(features_path, 'w') as f:
            json.dump(trained_data['feature_columns'], f, indent=2)
        print(f"💾 Saved feature columns to {features_path}")
    
    def load_trained_models(self, model_dir: str = 'trained_models') -> Dict[str, Any]:
        """Load trained models for inference"""
        models = {}
        
        model_files = {
            'isolation_forest': 'isolation_forest_model.pkl',
            'dbscan': 'dbscan_model.pkl',
            'one_class_svm': 'one_class_svm_model.pkl',
            'random_forest': 'random_forest_model.pkl'
        }
        
        for name, filename in model_files.items():
            model_path = os.path.join(model_dir, filename)
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    models[name] = pickle.load(f)
                print(f"✅ Loaded {name} model from {model_path}")
        
        # Load scaler
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        scaler = None
        if os.path.exists(scaler_path):
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)
            print(f"✅ Loaded scaler from {scaler_path}")
        
        return {'models': models, 'scaler': scaler}

def main():
    """Main training function"""
    print("🤖 L1 Network ML Model Training System")
    print("=" * 50)
    
    # Initialize trainer
    trainer = L1NetworkMLTrainer()
    
    # Check if training data directory exists
    data_dir = 'training_data'
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        print(f"📁 Created training data directory: {data_dir}")
        print("   Please add your PCAP files and log files to this directory")
        print("   Files with 'anomaly', 'error', 'violation', 'failure' in name will be labeled as anomalies")
        return
    
    # Create dataset
    X, y = trainer.create_training_dataset(data_dir)
    
    if X.empty:
        print("❌ No training data found. Please add PCAP and log files to training_data/ directory")
        return
    
    # Train models
    trained_data = trainer.train_ensemble_models(X, y)
    
    # Save models
    trainer.save_trained_models(trained_data)
    
    print("\n🎉 Training completed successfully!")
    print("💾 Models saved to trained_models/ directory")
    print("🚀 Ready for production deployment")

if __name__ == "__main__":
    main()