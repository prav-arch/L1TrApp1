#!/usr/bin/env python3
"""
Demo ML Training with Progress Timestamps
Shows the enhanced training progress indicators working correctly
"""

import time
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

class DemoMLTrainer:
    def __init__(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Demo ML Trainer initialized")
        
        # Initialize models
        self.supervised_svm = OneClassSVM(kernel='rbf', nu=0.1)
        self.supervised_rf = RandomForestClassifier(n_estimators=100, random_state=42)
        self.unsupervised_isolation = IsolationForest(contamination=0.1, random_state=42)
        self.unsupervised_dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()

    def generate_sample_data(self):
        """Generate sample network data for demonstration"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Generating sample network data...")
        
        # Generate normal network traffic patterns
        np.random.seed(42)
        normal_data = np.random.normal(0, 1, (200, 10))  # 200 normal samples, 10 features
        
        # Generate some anomalous patterns
        anomaly_data = np.random.normal(3, 1.5, (20, 10))  # 20 anomaly samples
        
        # Combine data
        X = np.vstack([normal_data, anomaly_data])
        y = np.array([0] * 200 + [1] * 20)  # 0 = normal, 1 = anomaly
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Generated {len(X)} samples ({len(normal_data)} normal, {len(anomaly_data)} anomalies)")
        
        return X, y

    def train_supervised_models(self, X_train, y_train):
        """Train supervised models with timestamp progress"""
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
        """Train unsupervised models with timestamp progress"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Training/tuning unsupervised models...")
        
        # Isolation Forest
        print(f"[{timestamp}] Starting Isolation Forest training...")
        start_time = time.time()
        self.unsupervised_isolation.fit(X_train)
        iso_duration = time.time() - start_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Isolation Forest training complete ({iso_duration:.2f}s)")
        
        # DBSCAN cluster analysis
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

    def evaluate_models(self, X_test, y_test):
        """Evaluate models with detailed progress"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Starting model evaluation...")
        
        results = {}
        
        # Evaluate One-Class SVM
        print(f"[{timestamp}] Evaluating One-Class SVM...")
        svm_pred = self.supervised_svm.predict(X_test)
        svm_pred = np.where(svm_pred == -1, 1, 0)  # Convert to binary
        results['One-Class SVM'] = {
            'accuracy': accuracy_score(y_test, svm_pred),
            'precision': precision_score(y_test, svm_pred, zero_division=0),
            'recall': recall_score(y_test, svm_pred, zero_division=0),
            'f1': f1_score(y_test, svm_pred, zero_division=0)
        }
        
        # Evaluate Random Forest
        print(f"[{timestamp}] Evaluating Random Forest...")
        rf_pred = self.supervised_rf.predict(X_test)
        results['Random Forest'] = {
            'accuracy': accuracy_score(y_test, rf_pred),
            'precision': precision_score(y_test, rf_pred, zero_division=0),
            'recall': recall_score(y_test, rf_pred, zero_division=0),
            'f1': f1_score(y_test, rf_pred, zero_division=0)
        }
        
        # Evaluate Isolation Forest
        print(f"[{timestamp}] Evaluating Isolation Forest...")
        iso_pred = self.unsupervised_isolation.predict(X_test)
        iso_pred = np.where(iso_pred == -1, 1, 0)  # Convert to binary
        results['Isolation Forest'] = {
            'accuracy': accuracy_score(y_test, iso_pred),
            'precision': precision_score(y_test, iso_pred, zero_division=0),
            'recall': recall_score(y_test, iso_pred, zero_division=0),
            'f1': f1_score(y_test, iso_pred, zero_division=0)
        }
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Model evaluation complete")
        
        return results

    def run_training_demo(self):
        """Run complete training demonstration"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Starting L1 ML Training Demo with Progress Tracking")
        print("=" * 70)
        
        # Generate data
        X, y = self.generate_sample_data()
        
        # Preprocess data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Preprocessing data...")
        X_scaled = self.scaler.fit_transform(X)
        
        # Train-test split
        print(f"[{timestamp}] Creating train-test split...")
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42, stratify=y)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Split complete: {len(X_train)} training, {len(X_test)} testing samples")
        
        # Train models
        self.train_supervised_models(X_train, y_train)
        self.train_unsupervised_models(X_train)
        
        # Evaluate models
        results = self.evaluate_models(X_test, y_test)
        
        # Display results
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] TRAINING RESULTS SUMMARY")
        print("=" * 70)
        for model_name, metrics in results.items():
            print(f"\n{model_name}:")
            print(f"  Accuracy:  {metrics['accuracy']:.3f}")
            print(f"  Precision: {metrics['precision']:.3f}")
            print(f"  Recall:    {metrics['recall']:.3f}")
            print(f"  F1-Score:  {metrics['f1']:.3f}")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] L1 ML Training Demo completed successfully!")
        print("✓ All training steps completed with detailed progress tracking")
        print("✓ No hanging or unclear status during training")
        print("✓ Timestamps show exact timing for each phase")
        
        return results

def main():
    """Main function to run the demo"""
    trainer = DemoMLTrainer()
    results = trainer.run_training_demo()
    return results

if __name__ == "__main__":
    main()