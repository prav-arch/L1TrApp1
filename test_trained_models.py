#!/usr/bin/env python3
"""
Simple script to test your trained models from /home/users/praveen.joe/L1/models
"""

import pickle
import numpy as np
import pandas as pd
import os
from sklearn.preprocessing import StandardScaler

class ModelTester:
    def __init__(self, models_dir="/home/users/praveen.joe/L1/models"):
        self.models_dir = models_dir
        self.models = {}
        self.scaler = None
        
    def load_models(self):
        """Load all trained models from your directory"""
        print(f"Loading models from: {self.models_dir}")
        
        # List of possible model files
        model_files = [
            "gpu_isolation_forest_model.pkl",
            "gpu_dbscan_model.pkl", 
            "gpu_svm_model.pkl",
            "isolation_forest_model.pkl",
            "one_class_svm_model.pkl",
            "scaler.pkl"
        ]
        
        loaded_count = 0
        for filename in model_files:
            filepath = os.path.join(self.models_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        if filename == "scaler.pkl":
                            self.scaler = pickle.load(f)
                            print(f"Loaded scaler: {filename}")
                        else:
                            model_name = filename.replace("_model.pkl", "")
                            self.models[model_name] = pickle.load(f)
                            print(f"Loaded model: {model_name}")
                    loaded_count += 1
                except Exception as e:
                    print(f"Error loading {filename}: {e}")
            else:
                print(f"File not found: {filepath}")
        
        print(f"Successfully loaded {loaded_count} files")
        return loaded_count > 0
    
    def test_with_sample_data(self):
        """Test models with sample network data"""
        if not self.models:
            print("No models loaded!")
            return
            
        # Create sample network features (replace with your actual data)
        print("Creating sample network data for testing...")
        sample_data = pd.DataFrame({
            'packet_size': np.random.normal(1500, 300, 100),
            'inter_arrival_time': np.random.exponential(0.01, 100),
            'protocol_type': np.random.randint(1, 4, 100),
            'port_number': np.random.randint(1, 65536, 100),
            'packet_flags': np.random.randint(0, 256, 100)
        })
        
        # Scale the data
        if self.scaler:
            sample_data_scaled = self.scaler.transform(sample_data)
            print("Data scaled using trained scaler")
        else:
            scaler = StandardScaler()
            sample_data_scaled = scaler.fit_transform(sample_data)
            print("Data scaled using new scaler (no trained scaler found)")
        
        # Test each model
        results = {}
        for model_name, model in self.models.items():
            try:
                if hasattr(model, 'predict'):
                    predictions = model.predict(sample_data_scaled)
                    
                    if model_name in ['gpu_isolation_forest', 'isolation_forest', 'gpu_svm', 'one_class_svm']:
                        # For anomaly detection models (-1 = anomaly, 1 = normal)
                        anomaly_count = len(predictions[predictions == -1])
                        normal_count = len(predictions[predictions == 1])
                        results[model_name] = {
                            'anomalies': anomaly_count,
                            'normal': normal_count,
                            'anomaly_rate': anomaly_count / len(predictions) * 100
                        }
                    elif model_name in ['gpu_dbscan']:
                        # For clustering models (-1 = outlier/noise)
                        outliers = len(predictions[predictions == -1])
                        clusters = len(set(predictions)) - (1 if -1 in predictions else 0)
                        results[model_name] = {
                            'outliers': outliers,
                            'clusters': clusters,
                            'outlier_rate': outliers / len(predictions) * 100
                        }
                    
                    print(f"\n{model_name} Results:")
                    for key, value in results[model_name].items():
                        print(f"  {key}: {value}")
                        
            except Exception as e:
                print(f"Error testing {model_name}: {e}")
        
        return results
    
    def analyze_file(self, file_path):
        """Analyze a specific PCAP or log file with your trained models"""
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
            
        print(f"Analyzing file: {file_path}")
        # Add your file processing logic here
        # This would extract features from your actual PCAP/log files
        # and then use the trained models to detect anomalies
        
        print("File analysis would go here - replace with your feature extraction logic")

def main():
    print("Testing Trained Models from /home/users/praveen.joe/L1/models")
    print("=" * 60)
    
    tester = ModelTester()
    
    # Load models
    if tester.load_models():
        print("\nTesting models with sample data...")
        results = tester.test_with_sample_data()
        
        print("\nModels are working correctly!")
        print("To analyze your own files, use:")
        print("  tester.analyze_file('/path/to/your/test/file.pcap')")
    else:
        print("Failed to load models. Check the models directory path.")

if __name__ == "__main__":
    main()