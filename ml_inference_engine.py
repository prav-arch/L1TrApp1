#!/usr/bin/env python3
"""
ML Inference Engine for L1 Network Troubleshooting
Real-time anomaly detection using trained ML models
"""

import numpy as np
import pandas as pd
import pickle
import json
import os
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import logging
from ml_model_trainer import L1NetworkMLTrainer

class L1MLInferenceEngine:
    """
    Production inference engine for L1 network anomaly detection
    Uses trained ML models for real-time analysis
    """
    
    def __init__(self, model_dir: str = 'trained_models'):
        self.model_dir = model_dir
        self.models = {}
        self.scaler = None
        self.feature_columns = []
        self.trainer = L1NetworkMLTrainer()
        self.confidence_threshold = 0.7  # Minimum confidence for anomaly detection
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Load models on initialization
        self.load_models()
    
    def load_models(self) -> bool:
        """Load all trained models and preprocessing components"""
        try:
            # Load individual models
            model_files = {
                'isolation_forest': 'isolation_forest_model.pkl',
                'dbscan': 'dbscan_model.pkl', 
                'one_class_svm': 'one_class_svm_model.pkl',
                'random_forest': 'random_forest_model.pkl'
            }
            
            self.models = {}
            for name, filename in model_files.items():
                model_path = os.path.join(self.model_dir, filename)
                if os.path.exists(model_path):
                    with open(model_path, 'rb') as f:
                        self.models[name] = pickle.load(f)
                    self.logger.info(f"✅ Loaded {name} model")
                else:
                    self.logger.warning(f"⚠️  Model file not found: {model_path}")
            
            # Load scaler
            scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.logger.info("✅ Loaded feature scaler")
            
            # Load feature columns
            features_path = os.path.join(self.model_dir, 'feature_columns.json')
            if os.path.exists(features_path):
                with open(features_path, 'r') as f:
                    self.feature_columns = json.load(f)
                self.logger.info(f"✅ Loaded {len(self.feature_columns)} feature columns")
            
            # Load training metadata
            metadata_path = os.path.join(self.model_dir, 'training_metadata.json')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    self.training_metadata = json.load(f)
                self.logger.info("✅ Loaded training metadata")
            
            if len(self.models) == 0:
                self.logger.error("❌ No models loaded. Run training first!")
                return False
                
            self.logger.info(f"🚀 ML Inference Engine ready with {len(self.models)} models")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load models: {e}")
            return False
    
    def preprocess_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess features for model inference"""
        try:
            # Ensure all required columns are present
            missing_cols = set(self.feature_columns) - set(features_df.columns)
            if missing_cols:
                self.logger.warning(f"Missing feature columns: {missing_cols}")
                # Add missing columns with default values
                for col in missing_cols:
                    features_df[col] = 0
            
            # Select only required columns in correct order
            features_df = features_df[self.feature_columns]
            
            # Handle missing values
            features_df = features_df.fillna(0)
            
            # Scale features if scaler is available
            if self.scaler is not None:
                features_scaled = self.scaler.transform(features_df)
                features_df = pd.DataFrame(features_scaled, columns=self.feature_columns)
            
            return features_df
            
        except Exception as e:
            self.logger.error(f"❌ Feature preprocessing failed: {e}")
            return features_df
    
    def predict_anomalies(self, features_df: pd.DataFrame) -> Dict[str, Any]:
        """Run inference on features using all available models"""
        
        if features_df.empty:
            return {'predictions': {}, 'ensemble_prediction': [], 'confidence_scores': []}
        
        # Preprocess features
        features_processed = self.preprocess_features(features_df)
        
        predictions = {}
        confidence_scores = {}
        
        try:
            # Get predictions from each model
            for model_name, model in self.models.items():
                try:
                    if model_name == 'random_forest':
                        # Supervised model - returns probabilities
                        pred_proba = model.predict_proba(features_processed)
                        if pred_proba.shape[1] > 1:
                            pred = pred_proba[:, 1] > 0.5  # Anomaly class
                            confidence = pred_proba[:, 1]
                        else:
                            pred = model.predict(features_processed)
                            confidence = np.abs(pred)
                            
                    elif model_name == 'dbscan':
                        # Clustering model - fit and predict
                        pred = model.fit_predict(features_processed) == -1  # -1 indicates anomaly
                        confidence = np.ones(len(pred)) * 0.5  # DBSCAN doesn't provide confidence
                        
                    else:
                        # Unsupervised models (Isolation Forest, One-Class SVM)
                        pred = model.predict(features_processed) == -1  # -1 indicates anomaly
                        # Get decision function scores as confidence
                        if hasattr(model, 'decision_function'):
                            decision_scores = model.decision_function(features_processed)
                            # Convert to 0-1 range (lower scores = higher anomaly probability)
                            confidence = 1 / (1 + np.exp(decision_scores))
                        else:
                            confidence = np.ones(len(pred)) * 0.5
                    
                    predictions[model_name] = pred.astype(int)
                    confidence_scores[model_name] = confidence
                    
                except Exception as model_error:
                    self.logger.error(f"❌ {model_name} prediction failed: {model_error}")
                    predictions[model_name] = np.zeros(len(features_processed))
                    confidence_scores[model_name] = np.zeros(len(features_processed))
            
            # Ensemble prediction using weighted voting
            ensemble_prediction = self.ensemble_vote(predictions, confidence_scores)
            
            return {
                'predictions': predictions,
                'ensemble_prediction': ensemble_prediction,
                'confidence_scores': confidence_scores,
                'feature_count': len(features_processed.columns),
                'sample_count': len(features_processed)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Prediction failed: {e}")
            return {'predictions': {}, 'ensemble_prediction': [], 'confidence_scores': {}}
    
    def ensemble_vote(self, predictions: Dict[str, np.ndarray], 
                     confidence_scores: Dict[str, np.ndarray]) -> List[Dict[str, Any]]:
        """Combine model predictions using weighted ensemble voting"""
        
        # Model weights based on typical performance
        weights = {
            'isolation_forest': 0.25,
            'dbscan': 0.15, 
            'one_class_svm': 0.20,
            'random_forest': 0.40
        }
        
        if not predictions:
            return []
        
        # Get number of samples
        sample_count = len(next(iter(predictions.values())))
        ensemble_results = []
        
        for i in range(sample_count):
            weighted_score = 0
            total_weight = 0
            model_votes = {}
            
            for model_name, pred_array in predictions.items():
                if model_name in weights and i < len(pred_array):
                    weight = weights[model_name]
                    prediction = pred_array[i]
                    confidence = confidence_scores.get(model_name, [0.5])[i] if i < len(confidence_scores.get(model_name, [])) else 0.5
                    
                    # Weighted voting
                    weighted_score += weight * prediction * confidence
                    total_weight += weight
                    model_votes[model_name] = {'prediction': int(prediction), 'confidence': float(confidence)}
            
            # Final ensemble decision
            final_score = weighted_score / total_weight if total_weight > 0 else 0
            is_anomaly = final_score > self.confidence_threshold
            
            ensemble_results.append({
                'is_anomaly': bool(is_anomaly),
                'confidence': float(final_score),
                'model_votes': model_votes,
                'agreement_count': sum(1 for vote in model_votes.values() if vote['prediction'] == 1)
            })
        
        return ensemble_results
    
    def analyze_file(self, file_path: str, file_type: str = 'auto') -> Dict[str, Any]:
        """Analyze a single file (PCAP or log) for anomalies"""
        
        self.logger.info(f"🔍 Analyzing file: {file_path}")
        
        try:
            # Determine file type if not specified
            if file_type == 'auto':
                if file_path.endswith('.pcap') or file_path.endswith('.cap'):
                    file_type = 'pcap'
                elif file_path.endswith('.txt') or file_path.endswith('.log'):
                    file_type = 'log'
                else:
                    self.logger.warning(f"⚠️  Unknown file type for {file_path}")
                    file_type = 'pcap'  # Default assumption
            
            # Extract features based on file type
            if file_type == 'pcap':
                features_df = self.trainer.extract_pcap_features(file_path)
            else:
                features_df = self.trainer.extract_log_features(file_path)
            
            if features_df.empty:
                self.logger.warning(f"⚠️  No features extracted from {file_path}")
                return {'anomalies': [], 'summary': {'total_samples': 0, 'anomalies_found': 0}}
            
            # Run ML inference
            ml_results = self.predict_anomalies(features_df)
            
            # Format results for output
            anomalies = []
            ensemble_predictions = ml_results.get('ensemble_prediction', [])
            
            for i, result in enumerate(ensemble_predictions):
                if result['is_anomaly']:
                    anomaly = {
                        'packet_number': i + 1,
                        'confidence': result['confidence'],
                        'model_agreement': result['agreement_count'],
                        'model_votes': result['model_votes'],
                        'timestamp': datetime.now().isoformat(),
                        'source_file': os.path.basename(file_path),
                        'file_type': file_type
                    }
                    anomalies.append(anomaly)
            
            # Generate summary
            summary = {
                'total_samples': len(features_df),
                'anomalies_found': len(anomalies),
                'anomaly_rate': len(anomalies) / len(features_df) if len(features_df) > 0 else 0,
                'average_confidence': np.mean([a['confidence'] for a in anomalies]) if anomalies else 0,
                'models_used': list(self.models.keys()),
                'file_processed': file_path
            }
            
            self.logger.info(f"✅ Analysis complete: {summary['anomalies_found']}/{summary['total_samples']} anomalies detected")
            
            return {
                'anomalies': anomalies,
                'summary': summary,
                'ml_results': ml_results
            }
            
        except Exception as e:
            self.logger.error(f"❌ File analysis failed: {e}")
            return {'anomalies': [], 'summary': {'error': str(e)}}
    
    def batch_analyze_directory(self, directory_path: str) -> Dict[str, Any]:
        """Analyze all files in a directory"""
        
        self.logger.info(f"📁 Batch analyzing directory: {directory_path}")
        
        if not os.path.exists(directory_path):
            return {'error': f'Directory not found: {directory_path}'}
        
        results = {}
        total_anomalies = 0
        total_files = 0
        
        # Get all supported files
        supported_extensions = ['.pcap', '.cap', '.txt', '.log']
        files = [f for f in os.listdir(directory_path) 
                if any(f.lower().endswith(ext) for ext in supported_extensions)]
        
        for filename in files:
            file_path = os.path.join(directory_path, filename)
            result = self.analyze_file(file_path)
            
            results[filename] = result
            total_anomalies += result.get('summary', {}).get('anomalies_found', 0)
            total_files += 1
        
        batch_summary = {
            'total_files_processed': total_files,
            'total_anomalies_found': total_anomalies,
            'files_with_anomalies': sum(1 for r in results.values() 
                                       if r.get('summary', {}).get('anomalies_found', 0) > 0),
            'average_anomaly_rate': np.mean([r.get('summary', {}).get('anomaly_rate', 0) 
                                           for r in results.values()]) if results else 0
        }
        
        self.logger.info(f"✅ Batch analysis complete: {batch_summary}")
        
        return {
            'batch_summary': batch_summary,
            'file_results': results
        }

def main():
    """Command-line interface for ML inference"""
    import argparse
    
    parser = argparse.ArgumentParser(description='L1 Network ML Anomaly Detection')
    parser.add_argument('--file', '-f', help='Single file to analyze')
    parser.add_argument('--directory', '-d', help='Directory to analyze')
    parser.add_argument('--model-dir', '-m', default='trained_models', help='Trained models directory')
    parser.add_argument('--output', '-o', help='Output JSON file for results')
    parser.add_argument('--confidence', '-c', type=float, default=0.7, help='Confidence threshold')
    
    args = parser.parse_args()
    
    # Initialize inference engine
    engine = L1MLInferenceEngine(model_dir=args.model_dir)
    engine.confidence_threshold = args.confidence
    
    results = {}
    
    if args.file:
        # Analyze single file
        results = engine.analyze_file(args.file)
        print(f"\n📊 Analysis Results for {args.file}:")
        print(f"   Anomalies found: {results['summary']['anomalies_found']}")
        print(f"   Total samples: {results['summary']['total_samples']}")
        if results['anomalies']:
            print("\n🚨 Detected Anomalies:")
            for anomaly in results['anomalies'][:5]:  # Show first 5
                print(f"   Packet #{anomaly['packet_number']}: {anomaly['confidence']:.3f} confidence")
                
    elif args.directory:
        # Analyze directory
        results = engine.batch_analyze_directory(args.directory)
        print(f"\n📊 Batch Analysis Results:")
        print(f"   Files processed: {results['batch_summary']['total_files_processed']}")
        print(f"   Total anomalies: {results['batch_summary']['total_anomalies_found']}")
        print(f"   Files with anomalies: {results['batch_summary']['files_with_anomalies']}")
        
    else:
        print("❌ Please specify either --file or --directory")
        return
    
    # Save results to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"💾 Results saved to {args.output}")

if __name__ == "__main__":
    main()