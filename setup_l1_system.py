#!/usr/bin/env python3
"""
L1 Troubleshooting System Setup Script
Automatically creates all required directories and provides training/testing workflow
"""

import os
import sys
import json
from datetime import datetime

class L1SystemSetup:
    def __init__(self, user="praveen.joe"):
        self.user = user
        self.base_dir = f"/home/users/{self.user}/L1"
        
        # Directory structure
        self.directories = {
            'base': self.base_dir,
            'training_data': f"{self.base_dir}/training_data",
            'training_normal': f"{self.base_dir}/training_data/normal",
            'training_anomalous': f"{self.base_dir}/training_data/anomalous",
            'training_validation': f"{self.base_dir}/training_data/validation",
            'models': f"{self.base_dir}/models",
            'results': f"{self.base_dir}/results",
            'analysis_reports': f"{self.base_dir}/results/analysis_reports",
            'training_reports': f"{self.base_dir}/results/training_reports",
            'production_data': f"{self.base_dir}/production_data",
            'test_data': f"{self.base_dir}/test_data"
        }
        
        print(f"L1 System Setup for user: {self.user}")
        print(f"Base directory: {self.base_dir}")
    
    def create_directories(self):
        """Create all required directories"""
        print("\n=== CREATING DIRECTORY STRUCTURE ===")
        
        created_dirs = []
        for name, path in self.directories.items():
            try:
                os.makedirs(path, exist_ok=True)
                if os.path.exists(path):
                    print(f"✓ Created: {path}")
                    created_dirs.append(path)
                else:
                    print(f"✗ Failed to create: {path}")
            except Exception as e:
                print(f"✗ Error creating {path}: {e}")
        
        print(f"\n✓ Successfully created {len(created_dirs)} directories")
        return len(created_dirs) > 0
    
    def create_sample_files(self):
        """Create sample configuration and documentation files"""
        print("\n=== CREATING SAMPLE FILES ===")
        
        # README file
        readme_content = f"""# L1 Troubleshooting System - User: {self.user}

## Directory Structure
- training_data/normal/     - Put your clean UE event files here (PCAP/HDF5 text)
- training_data/anomalous/  - Optional: Known problematic files
- training_data/validation/ - Optional: Test files for validation
- models/                   - Trained ML models (auto-generated)
- results/                  - Analysis outputs and reports
- production_data/          - Files to analyze in production
- test_data/               - Sample files for testing

## Quick Start
1. Add clean files to training_data/normal/
2. Run: python3 setup_l1_system.py --train
3. Test: python3 setup_l1_system.py --test

## File Types Supported
- PCAP files (.pcap, .pcapng)
- HDF5 text files (.txt with signal measurements)
- Protocol log files (.log, .txt)
- Fronthaul log files (eCPRI, O-RAN)

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        readme_path = f"{self.base_dir}/README.md"
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        print(f"✓ Created: {readme_path}")
        
        # Training configuration
        config = {
            "user": self.user,
            "base_directory": self.base_dir,
            "training_settings": {
                "algorithms": ["OneClassSVM", "IsolationForest", "DBSCAN", "RandomForest"],
                "feature_scaling": True,
                "validation_split": 0.2,
                "random_state": 42
            },
            "analysis_categories": [
                "ue_events",
                "fronthaul", 
                "mac_layer",
                "protocols",
                "signal_quality",
                "performance"
            ],
            "created_date": datetime.now().isoformat()
        }
        
        config_path = f"{self.base_dir}/l1_config.json"
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✓ Created: {config_path}")
        
        return True
    
    def check_training_data(self):
        """Check if training data is available"""
        normal_dir = self.directories['training_normal']
        
        if not os.path.exists(normal_dir):
            return False, "Training directory does not exist"
        
        files = [f for f in os.listdir(normal_dir) if os.path.isfile(os.path.join(normal_dir, f))]
        
        if len(files) == 0:
            return False, f"No training files found in {normal_dir}"
        
        valid_extensions = ['.pcap', '.pcapng', '.txt', '.log']
        valid_files = [f for f in files if any(f.lower().endswith(ext) for ext in valid_extensions)]
        
        if len(valid_files) == 0:
            return False, f"No valid training files found (need .pcap, .pcapng, .txt, .log)"
        
        return True, f"Found {len(valid_files)} valid training files"
    
    def train_models(self):
        """Train ML models using the comprehensive system"""
        print("\n=== TRAINING ML MODELS ===")
        
        # Check if training data exists
        data_available, message = self.check_training_data()
        if not data_available:
            print(f"✗ {message}")
            print(f"\nPlease add clean UE event files to: {self.directories['training_normal']}")
            print("Supported file types: .pcap, .pcapng, .txt, .log")
            return False
        
        print(f"✓ {message}")
        
        try:
            # Import and use the comprehensive analyzer for training
            from comprehensive_l1_analyzer import ComprehensiveL1Analyzer
            
            analyzer = ComprehensiveL1Analyzer()
            success = analyzer.train_with_default_paths()
            
            if success:
                print("✓ Model training completed successfully!")
                
                # List trained models
                models_dir = self.directories['models']
                if os.path.exists(models_dir):
                    model_dirs = [d for d in os.listdir(models_dir) if os.path.isdir(os.path.join(models_dir, d))]
                    if model_dirs:
                        latest_model = max(model_dirs)
                        print(f"✓ Latest model: {latest_model}")
                
                return True
            else:
                print("✗ Model training failed")
                return False
                
        except Exception as e:
            print(f"✗ Training error: {e}")
            return False
    
    def create_test_files(self):
        """Create sample test files for demonstration"""
        print("\n=== CREATING TEST FILES ===")
        
        test_dir = self.directories['test_data']
        
        # Sample PCAP-like data (text representation)
        sample_pcap_content = """# Sample UE Event Log (simulated PCAP content)
Timestamp: 2025-08-08 14:30:01.123
UE Attach Request: IMSI=123456789012345, Cell_ID=12345
RSRP: -95 dBm, RSRQ: -10 dB, SINR: 15 dB
Attach Accept: Success, TAC=54321

Timestamp: 2025-08-08 14:30:05.456
UE Handover Request: Source_Cell=12345, Target_Cell=12346
X2 Handover: Success, Duration=150ms
RSRP: -88 dBm, RSRQ: -8 dB, SINR: 18 dB

Timestamp: 2025-08-08 14:30:10.789
UE Detach Request: Normal detach
Detach Accept: Success
"""
        
        # Sample HDF5 text data
        sample_hdf5_content = """# Sample UE Measurements (HDF5 converted to text)
Cell_ID,RSRP,RSRQ,SINR,Timestamp
12345,-92,-9,16,2025-08-08T14:30:01.123Z
12345,-94,-10,15,2025-08-08T14:30:02.234Z
12346,-88,-8,18,2025-08-08T14:30:03.345Z
12346,-90,-9,17,2025-08-08T14:30:04.456Z
12345,-96,-12,12,2025-08-08T14:30:05.567Z
"""
        
        # Sample fronthaul log
        sample_fronthaul_content = """# Sample Fronthaul Log (eCPRI/O-RAN)
[2025-08-08 14:30:01] eCPRI: DU-RU Link established
[2025-08-08 14:30:02] O-RAN F1-C: Control plane message sent
[2025-08-08 14:30:03] PTP: Time sync achieved, offset=0.1us
[2025-08-08 14:30:04] eCPRI: User plane data transfer, 1024 bytes
[2025-08-08 14:30:05] eCPRI Error: Sequence number mismatch detected
[2025-08-08 14:30:06] O-RAN F1-U: User plane error recovery initiated
"""
        
        # Sample protocol violation log
        sample_protocol_content = """# Sample Protocol Violation Log
[14:30:01] RRC Connection Request: Valid
[14:30:02] MAC PDU: HARQ Process ID=3, Success
[14:30:03] Protocol Error: Invalid message format detected
[14:30:04] RACH: Preamble detection failure
[14:30:05] Timeout Error: Response timeout after 5000ms
[14:30:06] State Error: Invalid state transition from IDLE to CONNECTED
"""
        
        test_files = {
            'sample_ue_events.txt': sample_pcap_content,
            'sample_measurements.txt': sample_hdf5_content, 
            'sample_fronthaul.log': sample_fronthaul_content,
            'sample_protocol.log': sample_protocol_content
        }
        
        created_files = []
        for filename, content in test_files.items():
            file_path = os.path.join(test_dir, filename)
            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                print(f"✓ Created test file: {filename}")
                created_files.append(file_path)
            except Exception as e:
                print(f"✗ Failed to create {filename}: {e}")
        
        print(f"✓ Created {len(created_files)} test files")
        return created_files
    
    def test_system(self):
        """Test the system with sample files"""
        print("\n=== TESTING L1 ANALYSIS SYSTEM ===")
        
        # Create test files if they don't exist
        test_files = self.create_test_files()
        
        if not test_files:
            print("✗ No test files available")
            return False
        
        try:
            from comprehensive_l1_analyzer import ComprehensiveL1Analyzer
            
            analyzer = ComprehensiveL1Analyzer()
            
            # Test each sample file
            for test_file in test_files[:2]:  # Test first 2 files
                print(f"\n--- Testing: {os.path.basename(test_file)} ---")
                
                try:
                    results = analyzer.analyze_comprehensive_l1(test_file)
                    
                    if results:
                        print(f"✓ Analysis successful")
                        print(f"  Total anomalies: {results['summary']['total_anomalies']}")
                        print(f"  Health score: {results['summary']['overall_health_score']}/100")
                        print(f"  Analysis time: {results['summary']['analysis_duration_seconds']:.2f}s")
                    else:
                        print(f"✗ Analysis failed for {test_file}")
                
                except Exception as e:
                    print(f"✗ Test failed: {e}")
            
            print(f"\n✓ System testing completed")
            return True
            
        except Exception as e:
            print(f"✗ Testing error: {e}")
            return False
    
    def display_status(self):
        """Display current system status"""
        print(f"\n=== L1 SYSTEM STATUS ===")
        
        # Check directories
        print("Directory Status:")
        for name, path in self.directories.items():
            status = "✓" if os.path.exists(path) else "✗"
            print(f"  {status} {name}: {path}")
        
        # Check training data
        data_available, message = self.check_training_data()
        print(f"\nTraining Data: {'✓' if data_available else '✗'} {message}")
        
        # Check models
        models_dir = self.directories['models']
        if os.path.exists(models_dir):
            model_dirs = [d for d in os.listdir(models_dir) if os.path.isdir(os.path.join(models_dir, d))]
            print(f"Trained Models: {'✓' if model_dirs else '✗'} {len(model_dirs)} model(s)")
            if model_dirs:
                for model in model_dirs:
                    print(f"  - {model}")
        else:
            print("Trained Models: ✗ Models directory not found")
    
    def run_setup(self, action=None):
        """Main setup function"""
        if action == "create" or action is None:
            success = self.create_directories()
            if success:
                self.create_sample_files()
                print(f"\n✓ L1 System setup complete!")
                print(f"\nNext steps:")
                print(f"1. Add clean UE event files to: {self.directories['training_normal']}")
                print(f"2. Run training: python3 setup_l1_system.py --train")
                print(f"3. Test system: python3 setup_l1_system.py --test")
        
        elif action == "train":
            self.train_models()
        
        elif action == "test":
            self.test_system()
        
        elif action == "status":
            self.display_status()
        
        else:
            print(f"Unknown action: {action}")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='L1 Troubleshooting System Setup')
    parser.add_argument('--create', action='store_true', help='Create directory structure')
    parser.add_argument('--train', action='store_true', help='Train ML models')
    parser.add_argument('--test', action='store_true', help='Test system with sample data')
    parser.add_argument('--status', action='store_true', help='Show system status')
    parser.add_argument('--user', default='praveen.joe', help='Username for directory structure')
    
    args = parser.parse_args()
    
    # Create setup instance
    setup = L1SystemSetup(user=args.user)
    
    # Determine action
    if args.train:
        action = "train"
    elif args.test:
        action = "test"
    elif args.status:
        action = "status"
    elif args.create:
        action = "create"
    else:
        # Default: create directories and show help
        action = "create"
        print("L1 Troubleshooting System Setup")
        print("Available commands:")
        print("  --create  : Create directory structure (default)")
        print("  --train   : Train ML models")
        print("  --test    : Test system")
        print("  --status  : Show system status")
        print()
    
    # Run setup
    setup.run_setup(action)

if __name__ == "__main__":
    main()