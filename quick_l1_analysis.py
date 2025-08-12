#!/usr/bin/env python3
"""
Quick L1 Analysis Script
Simple command-line interface for comprehensive L1 troubleshooting analysis
Uses default directory structure: /home/users/praveen.joe/L1/
"""

import sys
import os
from comprehensive_l1_analyzer import ComprehensiveL1Analyzer

def main():
    """Main function for quick L1 analysis"""
    
    print("=== COMPREHENSIVE L1 TROUBLESHOOTING ANALYZER ===")
    print("Covers: UE Events, Fronthaul, MAC, Protocols, Signal Quality, Performance")
    print("Default directory: /home/users/praveen.joe/L1/")
    print()
    
    # Initialize analyzer with default paths
    analyzer = ComprehensiveL1Analyzer()
    
    # Handle command line arguments
    if len(sys.argv) < 2:
        print("Usage Options:")
        print("1. Create directory structure:")
        print("   python3 quick_l1_analysis.py --setup")
        print()
        print("2. Train models (put clean files in /home/users/praveen.joe/L1/training_data/normal/):")
        print("   python3 quick_l1_analysis.py --train")
        print()
        print("3. Analyze single file:")
        print("   python3 quick_l1_analysis.py /path/to/file.pcap")
        print("   python3 quick_l1_analysis.py /path/to/ue_measurements.txt")
        print()
        print("4. Batch analyze directory:")
        print("   python3 quick_l1_analysis.py /path/to/directory/ --batch")
        print()
        print("Required folder structure will be:")
        print("/home/users/praveen.joe/L1/")
        print("├── training_data/")
        print("│   ├── normal/          # Put clean UE files here")
        print("│   ├── anomalous/       # Optional: problematic files")
        print("│   └── validation/      # Optional: test files")
        print("├── models/              # Trained models storage")
        print("├── results/             # Analysis outputs")
        print("└── production_data/     # Files to analyze")
        return
    
    command = sys.argv[1]
    
    # Setup directory structure
    if command == "--setup":
        analyzer.ensure_directories()
        print("✅ Default directory structure created!")
        print()
        print("Next steps:")
        print("1. Place clean UE event files (PCAP/HDF5 text) in:")
        print("   /home/users/praveen.joe/L1/training_data/normal/")
        print()
        print("2. Train models:")
        print("   python3 quick_l1_analysis.py --train")
        return
    
    # Train models
    elif command == "--train":
        print("Training comprehensive L1 models...")
        success = analyzer.train_with_default_paths()
        
        if success:
            print("✅ Model training completed successfully!")
            print()
            print("Models saved in: /home/users/praveen.joe/L1/models/")
            print()
            print("Now you can analyze files:")
            print("  python3 quick_l1_analysis.py your_file.pcap")
        else:
            print("❌ Training failed!")
            print("Make sure you have clean UE event files in:")
            print("/home/users/praveen.joe/L1/training_data/normal/")
        return
    
    # Check if it's a file or directory
    elif os.path.exists(command):
        # Check for batch mode
        batch_mode = len(sys.argv) > 2 and sys.argv[2] == "--batch"
        
        if os.path.isfile(command):
            # Single file analysis
            print(f"Analyzing file: {os.path.basename(command)}")
            results = analyzer.analyze_comprehensive_l1(command)
            
            if results:
                # Save results
                output_dir = "/home/users/praveen.joe/L1/results/analysis_reports"
                os.makedirs(output_dir, exist_ok=True)
                
                import json
                from datetime import datetime
                
                output_file = os.path.join(
                    output_dir, 
                    f"{os.path.basename(command)}_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
                
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                
                print(f"\n✅ Analysis complete!")
                print(f"📊 Results saved: {output_file}")
                print(f"🏥 Health Score: {results['summary']['overall_health_score']}/100")
                print(f"⚠️  Total Anomalies: {results['summary']['total_anomalies']}")
            
        elif os.path.isdir(command) and batch_mode:
            # Batch directory analysis
            print(f"Batch analyzing directory: {command}")
            
            files_processed = 0
            total_anomalies = 0
            
            for filename in os.listdir(command):
                file_path = os.path.join(command, filename)
                
                if os.path.isfile(file_path):
                    print(f"\n--- Processing: {filename} ---")
                    results = analyzer.analyze_comprehensive_l1(file_path)
                    
                    if results:
                        files_processed += 1
                        total_anomalies += results['summary']['total_anomalies']
            
            print(f"\n✅ Batch analysis complete!")
            print(f"📁 Files processed: {files_processed}")
            print(f"⚠️  Total anomalies found: {total_anomalies}")
            print(f"📊 Results saved in: /home/users/praveen.joe/L1/results/")
        
        else:
            print("❌ Invalid path or missing --batch flag for directory")
            print("Use: python3 quick_l1_analysis.py /path/to/directory/ --batch")
    
    else:
        print(f"❌ File/directory not found: {command}")

if __name__ == "__main__":
    main()