# L1 Troubleshooting System - Complete Setup Steps

## Automated Setup and Usage Guide

### Prerequisites
- Python 3.7+ installed
- Required packages: scapy, scikit-learn, numpy, pandas, clickhouse-connect (optional)

## Step-by-Step Instructions

### Step 1: Create Directory Structure
```bash
# Run the automated setup script
python3 setup_l1_system.py --create
```

**What this does:**
- Creates `/home/users/praveen.joe/L1/` directory structure
- Sets up training, models, results, and test directories
- Creates README.md and configuration files
- Generates sample test files

**Expected Output:**
```
=== CREATING DIRECTORY STRUCTURE ===
✓ Created: /home/users/praveen.joe/L1
✓ Created: /home/users/praveen.joe/L1/training_data
✓ Created: /home/users/praveen.joe/L1/training_data/normal
✓ Created: /home/users/praveen.joe/L1/training_data/anomalous
...
✓ L1 System setup complete!
```

### Step 2: Add Your Training Data
```bash
# Copy your clean UE event files to the training directory
cp your_clean_ue_attach.pcap /home/users/praveen.joe/L1/training_data/normal/
cp your_measurements.txt /home/users/praveen.joe/L1/training_data/normal/
cp your_fronthaul_logs.log /home/users/praveen.joe/L1/training_data/normal/

# Optional: Add known problematic files
cp problematic_files* /home/users/praveen.joe/L1/training_data/anomalous/
```

**Supported File Types:**
- PCAP files (`.pcap`, `.pcapng`)
- HDF5 text files (`.txt` with signal measurements)
- Protocol logs (`.log`, `.txt`)
- Fronthaul logs (eCPRI, O-RAN)

### Step 3: Train the Models
```bash
# Train ML models using your data
python3 setup_l1_system.py --train
```

**What this does:**
- Loads all files from `/home/users/praveen.joe/L1/training_data/normal/`
- Trains 4 ML algorithms: OneClassSVM, IsolationForest, DBSCAN, RandomForest
- Creates feature scaling and preprocessing pipelines
- Saves trained models with timestamp
- Generates training performance reports

**Expected Output:**
```
=== TRAINING ML MODELS ===
✓ Found 5 valid training files
Comprehensive L1 Analyzer initialized
Training hybrid ML models...
✓ Model training completed successfully!
✓ Latest model: hybrid_training_20250808_143000
```

### Step 4: Test the System
```bash
# Test with sample files
python3 setup_l1_system.py --test
```

**What this does:**
- Creates sample test files covering all L1 scenarios
- Runs comprehensive analysis on test files
- Demonstrates all analysis categories
- Shows health scores and anomaly detection

### Step 5: Check System Status
```bash
# View complete system status
python3 setup_l1_system.py --status
```

**Shows:**
- Directory structure status
- Training data availability
- Trained model information
- System readiness

## Production Usage

### Analyze Single File
```bash
# Use the quick interface
python3 quick_l1_analysis.py /path/to/your_file.pcap

# Or use the comprehensive analyzer directly
python3 comprehensive_l1_analyzer.py /path/to/your_file.pcap
```

### Batch Process Multiple Files
```bash
# Process entire directory
python3 quick_l1_analysis.py /path/to/directory/ --batch
```

### Analysis Output Example
```
COMPREHENSIVE L1 ANALYSIS RESULTS
================================================================================
File: ue_events.pcap
Format: pcap
Analysis Time: 2025-08-08T14:30:15.123456

OVERALL SUMMARY:
  Total Anomalies: 12
  Overall Health Score: 78.5/100
  Analysis Duration: 2.34 seconds

SEVERITY BREAKDOWN:
  High: 2
  Medium: 5
  Low: 5

CATEGORY BREAKDOWN:
  UE Events: 3
  Fronthaul: 2
  MAC Layer: 4
  Protocols: 2
  Signal Quality: 1
  Performance: 0

TOP COMPREHENSIVE ANOMALIES:
  1. [Fronthaul] HIGH - eCPRI communication error: sequence mismatch (Confidence: 0.892)
  2. [UE Events] HIGH - UE Detach procedure with poor signal quality (Confidence: 0.845)
  3. [MAC Layer] MEDIUM - HARQ process failure detected (Confidence: 0.734)
  ...
```

## Directory Structure Created

```
/home/users/praveen.joe/L1/
├── training_data/
│   ├── normal/              # PUT YOUR CLEAN FILES HERE
│   ├── anomalous/           # Optional: problematic files
│   └── validation/          # Optional: validation files
├── models/                  # Trained models (auto-generated)
│   └── hybrid_training_YYYYMMDD_HHMMSS/
│       ├── hybrid_models.pkl
│       ├── feature_scaler.pkl
│       ├── training_report.json
│       └── model_metadata.json
├── results/                 # Analysis outputs
│   ├── analysis_reports/    # Individual file analysis
│   └── training_reports/    # Training performance logs
├── production_data/         # Optional: files to analyze
├── test_data/              # Sample test files
├── README.md               # System documentation
└── l1_config.json          # Configuration file
```

## Troubleshooting

### "No training files found"
```bash
# Check if files are in correct directory
ls -la /home/users/praveen.joe/L1/training_data/normal/

# Verify file extensions are supported (.pcap, .txt, .log)
```

### "Training failed" 
```bash
# Check file permissions
chmod 644 /home/users/praveen.joe/L1/training_data/normal/*

# Verify file formats are valid
file /home/users/praveen.joe/L1/training_data/normal/*
```

### "Analysis error"
```bash
# Check system status
python3 setup_l1_system.py --status

# Verify trained models exist
ls -la /home/users/praveen.joe/L1/models/
```

## Complete Workflow Summary

```bash
# 1. Create system (one time)
python3 setup_l1_system.py --create

# 2. Add your clean UE files to training_data/normal/

# 3. Train models (when you have new data)
python3 setup_l1_system.py --train

# 4. Test system
python3 setup_l1_system.py --test

# 5. Analyze production files
python3 quick_l1_analysis.py your_production_file.pcap
```

The system is now ready for comprehensive L1 troubleshooting analysis covering:
- **UE Events** (Attach/Detach, Handover)
- **Fronthaul Issues** (DU-RU, eCPRI, Timing)
- **MAC Layer** (Address, HARQ, RACH)
- **Protocol Violations** (3GPP compliance)
- **Signal Quality** (RSRP/RSRQ/SINR)
- **Network Performance** (Throughput, Latency)

All in a single comprehensive analysis with cross-correlation and health scoring!