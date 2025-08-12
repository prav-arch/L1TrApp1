# Comprehensive L1 Troubleshooting System
## Complete Setup and Usage Guide

### Overview
This system provides **single comprehensive analysis** covering all L1 troubleshooting scenarios:
- **UE Events**: Attach/Detach, Handover, RRC Connection procedures
- **Fronthaul Issues**: DU-RU communication, eCPRI errors, timing synchronization
- **MAC Layer**: Address anomalies, HARQ failures, RACH issues, scheduling errors  
- **Protocol Violations**: 3GPP standard violations, sequence errors, timeouts
- **Signal Quality**: RSRP/RSRQ/SINR analysis, interference detection
- **Network Performance**: Throughput drops, latency spikes, packet loss

### Directory Structure for User: praveen.joe

```bash
/home/users/praveen.joe/L1/
├── training_data/
│   ├── normal/          # Clean UE files (REQUIRED for training)
│   ├── anomalous/       # Known problematic files (OPTIONAL)
│   └── validation/      # Test files (OPTIONAL)
├── models/              # Trained model storage (auto-created)
├── results/             # Analysis outputs (auto-created)
│   ├── analysis_reports/
│   └── training_reports/
└── production_data/     # Files to analyze (optional)
```

## Quick Start (3 Steps)

### Step 1: Setup Directory Structure
```bash
python3 quick_l1_analysis.py --setup
```
This creates all required directories automatically.

### Step 2: Add Training Data
```bash
# Copy your clean UE event files to training directory
cp your_clean_ue_attach.pcap /home/users/praveen.joe/L1/training_data/normal/
cp your_clean_measurements.txt /home/users/praveen.joe/L1/training_data/normal/
cp more_clean_files* /home/users/praveen.joe/L1/training_data/normal/

# Optional: Add known problematic files for supervised learning
cp problematic_files* /home/users/praveen.joe/L1/training_data/anomalous/
```

### Step 3: Train Models
```bash
python3 quick_l1_analysis.py --train
```
This automatically trains hybrid ML models on your clean data.

## Usage

### Analyze Single File
```bash
# Analyze any UE event file (PCAP or HDF5 text)
python3 quick_l1_analysis.py /path/to/ue_events.pcap
python3 quick_l1_analysis.py /path/to/measurements.txt
python3 quick_l1_analysis.py /path/to/fronthaul_log.txt
```

### Batch Analyze Directory
```bash
# Process all files in a directory
python3 quick_l1_analysis.py /path/to/directory/ --batch
```

## What the Analysis Covers

### File Format Auto-Detection
- **PCAP files**: Full packet-level analysis with protocol stack examination
- **HDF5 text files**: Signal measurements and UE mobility events
- **Fronthaul logs**: eCPRI communication and DU-RU interface issues
- **Protocol logs**: MAC/RRC message parsing and violation detection

### Analysis Output for Each File

#### 1. UE Events Analysis
- Attach/Detach procedure success/failure rates
- Handover performance and timing
- RRC connection establishment issues
- TAU and paging response analysis

#### 2. Fronthaul Analysis  
- eCPRI packet timing violations
- DU-RU communication failures
- PTP/GPS synchronization issues
- Interface link errors

#### 3. MAC Layer Analysis
- MAC address validity and duplicate detection
- HARQ process failures and retransmissions
- RACH preamble detection issues
- Resource block scheduling errors

#### 4. Protocol Analysis
- 3GPP standard compliance violations
- Message sequence errors
- Protocol timeout detection
- State machine transition errors

#### 5. Signal Quality Analysis
- RSRP/RSRQ/SINR threshold violations
- Coverage hole detection
- Interference pattern analysis
- Signal degradation trends

#### 6. Performance Analysis
- Throughput degradation detection
- Latency spike identification
- Packet loss rate analysis
- Network congestion indicators

### Cross-Correlation Analysis
The system automatically finds relationships between different types of anomalies:
- UE detach events correlated with poor signal quality
- Fronthaul timing issues causing MAC layer problems
- Protocol violations leading to performance degradation

### Health Scoring
Each analysis provides:
- **Overall Health Score** (0-100): Weighted score based on anomaly severity
- **Category Breakdown**: Number of issues per L1 area
- **Severity Classification**: High/Medium/Low priority issues
- **Confidence Scoring**: ML model certainty for each anomaly

## Advanced Usage

### Use Advanced Analyzer Directly
```bash
# Full comprehensive analysis with detailed options
python3 comprehensive_l1_analyzer.py /path/to/file.pcap --output results.json

# Batch process with trained models
python3 comprehensive_l1_analyzer.py /path/to/directory/ --batch --use-trained-models /home/users/praveen.joe/L1/models/hybrid_training_20250808_140000

# Setup directories only
python3 comprehensive_l1_analyzer.py --ensure-dirs

# Train models manually
python3 comprehensive_l1_analyzer.py --train
```

### Training Options

#### Unsupervised Training (Recommended)
```bash
# Train only on clean data (most common approach)
# Put clean files in /home/users/praveen.joe/L1/training_data/normal/
python3 quick_l1_analysis.py --train
```

#### Supervised + Unsupervised Training
```bash
# Add known anomalous files to training_data/anomalous/
# Then train on both normal and anomalous data
python3 quick_l1_analysis.py --train
```

### Output Files

#### Analysis Reports
- **Location**: `/home/users/praveen.joe/L1/results/analysis_reports/`
- **Format**: JSON files with timestamp
- **Content**: Complete analysis results with all anomaly details

#### Training Reports  
- **Location**: `/home/users/praveen.joe/L1/results/training_reports/`
- **Content**: Model performance metrics, F-scores, validation results

#### Models
- **Location**: `/home/users/praveen.joe/L1/models/hybrid_training_YYYYMMDD_HHMMSS/`
- **Files**: 
  - `hybrid_models.pkl` - All 4 trained ML models
  - `feature_scaler.pkl` - Data preprocessing scaler
  - `training_report.json` - Performance metrics
  - `model_metadata.json` - Training parameters

## Integration with Web Interface

The comprehensive analyzer integrates with the existing web application:
- Results automatically stored in PostgreSQL database
- ClickHouse integration for high-volume analytics
- Real-time WebSocket updates during analysis
- Dashboard visualization of health scores and trends

## Troubleshooting

### No Training Data Found
```
Error: No training data found at /home/users/praveen.joe/L1/training_data/normal
```
**Solution**: Add clean UE event files to the normal directory before training.

### Training Failed
```
Error: Model training failed - check training data
```
**Solution**: Ensure files in training_data/normal are valid PCAP or HDF5 text files.

### Analysis Errors
```
Error: File format not supported
```
**Solution**: Supported formats are PCAP, PCAPNG, TXT, LOG. Check file extension and content.

## Performance Notes

- **Training Time**: 2-10 minutes depending on data volume
- **Analysis Time**: 1-30 seconds per file depending on size
- **Memory Usage**: 100MB-1GB for large PCAP files
- **Storage**: Models ~10MB, results vary by file size

## Summary

This comprehensive L1 system provides:
✓ **Complete Coverage**: All L1 troubleshooting scenarios in single analysis  
✓ **Zero Configuration**: Default paths, no arguments needed  
✓ **Auto-Detection**: Handles PCAP, HDF5 text, and log files automatically  
✓ **Cross-Correlation**: Finds relationships between different anomaly types  
✓ **Health Scoring**: Quantitative network health assessment  
✓ **Easy Deployment**: Simple command-line interface  
✓ **Web Integration**: Works with existing dashboard and database systems

Perfect for telecom engineers who need comprehensive L1 network analysis without complex configuration!