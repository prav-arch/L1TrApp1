# Complete Setup Guide: ML Anomaly Detection with Algorithm Details

## Overview
This guide provides complete steps to set up and run the enhanced ML anomaly detection system that shows individual ML algorithm outputs, confidence scores, and stores results in ClickHouse database.

## Step 1: Install Dependencies

```bash
# Install Python ML packages
pip install scikit-learn numpy pandas scapy clickhouse-connect

# Or install from requirements
pip install -r requirements.txt
```

## Step 2: Setup ClickHouse Database

### Option A: Using Docker (Recommended)
```bash
# Start ClickHouse server
docker run -d --name clickhouse-server \
  -p 8123:8123 -p 9000:9000 \
  yandex/clickhouse-server

# Verify it's running
curl http://localhost:8123/ping
```

### Option B: Direct Installation
```bash
# Install ClickHouse (Ubuntu/Debian)
curl https://clickhouse.com/ | sh
sudo ./clickhouse install
sudo systemctl start clickhouse-server
```

## Step 3: Setup Enhanced Database Schema

```bash
# Run the enhanced database setup
python3 setup_complete_system.py
```

This creates:
- Enhanced anomalies table with ML algorithm details
- ML model performance tracking table
- Comprehensive test data with algorithm scores
- Session tracking with model versions

## Step 4: Train ML Models (First Time Only)

```bash
# Create training data directory
mkdir training_data

# Add your network files to training_data/
# Files with 'anomaly', 'error', 'failure' in name = anomalies
# Other files = normal traffic

# Train the ML models
python3 ml_model_trainer.py
```

Expected output:
```
Training ML Ensemble for L1 Network Anomaly Detection
========================================================
Created dataset: 5000 samples, 25 features
   Normal samples: 4200
   Anomaly samples: 800

Training Isolation Forest...
   Best parameters: {'contamination': 0.1, 'n_estimators': 200}

Training Random Forest...
   Best parameters: {'n_estimators': 300, 'max_depth': 20}

Models saved to trained_models/ directory
```

## Step 5: Run Enhanced Anomaly Detection

### Basic Analysis
```bash
# Analyze folder with detailed ML algorithm output
python3 enhanced_ml_analyzer.py /path/to/your/logs

# Save results to file
python3 enhanced_ml_analyzer.py /path/to/your/logs --output detailed_results.json

# Set custom confidence threshold
python3 enhanced_ml_analyzer.py /path/to/your/logs --confidence-threshold 0.8
```

### Example Output Format

```
Enhanced ML L1 Network Anomaly Detection
==================================================
Found 3 files to analyze

================================================================================
ANALYZING FILE: sample_error_log.txt
================================================================================
File: sample_error_log.txt
Size: 1,024 bytes

ML ALGORITHM ANALYSIS RESULTS:
--------------------------------------------------
Isolation Forest:
  Anomalies detected: 5/100
  Average confidence: 0.847
  Detection rate: 5.0%

Dbscan:
  Anomalies detected: 3/100
  Average confidence: 0.672
  Detection rate: 3.0%

One Class Svm:
  Anomalies detected: 4/100
  Average confidence: 0.789
  Detection rate: 4.0%

Random Forest:
  Anomalies detected: 6/100
  Average confidence: 0.912
  Detection rate: 6.0%

ENSEMBLE VOTING RESULTS:
------------------------------
Total samples analyzed: 100
Ensemble anomalies found: 4
High confidence anomalies: 3

DETAILED ANOMALY BREAKDOWN:
----------------------------------------

ANOMALY #1:
  Location: Packet #75
  Confidence: 0.924
  Model Agreement: 4/4 algorithms
  Algorithm Votes:
    Isolation Forest: ANOMALY (0.891)
    Dbscan: ANOMALY (0.765)
    One Class Svm: ANOMALY (0.834)
    Random Forest: ANOMALY (0.967)

ANOMALY #2:
  Location: Packet #150
  Confidence: 0.887
  Model Agreement: 3/4 algorithms
  Algorithm Votes:
    Isolation Forest: ANOMALY (0.823)
    Dbscan: NORMAL (0.432)
    One Class Svm: ANOMALY (0.891)
    Random Forest: ANOMALY (0.945)

================================================================================
FINAL ANALYSIS SUMMARY
================================================================================
TOTAL ANOMALIES FOUND: 8

CONFIDENCE DISTRIBUTION:
  Very High (>0.9): 3 anomalies
  High (0.7-0.9): 4 anomalies
  Medium (0.5-0.7): 1 anomalies

MODEL AGREEMENT ANALYSIS:
  4/4 algorithms agreed: 3 anomalies
  3/4 algorithms agreed: 4 anomalies
  2/4 algorithms agreed: 1 anomalies

TOP 5 HIGH-CONFIDENCE ANOMALIES:
  1. Packet #75 - Confidence: 0.924 - Agreement: 4/4 - File: sample_error_log.txt
  2. Packet #150 - Confidence: 0.887 - Agreement: 3/4 - File: sample_error_log.txt
  3. Packet #203 - Confidence: 0.856 - Agreement: 3/4 - File: timing_data.pcap
```

## Step 6: View Results in ClickHouse

### Query Anomalies with ML Details
```sql
-- Connect to ClickHouse
clickhouse-client

-- Use the database
USE l1_anomaly_detection;

-- View all anomalies with ML algorithm details
SELECT 
    timestamp,
    anomaly_type,
    source_file,
    packet_number,
    confidence_score,
    model_agreement,
    ml_algorithm_details
FROM anomalies
ORDER BY confidence_score DESC
LIMIT 10;

-- View model performance statistics
SELECT 
    model_name,
    total_predictions,
    anomalies_detected,
    average_confidence,
    accuracy_score
FROM ml_model_performance
ORDER BY accuracy_score DESC;

-- View session summaries
SELECT 
    session_id,
    start_time,
    files_completed,
    total_anomalies,
    status
FROM sessions
ORDER BY start_time DESC;
```

## Step 7: Integration with Your System

### Web Dashboard Integration
The anomalies are automatically stored in ClickHouse and can be displayed in your web dashboard:

```javascript
// Frontend can fetch anomalies with ML details
fetch('/api/anomalies')
  .then(response => response.json())
  .then(anomalies => {
    anomalies.forEach(anomaly => {
      console.log(`Packet #${anomaly.packet_number}`);
      console.log(`Confidence: ${anomaly.confidence_score}`);
      console.log(`Model Agreement: ${anomaly.model_agreement}/4`);
      console.log(`Algorithm Details: ${anomaly.ml_algorithm_details}`);
    });
  });
```

### Automated Processing
```bash
# Set up automated processing
crontab -e

# Add entry to run every hour
0 * * * * /usr/bin/python3 /path/to/enhanced_ml_analyzer.py /incoming/logs/ >> /var/log/ml_analysis.log 2>&1
```

## Step 8: Monitoring and Maintenance

### Check System Status
```bash
# Verify ClickHouse is running
curl http://localhost:8123/ping

# Check database size
clickhouse-client --query="SELECT count() FROM l1_anomaly_detection.anomalies"

# View recent analysis sessions
clickhouse-client --query="SELECT * FROM l1_anomaly_detection.sessions ORDER BY start_time DESC LIMIT 5"
```

### Model Retraining
```bash
# Retrain models with new data (recommended monthly)
python3 ml_model_trainer.py --retrain --new-data-dir /path/to/new/training/data
```

## Troubleshooting

### ClickHouse Connection Issues
```bash
# Check if ClickHouse is listening
netstat -tlnp | grep 8123

# Check ClickHouse logs
sudo journalctl -u clickhouse-server -f

# Restart ClickHouse
sudo systemctl restart clickhouse-server
```

### ML Model Issues
```bash
# Check if models exist
ls -la trained_models/

# Retrain if models are missing
python3 ml_model_trainer.py

# Check model loading
python3 -c "from ml_inference_engine import L1MLInferenceEngine; engine = L1MLInferenceEngine()"
```

### Database Schema Issues
```bash
# Reset database (WARNING: deletes all data)
clickhouse-client --query="DROP DATABASE IF EXISTS l1_anomaly_detection"
python3 setup_complete_system.py
```

## System Features

### What You Get:
1. **Detailed ML Algorithm Output** - See how each algorithm voted
2. **Confidence Scoring** - Know how certain the detection is
3. **Model Agreement Analysis** - Understand consensus between algorithms
4. **Database Storage** - All results stored in ClickHouse for analysis
5. **Performance Tracking** - Monitor ML model accuracy over time
6. **Session Management** - Track analysis sessions and batch processing
7. **Web Integration** - Ready for dashboard display

### Detection Capabilities:
- **DU-RU Communication Issues** - Fronthaul timeouts, protocol violations
- **UE Event Anomalies** - Attach/detach failures, mobility issues
- **Timing Synchronization** - Ultra-low latency violations, jitter
- **Protocol Violations** - Frame structure errors, CRC failures
- **Connection Problems** - Network unreachable, device timeouts

The system provides professional-grade network anomaly detection with full transparency into ML algorithm decision-making and comprehensive result storage.