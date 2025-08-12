# Complete ClickHouse Setup Guide for L1 Anomaly Detection

## Overview

This guide provides step-by-step instructions to set up ClickHouse for storing anomalies detected by the enhanced ML analyzer with detailed algorithm voting and confidence scoring.

## 1. ClickHouse Installation

### Ubuntu/Debian:
```bash
sudo apt-get install -y apt-transport-https ca-certificates dirmngr
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv E0C56BD4
echo "deb https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list
sudo apt-get update
sudo apt-get install -y clickhouse-server clickhouse-client
```

### Start ClickHouse Service:
```bash
sudo service clickhouse-server start
```

## 2. Database Schema Creation

The enhanced ML analyzer automatically creates the complete database schema when connecting. Here are the tables created:

### Main Anomalies Table
```sql
CREATE TABLE IF NOT EXISTS l1_anomaly_detection.anomalies (
    id UInt64 DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    anomaly_type LowCardinality(String),
    description String,
    severity LowCardinality(String),
    source_file String,
    packet_number UInt32,
    session_id String,
    confidence_score Float64,
    model_agreement UInt8,
    ml_algorithm_details String,
    isolation_forest_score Float64 DEFAULT 0.0,
    one_class_svm_score Float64 DEFAULT 0.0,
    dbscan_prediction Int8 DEFAULT 0,
    random_forest_score Float64 DEFAULT 0.0,
    ensemble_vote String,
    detection_timestamp String,
    status LowCardinality(String) DEFAULT 'active'
) ENGINE = MergeTree()
ORDER BY (timestamp, severity, anomaly_type)
PARTITION BY toYYYYMM(timestamp);
```

### ML Model Performance Table
```sql
CREATE TABLE IF NOT EXISTS l1_anomaly_detection.ml_model_performance (
    timestamp DateTime DEFAULT now(),
    session_id String,
    model_name LowCardinality(String),
    detection_rate Float64,
    avg_confidence Float64,
    accuracy_score Float64,
    precision_score Float64,
    recall_score Float64,
    f1_score Float64,
    file_analyzed String,
    total_samples UInt32,
    anomalies_found UInt32,
    false_positives UInt32,
    true_positives UInt32
) ENGINE = MergeTree()
ORDER BY (timestamp, model_name, session_id);
```

### Analysis Sessions Table
```sql
CREATE TABLE IF NOT EXISTS l1_anomaly_detection.analysis_sessions (
    session_id String,
    start_time DateTime DEFAULT now(),
    end_time DateTime,
    folder_path String,
    files_to_process UInt32,
    files_analyzed UInt32,
    total_anomalies UInt32,
    confidence_threshold Float64,
    ensemble_quality_score Float64,
    consensus_rate Float64,
    status LowCardinality(String) DEFAULT 'processing'
) ENGINE = MergeTree()
ORDER BY (start_time, session_id);
```

### File Processing Log Table
```sql
CREATE TABLE IF NOT EXISTS l1_anomaly_detection.processed_files (
    file_id UInt64 DEFAULT generateUUIDv4(),
    session_id String,
    filename String,
    file_path String,
    file_size UInt64,
    processing_start DateTime,
    processing_end DateTime,
    total_samples UInt32,
    anomalies_found UInt32,
    processing_status LowCardinality(String),
    error_message String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (processing_start, session_id);
```

## 3. Connection Configuration

### Default Connection Settings:
```python
clickhouse_client = clickhouse_connect.get_client(
    host='localhost',
    port=8123,
    username='default',
    password='',
    database='l1_anomaly_detection'
)
```

### Custom Configuration:
```python
clickhouse_client = clickhouse_connect.get_client(
    host='your_clickhouse_host',
    port=8123,
    username='your_username',
    password='your_password',
    database='l1_anomaly_detection'
)
```

## 4. Confidence Score Calculation Explained

The confidence score is calculated using ensemble voting methodology:

### Formula:
```
ensemble_confidence = (model_agreements / total_models) * (sum_of_scores / max(agreements, 1))
```

### Step-by-Step Process:

1. **Individual Algorithm Predictions**: Each ML algorithm (Isolation Forest, One-Class SVM, DBSCAN, Random Forest) makes a binary prediction (anomaly/normal)

2. **Score Extraction**: Each algorithm provides a confidence score:
   - **Isolation Forest**: Decision function score (negative for anomalies)
   - **One-Class SVM**: Decision function score (negative for anomalies) 
   - **DBSCAN**: Binary prediction (-1 for outliers, cluster ID for normal)
   - **Random Forest**: Probability score when available

3. **Model Agreement Counting**: Count how many algorithms agree on anomaly detection

4. **Ensemble Confidence Calculation**:
   - Count model agreements (models that detected anomaly)
   - Sum absolute values of confidence scores from agreeing models
   - Apply formula: (agreements / total_models) × (score_sum / max(agreements, 1))
   - Cap result at 1.0 for normalization

### Example:
```
Packet #1 Analysis:
- Isolation Forest: ANOMALY (-0.007) → Agreement = 1, Score = 0.007
- One-Class SVM: ANOMALY (-0.000) → Agreement = 2, Score = 0.007  
- DBSCAN: ANOMALY (-1) → Agreement = 3, Score = 1.007
- Random Forest: NORMAL (0.0) → Agreement = 3, Score = 1.007

Final Calculation:
ensemble_confidence = (3/4) × (1.007/3) = 0.75 × 0.336 = 0.252
```

## 5. Running Enhanced ML Analyzer with ClickHouse

### Basic Usage:
```bash
python3 enhanced_ml_analyzer.py /path/to/network/logs
```

### With Custom Confidence Threshold:
```bash
python3 enhanced_ml_analyzer.py /path/to/network/logs --confidence-threshold 0.8
```

### Save Results to File:
```bash
python3 enhanced_ml_analyzer.py /path/to/network/logs --output results.json
```

## 6. Querying Anomaly Data

### View Recent Anomalies:
```sql
SELECT 
    timestamp,
    anomaly_type,
    severity,
    confidence_score,
    model_agreement,
    source_file
FROM l1_anomaly_detection.anomalies 
ORDER BY timestamp DESC 
LIMIT 10;
```

### High-Confidence Anomalies:
```sql
SELECT 
    timestamp,
    source_file,
    confidence_score,
    model_agreement,
    isolation_forest_score,
    one_class_svm_score,
    dbscan_prediction
FROM l1_anomaly_detection.anomalies 
WHERE confidence_score > 0.7 AND model_agreement >= 3
ORDER BY confidence_score DESC;
```

### Algorithm Performance Analysis:
```sql
SELECT 
    model_name,
    AVG(detection_rate) as avg_detection_rate,
    AVG(avg_confidence) as avg_confidence,
    AVG(accuracy_score) as avg_accuracy
FROM l1_anomaly_detection.ml_model_performance 
GROUP BY model_name
ORDER BY avg_confidence DESC;
```

## 7. Data Insertion Process

When the enhanced ML analyzer runs, it automatically:

1. **Creates ClickHouse connection** with error handling
2. **Creates database schema** if tables don't exist  
3. **Inserts anomaly records** with detailed ML algorithm data:
   - Individual algorithm scores
   - Model voting details
   - Confidence calculation breakdown
   - Session tracking information

4. **Stores session metadata** for analysis tracking
5. **Records file processing status** for audit trail

## 8. Schema Benefits

- **Detailed Algorithm Tracking**: Individual scores from each ML model
- **Ensemble Methodology**: Complete voting and confidence calculation data
- **Performance Monitoring**: Track ML model performance over time
- **Session Management**: Group related analysis runs
- **Audit Trail**: Complete file processing history
- **Time-Series Optimization**: Partitioned by month for efficient querying
- **High-Performance Queries**: Optimized indexes for common query patterns

This setup provides complete anomaly storage with full ML algorithm transparency and detailed confidence scoring as requested.