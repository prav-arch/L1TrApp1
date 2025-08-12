# Quick Start: Run Anomaly Detection on Log Folders

## 🚀 How to Find Anomalies in Your Log Folders

### Method 1: Simple Analysis (No Setup Required)

Use the basic anomaly detection script that works immediately:

```bash
# Analyze a single folder
python3 run_anomaly_detection.py /path/to/your/logs

# Analyze with output file
python3 run_anomaly_detection.py /path/to/your/logs --output results.json

# Verbose analysis
python3 run_anomaly_detection.py /path/to/your/logs --verbose
```

**What it detects:**
- Error messages in log files
- Timeout events
- DU-RU communication failures
- UE attach/detach issues
- Suspicious file patterns
- Unusual file sizes

### Method 2: Using Your Existing Analyzers

If you have your existing analyzer scripts:

```bash
# Using the folder analyzer with ClickHouse
python3 folder_anomaly_analyzer_clickhouse.py /path/to/your/logs

# Using the unified analyzer
python3 unified_l1_analyzer.py /path/to/your/logs

# Using the ML-enhanced analyzer (if ML models are trained)
python3 ml_inference_engine.py --directory /path/to/your/logs
```

## 📁 Example Usage

### Analyze Test Data Folders:

```bash
# Analyze the test network data
python3 run_anomaly_detection.py ./test_network_data

# Analyze with detailed output
python3 run_anomaly_detection.py ./test_network_data --output anomaly_results.json --verbose
```

### Expected Output:
```
🔍 L1 Network Anomaly Detection
========================================
🔍 Analyzing folder: ./test_network_data
📁 Found 8 files to analyze:

📄 Analyzing: fronthaul_capture.pcap
   Size: 2,048,576 bytes
   ✅ No obvious anomalies detected

📄 Analyzing: ue_attach_failure.log
   Size: 45,832 bytes
   🚨 Found 3 anomalies

📄 Analyzing: du_ru_timeout_events.txt
   Size: 12,456 bytes  
   🚨 Found 5 anomalies

📊 Analysis Summary:
   Files analyzed: 8
   Total anomalies: 23

🚨 Detected Anomalies:
   1. Error Pattern: Error detected in log: UE attach failed after 3 attempts...
      File: ue_attach_failure.log
      
   2. DU-RU Communication Issue: DU-RU communication problem: DU timeout waiting for RU response...
      File: du_ru_timeout_events.txt
      Packet: #150
      
   3. UE Event Anomaly: UE event issue detected: Handover failure - signal drop detected...
      File: mobility_issues.log

🎯 Final Results:
   Total anomalies found: 23
   Severity breakdown:
     critical: 8
     high: 10
     medium: 4
     low: 1
```

## 🗂️ Folder Structure Examples

Your log folder should contain network files:

```
your_logs/
├── pcap_files/
│   ├── normal_traffic_001.pcap
│   ├── fronthaul_errors_002.pcap
│   └── timing_violations_003.cap
├── ue_logs/
│   ├── attach_events_001.txt
│   ├── detach_failures_002.log
│   └── handover_issues_003.txt
├── du_ru_logs/
│   ├── communication_log_001.txt
│   └── timeout_events_002.log
└── system_logs/
    ├── error_log_001.txt
    └── performance_metrics_002.log
```

## 🎯 What Gets Detected

### In PCAP Files:
- Suspicious filenames (containing "error", "fail", "timeout")
- Unusual file sizes (too small or too large)
- File patterns suggesting network issues

### In Log Files:
- **Error Messages**: Lines containing "error", "failed", "fail"
- **Timeout Events**: Network timeout patterns
- **DU-RU Issues**: Communication problems between DU and RU
- **UE Problems**: User Equipment attach/detach failures
- **High Error Rates**: Files with excessive error counts

### Severity Levels:
- **Critical**: DU-RU failures, high error rates
- **High**: UE event failures, frequent errors
- **Medium**: Timeout events, moderate issues
- **Low**: File size anomalies, minor patterns

## 🔧 Advanced Options

### Using ML Models (if trained):

```bash
# First train ML models (one-time setup)
mkdir training_data
# Add your training files to training_data/
python3 ml_model_trainer.py

# Then use ML for analysis
python3 run_anomaly_detection.py /path/to/logs --advanced
```

### Custom Analysis:

```bash
# Create custom analyzer for your specific patterns
python3 -c "
from run_anomaly_detection import analyze_folder_simple
results = analyze_folder_simple('/your/log/path')
print(f'Found {len(results)} anomalies')
"
```

## 💾 Output Formats

### JSON Output File:
```json
{
  "analysis_timestamp": "2025-08-06T12:30:00",
  "total_anomalies": 23,
  "anomalies": [
    {
      "type": "DU-RU Communication Issue",
      "description": "DU timeout waiting for RU response",
      "source_file": "du_ru_timeout.log",
      "line_number": 150,
      "severity": "critical",
      "timestamp": "2025-08-06T12:30:15"
    }
  ]
}
```

### Console Output:
- Real-time progress updates
- File-by-file analysis results
- Summary statistics
- Top anomalies list

## 🚨 Common Issues & Solutions

### "No files found":
```bash
# Check your folder path
ls -la /path/to/your/logs

# Ensure files have correct extensions (.pcap, .cap, .txt, .log)
find /path/to/logs -name "*.pcap" -o -name "*.txt" -o -name "*.log"
```

### "Permission denied":
```bash
# Fix file permissions
chmod +r /path/to/your/logs/*

# Or run with sudo if needed
sudo python3 run_anomaly_detection.py /path/to/logs
```

### "Module not found":
```bash
# Basic script has no dependencies - should work immediately
python3 run_anomaly_detection.py /path/to/logs

# For advanced features, install requirements
pip3 install scapy pandas numpy scikit-learn
```

## 🎯 Next Steps

1. **Run basic analysis** on your log folders
2. **Review the results** in the output
3. **Identify patterns** in detected anomalies
4. **Train ML models** if you want higher accuracy
5. **Integrate** with your existing monitoring system

The anomaly detection will help you quickly identify network issues, DU-RU communication problems, and UE mobility failures in your 5G network logs.