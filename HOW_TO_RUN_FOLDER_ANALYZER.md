# How to Run the Folder-Based L1 Anomaly Analyzer

## Quick Start Guide

### Step 1: Prepare Your Files
Put all your network files in a single folder:
```
network_data/
├── capture1.pcap
├── capture2.pcap  
├── ue_events1.txt
├── ue_events2.log
├── fronthaul_data.txt
└── du_ru_comm.pcap
```

### Step 2: Run the Analyzer
```bash
python folder_anomaly_analyzer.py /path/to/network_data
```

**Examples:**
```bash
# Analyze files in current directory's 'data' folder
python folder_anomaly_analyzer.py ./data

# Analyze files in absolute path
python folder_anomaly_analyzer.py /home/user/network_files

# Analyze files in relative path
python folder_anomaly_analyzer.py ../network_captures
```

### Step 3: Review Results
The program will:
1. **Scan** the folder for PCAP and text files
2. **Process** each file automatically
3. **Generate** a comprehensive summary report
4. **Save** detailed report to `anomaly_analysis_report.txt`

## What Files Are Supported?

### PCAP Files
- `.pcap` - Standard PCAP captures
- `.cap` - Alternative PCAP format
- `.pcapng` - Next generation PCAP

### Text Files (HDF5-converted)
- `.txt` - Your OTA log format
- `.log` - Log files with UE events

## Sample Output

```
FOLDER-BASED L1 ANOMALY DETECTION SYSTEM
==================================================

SCANNING FOLDER: ./network_data
----------------------------------------
Found 6 network files:
  capture1.pcap (PCAP, 2,547,821 bytes)
  capture2.pcap (PCAP, 1,235,647 bytes)
  ue_events1.txt (TEXT, 45,123 bytes)
  ue_events2.log (TEXT, 32,891 bytes)
  fronthaul_data.txt (TEXT, 67,234 bytes)
  du_ru_comm.pcap (PCAP, 890,456 bytes)

FILE SUMMARY:
• PCAP files: 3
• Text files: 3

PROCESSING FILES...
==============================

📁 Processing PCAP: capture1.pcap
  Extracted 1,247 DU-RU packets
  Found 3 anomalous time windows

📁 Processing PCAP: capture2.pcap
  Extracted 892 DU-RU packets
  Found 1 anomalous time windows

📁 Processing TEXT: ue_events1.txt
  Extracted 23 UE events
  Found 2 anomalous UEs

...

FOLDER ANALYSIS SUMMARY REPORT
============================================================
📁 Folder: ./network_data
📊 Files Processed: 6
   • PCAP files: 3
   • Text files: 3
🚨 Total Anomalies Found: 8

🔍 DETAILED ANOMALY BREAKDOWN
----------------------------------------

📄 FILE: capture1.pcap
   Anomalies: 3

   1. LINE 1523: DU-RU Communication
      *** FRONTHAUL ISSUE BETWEEN DU TO RU ***
      DU MAC: 00:11:22:33:44:67
      RU MAC: 6c:ad:ad:00:03:2a
      Issues:
        • Missing Responses: 8 DU packets without RU replies
        • Poor Communication Ratio: 0.45 (expected > 0.8)

📄 FILE: ue_events1.txt
   Anomalies: 2

   1. LINE 33: UE Event Pattern
      *** FRONTHAUL ISSUE BETWEEN DU TO RU ***
      DU MAC: 00:11:22:33:44:67
      RU MAC: 6c:ad:ad:00:03:2a
      UE ID: 460110123456789
      Issues:
        • Failed Attach Procedures: 2 incomplete
        • Context Failures: 2 detected

📈 ANOMALY STATISTICS:
   • PCAP anomalies: 5
   • UE event anomalies: 3

🔧 NEXT STEPS:
1. Review anomalous files for network issues
2. Check DU-RU fronthaul connections  
3. Investigate UE attachment failures
4. Monitor communication patterns

📄 Detailed report saved to: ./network_data/anomaly_analysis_report.txt

✅ FOLDER ANALYSIS COMPLETE
All network files have been processed and analyzed.
```

## Key Features

### ✅ Automatic File Detection
- Scans folder recursively for network files
- Auto-detects PCAP vs text file types
- Handles mixed file formats in same folder

### ✅ Batch Processing
- Processes all files in sequence
- Provides progress updates for each file
- Generates unified summary report

### ✅ Comprehensive Analysis
- **PCAP files**: DU-RU communication analysis
- **Text files**: UE Attach/Detach event analysis
- **ML algorithms**: 4-algorithm ensemble voting
- **Consistent output**: Same format for all anomalies

### ✅ Detailed Reporting
- Console summary with key findings
- Saved report file with full details
- File-by-file breakdown
- Statistics and next steps

## Error Handling

### Common Issues and Solutions

**"Folder not found"**
```bash
# Check folder path exists
ls -la /path/to/folder

# Use absolute path if relative path fails
python folder_anomaly_analyzer.py /full/path/to/folder
```

**"No files found"**
```bash
# Check for supported file extensions
ls -la *.pcap *.cap *.txt *.log

# Files might be in subdirectories (automatically searched)
```

**"Insufficient data"**
- Some files might be too small for ML analysis
- This is normal - the program continues with other files

## Integration with Existing Tools

### Current Tools (Keep for Advanced Analysis)
- `ml_anomaly_detection.py` - Advanced PCAP analysis
- `ue_event_analyzer.py` - Detailed UE analysis
- `unified_l1_analyzer.py` - Single file analysis

### New Tool (Use for Batch Processing)
- `folder_anomaly_analyzer.py` - **Batch folder analysis**

### When to Use Each Tool

**Use folder analyzer for:**
- Processing multiple files at once
- Getting overview of entire dataset
- Batch analysis workflows
- Regular monitoring tasks

**Use single-file analyzers for:**
- Detailed investigation of specific files
- Advanced feature analysis
- Real-time analysis
- Development and testing

## System Requirements

- Python 3.7+
- Required packages: numpy, pandas, scikit-learn
- Memory: ~100MB per 1000 packets
- Storage: Report files ~1-10KB per anomaly

## Troubleshooting

### Permission Issues
```bash
# Make script executable
chmod +x folder_anomaly_analyzer.py

# Run with python explicitly
python3 folder_anomaly_analyzer.py ./data
```

### Large File Processing
- PCAP files >1GB may take several minutes
- Text files >10MB are processed in chunks
- Progress is shown for each file

### Memory Issues
- Large datasets may require more RAM
- Process files in smaller batches if needed
- Close other applications if memory is limited

## Next Steps After Analysis

1. **Review the anomaly report** (`anomaly_analysis_report.txt`)
2. **Investigate specific anomalous files** using single-file analyzers
3. **Check network infrastructure** for DU-RU connection issues
4. **Monitor UE behavior** for attachment/detachment patterns
5. **Set up regular monitoring** using this folder analyzer

---

**Need Help?**
- Check that folder path is correct
- Ensure files are in supported formats (.pcap, .cap, .txt, .log)
- Verify Python and required packages are installed
- Review console output for specific error messages