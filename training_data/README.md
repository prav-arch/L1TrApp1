# Training Data Organization Guide

## Folder Structure

```
training_data/
├── normal/          # Place your clean/normal files here
├── anomalous/       # Place known anomalous files here (optional)
├── validation/      # Hold-out test files for validation
└── processed/       # Automatically generated preprocessed data
```

## Usage Instructions

### 1. Prepare Normal Data
Place your clean network log files (files without anomalies) in the `normal/` directory:
```bash
cp your_clean_file1.txt training_data/normal/
cp your_clean_file2.log training_data/normal/
cp your_clean_pcap_data.txt training_data/normal/
```

### 2. Optional: Add Known Anomalies
If you have files with known anomalies, place them in `anomalous/`:
```bash
cp known_error_file.txt training_data/anomalous/
```

### 3. Prepare Validation Data
Keep some clean files separate for testing:
```bash
cp validation_clean_file.txt training_data/validation/
```

### 4. Run Hybrid Training
```bash
python3 hybrid_ml_trainer.py --normal-data training_data/normal --models-path models/trained
```

### 5. Use Trained Models
```bash
python3 enhanced_hybrid_analyzer.py /path/to/test/files --use-trained-models hybrid_training_20250101_120000
```

## File Types Supported
- `.txt` - Text log files
- `.log` - System log files  
- `.pcap` - Network packet capture files (converted to text)
- Any text-based network data files

## Training Benefits

With your clean files in `normal/`, the system will:

✅ **Supervised Learning**: Train models on your known-good data patterns  
✅ **Reduced False Positives**: Learn what normal traffic looks like  
✅ **True F-Score Metrics**: Calculate actual precision, recall, and F1-score  
✅ **Calibrated Thresholds**: Set confidence boundaries based on your data  
✅ **Hybrid Detection**: Combine supervised accuracy with unsupervised discovery  

## Model Performance

After training, you'll get metrics like:
```
Model                     Accuracy     Precision    Recall       F1-Score    
supervised_svm           0.892        0.847        0.923        0.883
supervised_rf            0.915        0.901        0.934        0.917
unsupervised_isolation   0.834        0.789        0.891        0.837
unsupervised_dbscan      0.756        0.723        0.834        0.774
hybrid_ensemble          0.927        0.912        0.945        0.928
```

The hybrid ensemble typically achieves the highest F1-Score by combining the strengths of both supervised and unsupervised approaches.