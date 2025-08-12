# Trained Models Storage

## Directory Structure

```
models/
├── trained/         # Saved trained models (.joblib files)
├── checkpoints/     # Training checkpoints and intermediate states
└── baseline/        # Normal data baseline statistics
```

## Model Files

After training, you'll find files like:
```
models/trained/
├── hybrid_training_20250101_120000_supervised_svm.joblib
├── hybrid_training_20250101_120000_supervised_rf.joblib
├── hybrid_training_20250101_120000_unsupervised_isolation.joblib
└── hybrid_training_20250101_120000_scaler.joblib
```

## Loading Trained Models

Use the training ID to load models in the enhanced analyzer:
```bash
python3 enhanced_hybrid_analyzer.py /path/to/data --use-trained-models hybrid_training_20250101_120000
```

## Model Types

### Supervised Models (Trained on your clean data)
- **supervised_svm.joblib**: One-Class SVM trained on normal patterns
- **supervised_rf.joblib**: Random Forest binary classifier (normal vs anomaly)

### Unsupervised Models (Fitted/tuned with data)
- **unsupervised_isolation.joblib**: Isolation Forest with optimal contamination
- **scaler.joblib**: Feature scaler for data preprocessing

## Performance Tracking

Models are automatically tracked in:
- Local JSON files: `results/training_logs/`
- ClickHouse database: `l1_anomaly_detection.training_metrics`

## Model Retraining

To retrain with new data:
```bash
# Add new clean files to training_data/normal/
python3 hybrid_ml_trainer.py

# Use the new training ID
python3 enhanced_hybrid_analyzer.py /data --use-trained-models NEW_TRAINING_ID
```

This approach gives you the best of both worlds: supervised accuracy from your clean data and unsupervised discovery of novel anomalies.