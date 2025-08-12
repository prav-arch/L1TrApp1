# How to Run Tests and Insert Dummy Anomalies

## Quick Steps

### 1. Start the Application
The application is already running at: http://localhost:5000

### 2. Test Dummy Anomalies (Already Available)
The system now has 5 test anomalies automatically loaded:

1. **Fronthaul Issue** (Critical) - DU-RU link timeout, 75% packet loss
2. **UE Event** (High) - UE attach failure, authentication error  
3. **MAC Address** (Medium) - Duplicate MAC address conflict
4. **Protocol** (High) - L1 protocol violation, invalid PRACH format
5. **Signal Quality** (Critical) - RSRP degradation, interference detected

### 3. Test the Recommendations Feature

**Steps:**
1. Open http://localhost:5000 in your browser
2. Click on "Anomalies" in the navigation
3. You'll see the 5 test anomalies in the table
4. Click the **"Get Recommendations"** button on any anomaly row
5. A popup will appear with streaming AI recommendations

### 4. Test ML Training with Progress Tracking

**Run ML Training Demo (Working):**
```bash
python3 demo_ml_training.py
```

**What you'll see:**
- Timestamped progress indicators: "[2025-08-12 05:36:24] Starting One-Class SVM training..."
- Detailed timing: "One-Class SVM training complete (0.00s)"
- Training results with accuracy, precision, recall, F1-scores
- Step-by-step progress prevents hanging without feedback

**Run Full ML Training (Requires more data):**
```bash
python3 hybrid_ml_trainer.py
```
Note: This requires more training data in training_data/normal/ directory

### 5. Insert More Test Data (Optional)

**Option A: Add via API (requires requests module):**
```bash
python3 insert_dummy_data_memory.py
```

**Option B: ClickHouse insertion (if ClickHouse is running):**
```bash
python3 insert_dummy_anomalies.py
```

## Expected Results

### Frontend Test Results
- Anomalies table displays 25+ realistic network issues  
- "Get Recommendations" button opens streaming popup
- AI recommendations appear token-by-token from Mistral AI
- Professional UI with anomaly context and error handling

### ML Training Results (Demo Working)
- Detailed timestamps: "[2025-08-12 05:36:24] Starting One-Class SVM training..."
- Training durations: "Random Forest training complete (0.15s)" 
- Model performance metrics: Accuracy: 0.985, F1-Score: 0.909
- No hanging or unclear status during training
- All 4 ML algorithms (One-Class SVM, Random Forest, Isolation Forest, DBSCAN) trained successfully

### AI Recommendations Results
- Streaming text appears in real-time
- Fallback recommendations if Mistral AI unavailable at /tmp/llm_models
- Professional troubleshooting advice for each anomaly type
- Error handling for connection issues

## Troubleshooting

**No anomalies visible?**
- The server automatically adds 5 test anomalies on startup
- Refresh the browser page
- Check the console logs for any errors

**Recommendations not working?**  
- The system has fallback recommendations even without Mistral AI
- WebSocket connection provides real-time streaming
- Error messages appear if connection fails

**Training hanging?**
- All training steps now have timestamps and duration tracking
- Progress indicators show which step is currently executing
- No more silent hanging during ML model training