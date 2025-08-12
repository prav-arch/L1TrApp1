# Mistral AI Integration Setup Guide

## Current Status
- The system is configured to look for: `/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf`
- When the model is not available, it shows the analysis prompt and provides fallback recommendations
- The WebSocket streaming is working correctly

## Option 1: Copy Model File (Recommended)
```bash
# Copy your model file to the expected location
cp /path/to/your/mistral-7b-instruct-v0.2.Q4_K_M.gguf /tmp/llm_models/

# Install llama-cpp-python (if not already installed)
pip install llama-cpp-python
```

## Option 2: Update Model Path
If your model is in a different location, update `server/llm_service.py`:

```python
# Change these lines in MistralLLMService.__init__():
self.model_path = "/your/actual/path"
self.model_file = "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
```

## Option 3: HTTP API Integration (if running model as server)
If you're running Mistral as an HTTP server, we can modify the LLM service to make HTTP requests instead of loading the model directly.

## Testing the Current Setup
1. Click "Get Recommendations" on any anomaly
2. You'll see:
   - The exact prompt being sent to the LLM
   - Current status (model found/not found)
   - Fallback recommendations until the model is connected

## What You'll See Now
The system will display:
1. **Analysis Prompt**: Shows exactly what would be sent to Mistral
2. **Model Status**: Whether the model file was found
3. **Response**: Either real Mistral output or structured fallback recommendations

Would you like me to:
- Help copy the model file to the correct location?
- Modify the path configuration?
- Set up HTTP API integration if you're running Mistral as a server?