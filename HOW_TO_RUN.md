# How to Run the DU->RU Fronthaul Analysis Program

## Quick Start Commands

### 1. LLM-Powered PCAP Analysis (Recommended)
```bash
python stream_pcap_analysis.py YOUR_PCAP_FILE.pcap
```
**NEW: LLM directly analyzes PCAP packet data for communication issues**
**FIXED: "Argument list too long" error resolved using temporary files**

### 2. Setup Verification
```bash
python test_streaming_mistral.py
```

### 3. View Sample Output
```bash
python sample_analysis_output.py
```

## Detailed Instructions

### Step 1: Verify Your Setup
First, check that all components are working:
```bash
python test_streaming_mistral.py
```

This verifies:
- Mistral model at `/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf`
- llama.cpp binary at `/tmp/llama.cpp/build/bin/llama-cli`
- ClickHouse database connection

### Step 2: Prepare Your PCAP File
You need a packet capture file containing 5G fronthaul traffic with:
- **DU MAC address**: `00:11:22:33:44:67`
- **RU MAC address**: `6c:ad:ad:00:03:2a`

Supported formats: `.pcap`, `.pcapng`

### Step 3: Run the Analysis

#### Option A: Enhanced Fronthaul Analysis (Recommended)
```bash
python detect_communication_failures.py /path/to/your/capture.pcap
```

**What this detects:**
- DU messages where RU doesn't respond
- Ultra-low latency violations (>100μs)
- Jitter exceeding 50μs threshold
- Packet loss patterns
- Communication failure rates
- AI-powered root cause analysis

#### Option B: Streaming Analysis
```bash
python stream_pcap_analysis.py /path/to/your/capture.pcap
```

**What this provides:**
- Real-time analysis streaming
- Live AI recommendations
- Continuous monitoring output
- Detailed timing analysis

## Example Commands

```bash
# Test with a local file
python detect_communication_failures.py ./fronthaul_dump.pcap

# Test with absolute path
python detect_communication_failures.py /tmp/network_capture.pcap

# Streaming analysis
python stream_pcap_analysis.py ./5g_fronthaul.pcapng
```

## Expected Output

When successful, you'll see:

```
🔍 ANALYZING FRONTHAUL COMMUNICATION FAILURES: your_file.pcap
📊 Total packets loaded: 18,947
📤 DU→RU messages found: 1,534
📥 RU→DU responses found: 1,401

📈 FRONTHAUL ANALYSIS RESULTS:
Communication failure rate: 8.7%
Average round-trip latency: 142.3μs
Ultra-low latency violations (>100μs): 287

🚨 CRITICAL: 133 DU MESSAGES WITHOUT RU RESPONSE
🤖 STREAMING AI ANALYSIS FOR FRONTHAUL FAILURES:
📡 FRONTHAUL ISSUE: COMMUNICATION_BREAKDOWN - CRITICAL
📡 REMEDIATION: Verify RU power status, check physical connections
```

## Troubleshooting

### Common Issues:

**"Model not found"**
- Check if Mistral model exists at `/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf`

**"Binary not found"** 
- Verify llama.cpp installation at `/tmp/llama.cpp/build/bin/llama-cli`

**"No packets found"**
- Ensure PCAP file contains Ethernet frames
- Check file format is supported (.pcap/.pcapng)

**"No DU-RU traffic"**
- Verify your equipment uses MAC addresses: DU `00:11:22:33:44:67` and RU `6c:ad:ad:00:03:2a`
- Check if traffic contains the correct source/destination addresses

**"Database error"**
- Ensure ClickHouse database is running
- Check database connectivity

## What Gets Analyzed

### Communication Patterns Detected:
- **DU_TO_RU**: DU (`00:11:22:33:44:67`) → RU (`6c:ad:ad:00:03:2a`)
- **RU_TO_DU**: RU → DU responses
- **Communication failures**: DU sends but RU doesn't respond

### Timing Requirements Monitored:
- **Ultra-low latency**: ≤100μs round-trip requirement
- **Jitter tolerance**: <50μs variation threshold  
- **Packet loss**: <1% acceptable loss rate

### AI Analysis Provides:
- Root cause identification
- Specific troubleshooting steps
- Physical layer diagnostics
- Protocol performance impact assessment

## File Locations

All analysis scripts are in the current directory:
- `detect_communication_failures.py` - Main analysis tool
- `stream_pcap_analysis.py` - Streaming analysis
- `test_streaming_mistral.py` - Setup verification
- `sample_analysis_output.py` - See example outputs
- `fronthaul_analysis_demo.py` - Feature demonstration

## Web Dashboard

After running analysis, view results in the web dashboard:
- Open your Replit preview URL
- Navigate to the Dashboard and Anomalies tabs
- See real-time metrics and detected issues

Ready to analyze your DU→RU fronthaul communication!