#!/usr/bin/env python3

import os
import sys
from datetime import datetime
import uuid

# Simple test script to verify Mistral integration
def test_mistral_setup():
    """Test if Mistral model is accessible and ready"""
    
    model_path = "/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"
    
    print("🔍 Testing Mistral Model Setup")
    print("=" * 50)
    
    # Check if model file exists
    if os.path.exists(model_path):
        print(f"✅ Model found: {model_path}")
        print(f"📏 Model size: {os.path.getsize(model_path) / (1024**3):.2f} GB")
    else:
        print(f"❌ Model not found at: {model_path}")
        return False
    
    # Check for llama.cpp binary at specified location
    llama_path = "/tmp/llama.cpp/build/bin/llama-cli"
    if os.path.exists(llama_path):
        print(f"✅ Found llama.cpp binary: {llama_path}")
        llama_found = True
    else:
        print(f"❌ llama.cpp binary not found at: {llama_path}")
        print("   Expected location: /tmp/llama.cpp/build/bin/llama-cli")
        llama_found = False
    
    # Test basic functionality
    print("\n🧪 Testing basic Python dependencies")
    try:
        from scapy.all import rdpcap
        print("✅ Scapy available for PCAP processing")
    except ImportError:
        print("❌ Scapy not available - install with: pip install scapy")
        return False
    
    try:
        import clickhouse_connect
        print("✅ ClickHouse client available")
    except ImportError:
        print("❌ ClickHouse client not available - install with: pip install clickhouse-connect")
        return False
    
    print("\n🎯 System Ready for Fronthaul Analysis!")
    print("Usage examples:")
    print(f"  python stream_pcap_analysis.py your_file.pcap --model {model_path}")
    print(f"  python analyze_pcap_with_mistral.py your_file.pcap --model {model_path}")
    
    return True

def create_sample_anomaly():
    """Create a sample anomaly for testing database connectivity"""
    try:
        from server.services.clickhouse_client import clickhouse_client
        
        sample_anomaly = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now(),
            'type': 'fronthaul',
            'description': 'Test fronthaul timing violation detected by Mistral',
            'severity': 'high',
            'source_file': 'test_sample.pcap',
            'mac_address': '00:1b:21:aa:bb:cc',
            'ue_id': None,
            'details': '{"latency_us": 150.5, "threshold_us": 100, "analysis_method": "mistral_llm"}',
            'status': 'open'
        }
        
        clickhouse_client.insert_anomaly(sample_anomaly)
        print("✅ Successfully inserted test anomaly into ClickHouse")
        
        # Retrieve and verify
        anomalies = clickhouse_client.get_anomalies(limit=1)
        if anomalies:
            print(f"✅ Retrieved anomaly: {anomalies[0]['description']}")
            return True
        else:
            print("⚠️  Could not retrieve inserted anomaly")
            return False
            
    except Exception as e:
        print(f"❌ Database test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 L1 Troubleshooting Tool - Mistral Integration Test")
    print("=" * 60)
    
    # Test model setup
    model_ready = test_mistral_setup()
    
    print("\n" + "=" * 60)
    print("🗄️  Testing Database Connectivity")
    print("=" * 60)
    
    # Test database
    db_ready = create_sample_anomaly()
    
    print("\n" + "=" * 60)
    if model_ready and db_ready:
        print("🎉 ALL SYSTEMS READY!")
        print("Your L1 Troubleshooting Tool is configured for streaming DU-RU fronthaul analysis")
        print("\nNext steps:")
        print("1. Place your PCAP files in a directory")
        print("2. Run: python stream_pcap_analysis.py your_fronthaul.pcap")
        print("3. Watch real-time streaming analysis for timing violations and protocol issues")
    else:
        print("⚠️  SETUP INCOMPLETE")
        print("Please resolve the issues above before proceeding")
        sys.exit(1)