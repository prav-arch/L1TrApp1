#!/usr/bin/env python3
"""
Quick Start Guide for DU→RU Fronthaul Analysis
Simple commands to get started immediately
"""

import os
import sys

def show_quick_commands():
    """Display the essential commands to run the analysis"""
    
    print("QUICK START: DU->RU Fronthaul Analysis")
    print("=" * 50)
    print()
    
    print("STEP 1: Test Your Setup")
    print("Command: python test_streaming_mistral.py")
    print("Purpose: Verify Mistral model and database connection")
    print()
    
    print("STEP 2: Run Unified Analysis on Your PCAP File")
    print("Command: python stream_pcap_analysis.py YOUR_FILE.pcap")
    print("Purpose: Unified detection of DU->RU communication failures with AI analysis")
    print()
    
    print("EXAMPLES:")
    print("-" * 20)
    print("# Unified analysis (recommended - all detection logic in one file)")
    print("python stream_pcap_analysis.py fronthaul_dump.pcap")
    print()
    print("# Test the analysis system")
    print("python stream_pcap_analysis.py sample_capture.pcap")
    print()
    
    print("WHAT YOU NEED:")
    print("-" * 20)
    print("- PCAP file with 5G fronthaul traffic")
    print("- DU MAC: 00:11:22:33:44:67")
    print("- RU MAC: 6c:ad:ad:00:03:2a")
    print("- File formats: .pcap or .pcapng")
    print()
    
    print("WHAT YOU'LL GET:")
    print("-" * 20)
    print("- Communication failure rate (%)")
    print("- Round-trip latency measurements")
    print("- Ultra-low latency violations (>100μs)")
    print("- Jitter analysis (>50μs threshold)")
    print("- Packet loss detection")
    print("- AI-powered troubleshooting recommendations")
    print("- Fixed 'Argument list too long' error")
    print()
    
    print("SAMPLE COMMANDS FOR DIFFERENT FILE LOCATIONS:")
    print("-" * 20)
    
    examples = [
        "python stream_pcap_analysis.py ./capture.pcap",
        "python stream_pcap_analysis.py /tmp/fronthaul.pcap", 
        "python stream_pcap_analysis.py ~/Downloads/network_dump.pcapng",
        "python stream_pcap_analysis.py ./5g_analysis.pcap"
    ]
    
    for example in examples:
        print(f"# {example}")
    
    print()
    print("TROUBLESHOOTING:")
    print("-" * 20)
    print("• 'Model not found' -> Check /tmp/llm_models/ directory")
    print("• 'No packets' -> Verify PCAP file format and content")
    print("• 'No DU-RU traffic' -> Check MAC addresses in your equipment")
    print("• 'Database error' -> Ensure ClickHouse is running")
    print("• 'Argument list too long' -> Fixed in unified version")
    print()
    
    print("READY TO START!")
    print("Run: python stream_pcap_analysis.py YOUR_PCAP_FILE.pcap")

def check_files():
    """Check if required analysis files exist"""
    
    required_files = [
        "detect_communication_failures.py",
        "stream_pcap_analysis.py", 
        "test_streaming_mistral.py"
    ]
    
    print("\n📁 CHECKING REQUIRED FILES:")
    print("-" * 30)
    
    all_present = True
    for file in required_files:
        if os.path.exists(file):
            print(f"✓ {file}")
        else:
            print(f"❌ {file} - MISSING")
            all_present = False
    
    if all_present:
        print("\n✅ All analysis files are present and ready to use!")
    else:
        print("\n⚠️  Some files are missing. Please ensure all scripts are available.")
    
    return all_present

if __name__ == "__main__":
    show_quick_commands()
    check_files()