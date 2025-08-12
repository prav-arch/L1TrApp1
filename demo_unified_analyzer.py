#!/usr/bin/env python3
"""
Demo script showing the unified L1 analyzer capabilities
"""

def demonstrate_unified_analyzer():
    """Show capabilities of unified analyzer"""
    
    print("UNIFIED L1 ANOMALY DETECTION SYSTEM")
    print("=" * 40)
    print()
    
    print("SINGLE FILE FOR DUAL ANALYSIS:")
    print("✓ Automatically detects file type (PCAP vs Text)")
    print("✓ PCAP analysis: DU-RU communication patterns")
    print("✓ Text analysis: UE Attach/Detach events")
    print("✓ Consistent output format with line numbers")
    print("✓ ML ensemble voting for high confidence")
    print()
    
    print("SUPPORTED FILE FORMATS:")
    print("• PCAP files (.pcap, .cap)")
    print("  - Basic PCAP parsing without Scapy dependency")
    print("  - DU-RU MAC address filtering")
    print("  - Time window analysis (100ms)")
    print("  - Communication ratio detection")
    print()
    
    print("• HDF5 Text files (.txt, .log)")
    print("  - OTA log parsing (your format)")
    print("  - Multiple timestamp formats")
    print("  - UE identifier extraction (IMSI, RNTI)")
    print("  - Event type classification")
    print()
    
    print("MACHINE LEARNING ALGORITHMS:")
    print("• Isolation Forest - Anomaly isolation")
    print("• DBSCAN - Density clustering")
    print("• One-Class SVM - Boundary detection")
    print("• Local Outlier Factor - Local density")
    print()
    
    print("USAGE EXAMPLES:")
    print("python unified_l1_analyzer.py your_file.pcap")
    print("python unified_l1_analyzer.py your_ue_events.txt")
    print("python unified_l1_analyzer.py any_network_file")
    print()

def show_comparison():
    """Show comparison with separate tools"""
    
    print("TOOL COMPARISON")
    print("=" * 20)
    print()
    
    print("BEFORE (Separate Tools):")
    print("├── ml_anomaly_detection.py (PCAP only)")
    print("├── ue_event_analyzer.py (Text only)")
    print("└── User needs to know which tool to use")
    print()
    
    print("NOW (Unified Tool):")
    print("├── unified_l1_analyzer.py (Both formats)")
    print("├── Automatic file type detection")
    print("├── Consistent output format")
    print("└── Single command for all analysis")
    print()
    
    print("BENEFITS:")
    print("✓ Simplified workflow")
    print("✓ No need to remember multiple tools")
    print("✓ Consistent anomaly reporting")
    print("✓ Same ML algorithms for both formats")
    print("✓ Unified fronthaul issue detection")

def show_sample_outputs():
    """Show sample outputs for both file types"""
    
    print("SAMPLE OUTPUT FOR TEXT FILES:")
    print("-" * 30)
    print("Detected file type: TEXT")
    print("UE EVENT ANOMALY ANALYSIS")
    print("Processing: ue_events.txt")
    print("Extracted 20 UE events from 51 lines")
    print()
    print("LINE 33: UE ANOMALY DETECTED")
    print("*** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
    print("DU MAC: 00:11:22:33:44:67")
    print("RU MAC: 6c:ad:ad:00:03:2a")
    print("UE ID: 460110123456789")
    print("DETECTED ISSUES:")
    print("  • Failed Attach Procedures: 2 incomplete")
    print("  • Context Failures: 2 detected")
    print()
    
    print("SAMPLE OUTPUT FOR PCAP FILES:")
    print("-" * 30)
    print("Detected file type: PCAP")
    print("PCAP ANOMALY ANALYSIS")
    print("Processing: network.pcap")
    print("Extracted 1,247 DU-RU packets")
    print()
    print("LINE 1523: PCAP ANOMALY DETECTED")
    print("*** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
    print("DU MAC: 00:11:22:33:44:67")
    print("RU MAC: 6c:ad:ad:00:03:2a")
    print("Time Window: 15.235s")
    print("DETECTED ISSUES:")
    print("  • Missing Responses: 8 DU packets without RU replies")
    print("  • Poor Communication Ratio: 0.45 (expected > 0.8)")
    print()

def main():
    demonstrate_unified_analyzer()
    print()
    show_comparison()
    print()
    show_sample_outputs()
    
    print()
    print("INTEGRATION WITH EXISTING SYSTEM:")
    print("• Keep ml_anomaly_detection.py for advanced PCAP analysis")
    print("• Keep ue_event_analyzer.py for detailed UE analysis")
    print("• Use unified_l1_analyzer.py for quick, automatic analysis")
    print("• All tools provide consistent fronthaul issue reporting")

if __name__ == "__main__":
    main()