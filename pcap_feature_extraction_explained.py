#!/usr/bin/env python3
"""
Detailed explanation of PCAP feature extraction for ML anomaly detection
"""

def explain_pcap_to_features_process():
    """Explain the complete PCAP to features conversion process"""
    
    print("PCAP FEATURE EXTRACTION PROCESS")
    print("=" * 40)
    print()
    
    print("STEP 1: PCAP FILE PARSING")
    print("Input: Raw PCAP file (e.g., fronthaul_capture.pcap)")
    print("Process: Scapy library reads binary packet data")
    print("Output: List of packet objects with headers and timestamps")
    print()
    
    print("STEP 2: PACKET FILTERING")
    print("Focus: Only DU-RU communication packets")
    print("Filter criteria:")
    print("• Source MAC = 00:11:22:33:44:67 (DU) OR 6c:ad:ad:00:03:2a (RU)")
    print("• Destination MAC = 00:11:22:33:44:67 (DU) OR 6c:ad:ad:00:03:2a (RU)")
    print("• Must have Ethernet header")
    print()
    
    print("STEP 3: TIME WINDOW CREATION")
    print("Process: Group packets into 100ms time windows")
    print("Logic: time_window = int(timestamp * 10) / 10")
    print("Example:")
    print("• Packet at 1625097601.235s → Window 1625097601.2")
    print("• Packet at 1625097601.289s → Window 1625097601.2")
    print("• Packet at 1625097601.345s → Window 1625097601.3")
    print()
    
    print("STEP 4: DIRECTIONAL CLASSIFICATION")
    print("For each packet, determine communication direction:")
    print("• DU_TO_RU: Source MAC = DU, Destination MAC = RU")
    print("• RU_TO_DU: Source MAC = RU, Destination MAC = DU")
    print()

def explain_16_features_extraction():
    """Explain each of the 16 features extracted"""
    
    print("16 FEATURES EXTRACTED PER TIME WINDOW")
    print("=" * 40)
    print()
    
    features = [
        {
            "name": "du_count",
            "description": "Number of DU->RU packets in window",
            "calculation": "Count packets where src_mac = DU_MAC",
            "importance": "High count with low RU responses = communication failure"
        },
        {
            "name": "ru_count", 
            "description": "Number of RU->DU packets in window",
            "calculation": "Count packets where src_mac = RU_MAC",
            "importance": "Should match DU count in normal communication"
        },
        {
            "name": "communication_ratio",
            "description": "RU response rate (RU packets / DU packets)",
            "calculation": "ru_count / du_count if du_count > 0 else 0",
            "importance": "Ratio < 0.8 indicates missing responses"
        },
        {
            "name": "missing_responses",
            "description": "DU packets with no corresponding RU response",
            "calculation": "du_count - matched_responses",
            "importance": "Core indicator of communication failures"
        },
        {
            "name": "avg_inter_arrival",
            "description": "Average time between consecutive packets",
            "calculation": "mean(diff(timestamps))",
            "importance": "Abnormal spacing indicates timing issues"
        },
        {
            "name": "jitter",
            "description": "Variation in inter-arrival times",
            "calculation": "std(diff(timestamps))",
            "importance": "High jitter = synchronization problems"
        },
        {
            "name": "max_gap",
            "description": "Maximum time gap between packets",
            "calculation": "max(diff(timestamps))",
            "importance": "Large gaps indicate connection interruptions"
        },
        {
            "name": "min_gap",
            "description": "Minimum time gap between packets",
            "calculation": "min(diff(timestamps))",
            "importance": "Very small gaps may indicate burst transmissions"
        },
        {
            "name": "avg_response_time",
            "description": "Average DU->RU response latency (microseconds)",
            "calculation": "mean(ru_timestamp - du_timestamp)",
            "importance": "Values >100μs violate fronthaul requirements"
        },
        {
            "name": "response_jitter",
            "description": "Variation in response times",
            "calculation": "std(response_times)",
            "importance": "High jitter indicates unstable communication"
        },
        {
            "name": "max_response_time",
            "description": "Maximum response latency observed",
            "calculation": "max(response_times)",
            "importance": "Peak latency violations"
        },
        {
            "name": "latency_violations",
            "description": "Count of responses exceeding 100μs",
            "calculation": "sum(response_time > 100 for each response)",
            "importance": "Direct measure of timing violations"
        },
        {
            "name": "avg_size",
            "description": "Average packet size in bytes",
            "calculation": "mean(packet_lengths)",
            "importance": "Unusual sizes may indicate protocol issues"
        },
        {
            "name": "size_variance",
            "description": "Variation in packet sizes",
            "calculation": "var(packet_lengths)",
            "importance": "High variance indicates mixed traffic types"
        },
        {
            "name": "max_size",
            "description": "Largest packet size observed",
            "calculation": "max(packet_lengths)",
            "importance": "Oversized packets may cause processing delays"
        },
        {
            "name": "min_size",
            "description": "Smallest packet size observed", 
            "calculation": "min(packet_lengths)",
            "importance": "Very small packets might be control messages"
        }
    ]
    
    for i, feature in enumerate(features, 1):
        print(f"{i:2d}. {feature['name'].upper()}")
        print(f"    Description: {feature['description']}")
        print(f"    Calculation: {feature['calculation']}")
        print(f"    Importance: {feature['importance']}")
        print()

def show_response_time_calculation():
    """Show detailed response time calculation logic"""
    
    print("RESPONSE TIME CALCULATION LOGIC")
    print("=" * 35)
    print()
    
    print("ALGORITHM:")
    print("For each DU packet in the time window:")
    print("1. Record DU packet timestamp")
    print("2. Search for RU response packets")
    print("3. Find RU packet with timestamp > DU timestamp")
    print("4. Calculate response_time = (RU_time - DU_time) * 1,000,000 μs")
    print("5. Only consider responses within 1ms window")
    print()
    
    print("EXAMPLE:")
    print("DU Packet #1247 at 1625097601.235000s")
    print("RU Packet #1248 at 1625097601.235087s")
    print("Response Time = (1625097601.235087 - 1625097601.235000) * 1M")
    print("Response Time = 87 μs ✓ (within 100μs threshold)")
    print()
    
    print("DU Packet #1289 at 1625097601.457000s") 
    print("RU Packet #1290 at 1625097601.457156s")
    print("Response Time = (1625097601.457156 - 1625097601.457000) * 1M")
    print("Response Time = 156 μs ✗ (exceeds 100μs threshold)")
    print()
    
    print("MISSING RESPONSE DETECTION:")
    print("DU Packet #1456 at 1625097601.678000s")
    print("No RU response found within 1ms window")
    print("Result: missing_responses += 1")

def show_feature_matrix_example():
    """Show concrete example of feature matrix creation"""
    
    print("FEATURE MATRIX CREATION EXAMPLE")
    print("=" * 35)
    print()
    
    print("INPUT PCAP: 10,000 packets over 60 seconds")
    print("TIME WINDOWS: 60s ÷ 0.1s = 600 windows")
    print("FEATURES PER WINDOW: 16")
    print("FINAL MATRIX: 600 rows × 16 columns")
    print()
    
    print("SAMPLE FEATURE MATRIX (first 3 windows):")
    print("-" * 80)
    
    headers = ["Window", "DU_cnt", "RU_cnt", "Ratio", "Missing", "Avg_RT", "Jitter", 
              "Violations", "Avg_Size", "...8 more"]
    print(f"{'':>8} {' '.join(f'{h:>8}' for h in headers)}")
    print("-" * 80)
    
    # Sample data
    samples = [
        [1, 12, 11, 0.92, 1, 78.5, 15.2, 0, 128, "..."],
        [2, 8, 8, 1.00, 0, 82.1, 12.8, 0, 132, "..."],
        [3, 15, 6, 0.40, 9, 145.7, 45.6, 8, 127, "..."]  # Anomaly
    ]
    
    for sample in samples:
        print(f"{'':>8} {' '.join(f'{str(val):>8}' for val in sample)}")
    
    print("-" * 80)
    print("Window 3 shows clear anomaly:")
    print("• High missing responses (9 out of 15)")
    print("• High average response time (145.7μs > 100μs)")
    print("• High jitter (45.6μs)")
    print("• Multiple latency violations (8)")

def show_normalization_process():
    """Show how features are normalized for ML algorithms"""
    
    print("FEATURE NORMALIZATION FOR ML")
    print("=" * 30)
    print()
    
    print("WHY NORMALIZATION IS NEEDED:")
    print("• Response times in microseconds (0-500 range)")
    print("• Packet counts in units (0-20 range)")
    print("• Packet sizes in bytes (64-1500 range)")
    print("• Without normalization, large values dominate")
    print()
    
    print("STANDARDSCALER NORMALIZATION:")
    print("• Transforms each feature to mean=0, std=1")
    print("• Formula: normalized = (value - mean) / std_deviation")
    print()
    
    print("EXAMPLE:")
    print("Response times: [75, 82, 156, 78, 145, 83, 76]")
    print("Mean = 99.3μs, Std = 32.8μs")
    print()
    print("Normalized values:")
    print("• 75μs → (75-99.3)/32.8 = -0.74")
    print("• 156μs → (156-99.3)/32.8 = 1.73")
    print("• 145μs → (145-99.3)/32.8 = 1.39")
    print()
    print("Now all features are on similar scale for ML algorithms")

def main():
    explain_pcap_to_features_process()
    print()
    explain_16_features_extraction()
    print()
    show_response_time_calculation()
    print()
    show_feature_matrix_example()
    print()
    show_normalization_process()

if __name__ == "__main__":
    main()