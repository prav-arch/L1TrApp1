#!/usr/bin/env python3
"""
Script to show the exact prompt sent to the LLM
"""

def show_llm_prompt():
    """Display the actual prompt sent to the LLM for PCAP analysis"""
    
    # Mock packet data similar to what the system generates
    packet_data = {
        'pcap_file': 'fronthaul_capture.pcap',
        'total_packets': 18947,
        'du_ru_packets': [
            {'packet_id': 1247, 'timestamp': 1625097601.235, 'direction': 'DU_TO_RU', 'size': 128},
            {'packet_id': 1289, 'timestamp': 1625097601.457, 'direction': 'DU_TO_RU', 'size': 156},
            {'packet_id': 1456, 'timestamp': 1625097601.678, 'direction': 'DU_TO_RU', 'size': 142},
            {'packet_id': 1248, 'timestamp': 1625097601.236, 'direction': 'RU_TO_DU', 'size': 64},
            {'packet_id': 1290, 'timestamp': 1625097601.458, 'direction': 'RU_TO_DU', 'size': 72},
            {'packet_id': 1457, 'timestamp': 1625097601.679, 'direction': 'RU_TO_DU', 'size': 58}
        ],
        'du_mac': '00:11:22:33:44:67',
        'ru_mac': '6c:ad:ad:00:03:2a'
    }
    
    # Create the prompt exactly as the system does
    du_packets = []
    ru_packets = []
    
    for pkt in packet_data['du_ru_packets'][:20]:  # Analyze first 20 packets only
        if pkt['direction'] == 'DU_TO_RU':
            du_packets.append(f"DU#{pkt['packet_id']}@{pkt['timestamp']:.3f}s")
        else:
            ru_packets.append(f"RU#{pkt['packet_id']}@{pkt['timestamp']:.3f}s")
    
    prompt = f"""5G fronthaul PCAP analysis for DU-RU communication failures.

File: {packet_data['pcap_file']}
Total packets: {packet_data['total_packets']}
DU MAC: {packet_data['du_mac']}
RU MAC: {packet_data['ru_mac']}

DU packets: {' '.join(du_packets[:10])}
RU packets: {' '.join(ru_packets[:10])}

ANALYZE FOR:
1. DU sends but RU doesn't respond (communication failures)
2. Response latency >100μs (timing violations)
3. Jitter >50μs (synchronization issues)
4. Root causes from packet patterns

Requirements: ≤100μs latency, <50μs jitter, <1% loss

Provide ONLY analysis findings with packet IDs. NO recommendations or troubleshooting steps."""

    return prompt

def main():
    print("LLM PROMPT EXAMINATION")
    print("=" * 60)
    print("This is the EXACT prompt sent to the LLM for PCAP analysis:")
    print()
    
    prompt = show_llm_prompt()
    
    print("PROMPT START")
    print("-" * 40)
    print(prompt)
    print("-" * 40)
    print("PROMPT END")
    print()
    
    print("PROMPT ANALYSIS:")
    print(f"Total characters: {len(prompt)}")
    print(f"Estimated tokens: {len(prompt)//4}")
    print(f"Token limit status: {'WITHIN LIMIT' if len(prompt)//4 < 4092 else 'EXCEEDS LIMIT'}")
    print()
    
    print("KEY ELEMENTS:")
    print("✓ File and packet counts")
    print("✓ DU and RU MAC addresses")
    print("✓ Sample packet timestamps")
    print("✓ Analysis requirements")
    print("✓ 5G fronthaul specifications")
    print("✓ NO RECOMMENDATIONS requested")
    print()
    
    print("COMMAND LINE EQUIVALENT:")
    print("llama-cli -m model.gguf -f prompt_file.txt -n 2048 --temp 0.1 -c 4096")

if __name__ == "__main__":
    main()