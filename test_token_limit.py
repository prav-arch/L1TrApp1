#!/usr/bin/env python3
"""
Test script to demonstrate the token limit fix
"""

def create_old_prompt_style():
    """Simulate the old verbose prompt that caused token limits"""
    prompt = """You are a 5G network expert analyzing PCAP packet capture data for fronthaul communication issues between DU and RU equipment.

PCAP FILE: fronthaul_capture.pcap
TOTAL PACKETS: 18947
DU-RU PACKETS ANALYZED: 500
DU MAC ADDRESS: 00:11:22:33:44:67
RU MAC ADDRESS: 6c:ad:ad:00:03:2a

PACKET DETAILS FOR ANALYSIS:
Packet 1247: DU_TO_RU at 1625097601.234567s, Size: 128 bytes, UDP 5000->5001, Payload: a1b2c3d4e5f6a7b8
Packet 1289: DU_TO_RU at 1625097601.456789s, Size: 156 bytes, UDP 5000->5001, Payload: e5f6a7b8c9d0e1f2
Packet 1456: RU_TO_DU at 1625097601.567890s, Size: 64 bytes, UDP 5001->5000, Payload: f3a4b5c6d7e8f9a0
""" + "\n".join([f"Packet {i}: DU_TO_RU at 1625097601.{i:06d}s, Size: 128 bytes, UDP 5000->5001, Payload: a1b2c3d4e5f6a7b8" for i in range(1000, 1050)])
    
    prompt += """

ANALYSIS REQUIREMENTS:
1. Examine the packet timing patterns between DU and RU
2. Identify communication failures where DU sends but RU doesn't respond
3. Calculate latency violations (>100μs for 5G fronthaul)
4. Detect jitter and synchronization issues
5. Find packet loss patterns
6. Determine root causes of communication breakdowns

CRITICAL FOCUS: Look for cases where DU (00:11:22:33:44:67) sends messages but RU (6c:ad:ad:00:03:2a) fails to respond or responds too late.

5G FRONTHAUL REQUIREMENTS:
- Ultra-low latency: ≤100μs
- Jitter tolerance: <50μs
- Packet loss: <1%
- Synchronization accuracy: Critical

Please analyze these packets and provide:
1. Communication failure detection with specific packet IDs
2. Timing violation analysis with measurements
3. Root cause identification
4. Specific troubleshooting recommendations
5. Priority ranking of issues found

Focus on actual packet-level evidence from the data provided above."""

    return prompt

def create_new_prompt_style():
    """Simulate the new concise prompt that fits within token limits"""
    prompt = """5G fronthaul PCAP analysis for DU-RU communication failures.

File: fronthaul_capture.pcap
Total packets: 18947
DU MAC: 00:11:22:33:44:67
RU MAC: 6c:ad:ad:00:03:2a

DU packets: DU#1247@1625097601.235s DU#1289@1625097601.457s DU#1456@1625097601.678s
RU packets: RU#1248@1625097601.236s RU#1290@1625097601.458s

ANALYZE FOR:
1. DU sends but RU doesn't respond (communication failures)
2. Response latency >100μs (timing violations)
3. Jitter >50μs (synchronization issues)
4. Root causes and fixes

Requirements: ≤100μs latency, <50μs jitter, <1% loss

Provide specific findings with packet IDs and troubleshooting steps."""

    return prompt

def main():
    print("TOKEN LIMIT FIX DEMONSTRATION")
    print("=" * 50)
    
    old_prompt = create_old_prompt_style()
    new_prompt = create_new_prompt_style()
    
    print(f"OLD PROMPT:")
    print(f"Characters: {len(old_prompt)}")
    print(f"Estimated tokens: {len(old_prompt)//4}")
    print(f"Result: {'EXCEEDS 4092 TOKEN LIMIT' if len(old_prompt)//4 > 4092 else 'Within limit'}")
    print()
    
    print(f"NEW PROMPT:")
    print(f"Characters: {len(new_prompt)}")
    print(f"Estimated tokens: {len(new_prompt)//4}")
    print(f"Result: {'EXCEEDS 4092 TOKEN LIMIT' if len(new_prompt)//4 > 4092 else 'WITHIN TOKEN LIMIT'}")
    print()
    
    print("TOKEN REDUCTION:")
    print(f"Character reduction: {len(old_prompt) - len(new_prompt)} characters")
    print(f"Token reduction: {len(old_prompt)//4 - len(new_prompt)//4} tokens")
    print(f"Reduction percentage: {((len(old_prompt) - len(new_prompt))/len(old_prompt))*100:.1f}%")
    
    print()
    print("NEW PROMPT PREVIEW:")
    print("-" * 30)
    print(new_prompt)

if __name__ == "__main__":
    main()