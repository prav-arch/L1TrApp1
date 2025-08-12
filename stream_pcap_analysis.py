#!/usr/bin/env python3
"""
Unified DU-RU Fronthaul Communication Analysis
Detects communication failures, timing violations, and provides AI recommendations
Fixed "Argument list too long" error by using temporary files for AI analysis
"""

import sys
import subprocess
import json
import tempfile
import os
from scapy.all import rdpcap, Ether, IP, UDP
from datetime import datetime
import argparse
from decimal import Decimal

def serialize_for_json(obj):
    """Convert objects to JSON serializable format"""
    if isinstance(obj, (Decimal, float)):
        return float(obj)
    elif hasattr(obj, '__float__'):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [serialize_for_json(item) for item in obj]
    elif hasattr(obj, 'isoformat'):
        return obj.isoformat()
    else:
        return obj

class UnifiedFronthaulAnalyzer:
    def __init__(self, model_path="/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"):
        self.model_path = model_path
        self.DU_MAC = "00:11:22:33:44:67"
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        self.detected_anomalies = []
        self.llama_binary = "/tmp/llama.cpp/build/bin/llama-cli"
        
    def get_communication_direction(self, src_mac, dst_mac):
        """Determine communication direction between DU and RU"""
        src_lower = src_mac.lower()
        dst_lower = dst_mac.lower()
        
        if src_lower == self.DU_MAC.lower() and dst_lower == self.RU_MAC.lower():
            return 'DU_TO_RU'
        elif src_lower == self.RU_MAC.lower() and dst_lower == self.DU_MAC.lower():
            return 'RU_TO_DU'
        return None
    
    def analyze_communication_failures(self, packets):
        """Main analysis function for DU-RU communication failures"""
        print("ANALYZING FRONTHAUL COMMUNICATION FAILURES")
        print("=" * 70)
        
        # Track DU messages and RU responses separately
        du_messages = []
        ru_responses = []
        communication_failures = []
        latency_violations = []
        jitter_issues = []
        packet_loss_events = []
        
        print("Processing packets for fronthaul analysis...")
        
        for i, packet in enumerate(packets):
            if not Ether in packet:
                continue
                
            src_mac = packet[Ether].src.lower()
            dst_mac = packet[Ether].dst.lower()
            timestamp = float(packet.time)
            
            # Collect DU→RU messages
            if src_mac == self.DU_MAC.lower() and dst_mac == self.RU_MAC.lower():
                du_msg = {
                    'packet_id': i,
                    'timestamp': timestamp,
                    'size': len(packet),
                    'responded': False,
                    'response_time': None,
                    'latency_us': None
                }
                du_messages.append(du_msg)
                
            # Collect RU→DU responses
            elif src_mac == self.RU_MAC.lower() and dst_mac == self.DU_MAC.lower():
                ru_resp = {
                    'packet_id': i,
                    'timestamp': timestamp,
                    'size': len(packet)
                }
                ru_responses.append(ru_resp)
        
        print(f"DU→RU messages found: {len(du_messages)}")
        print(f"RU→DU responses found: {len(ru_responses)}")
        
        # Analyze fronthaul requirements
        response_window = 0.0001  # 100μs critical threshold for 5G fronthaul
        extended_window = 0.001   # 1ms extended window
        
        print("Analyzing fronthaul timing requirements...")
        
        # Match DU messages with RU responses
        for du_msg in du_messages:
            du_time = du_msg['timestamp']
            
            # Find matching RU response within timing windows
            for ru_resp in ru_responses:
                ru_time = ru_resp['timestamp']
                time_diff = ru_time - du_time
                
                # Must be after DU message and within extended window
                if 0 < time_diff <= extended_window:
                    du_msg['responded'] = True
                    du_msg['response_time'] = ru_time
                    du_msg['latency_us'] = time_diff * 1000000  # Convert to microseconds
                    
                    # Check for latency violations
                    if time_diff > response_window:
                        violation = {
                            'du_packet_id': du_msg['packet_id'],
                            'ru_packet_id': ru_resp['packet_id'],
                            'latency_us': time_diff * 1000000,
                            'timestamp': du_time,
                            'severity': 'CRITICAL' if time_diff > 0.001 else 'HIGH'
                        }
                        latency_violations.append(violation)
                    break
        
        # Identify communication failures (DU messages without RU response)
        for du_msg in du_messages:
            if not du_msg['responded']:
                failure = {
                    'packet_id': du_msg['packet_id'],
                    'timestamp': du_msg['timestamp'],
                    'issue_type': 'NO_RU_RESPONSE',
                    'severity': 'CRITICAL',
                    'description': f"DU message #{du_msg['packet_id']} - RU never responded (>1ms timeout)"
                }
                communication_failures.append(failure)
        
        # Calculate metrics
        total_du_messages = len(du_messages)
        responded_messages = sum(1 for msg in du_messages if msg['responded'])
        failure_rate = ((total_du_messages - responded_messages) / total_du_messages * 100) if total_du_messages > 0 else 0
        
        # Calculate average latency for responded messages
        latencies = [msg['latency_us'] for msg in du_messages if msg['latency_us'] is not None]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        
        # Analyze jitter (variation in latency)
        if len(latencies) > 1:
            jitter_values = []
            for i in range(1, len(latencies)):
                jitter = abs(latencies[i] - latencies[i-1])
                if jitter > 50:  # >50μs jitter threshold
                    jitter_issues.append({
                        'packet_pair': [i-1, i],
                        'jitter_us': jitter,
                        'severity': 'HIGH' if jitter > 100 else 'MEDIUM'
                    })
        
        # Detect packet loss patterns
        time_windows = self.analyze_packet_loss_windows(packets, du_messages, ru_responses)
        packet_loss_events = [window for window in time_windows if window['loss_rate'] > 0.2]  # >20% loss
        
        # Display results
        print()
        print("FRONTHAUL ANALYSIS RESULTS:")
        print("-" * 50)
        print(f"Total DU→RU messages: {total_du_messages}")
        print(f"Messages with RU response: {responded_messages}")
        print(f"Communication failure rate: {failure_rate:.1f}%")
        print(f"Average round-trip latency: {avg_latency:.1f}μs")
        print(f"Ultra-low latency violations (>100μs): {len(latency_violations)}")
        print(f"Jitter issues detected: {len(jitter_issues)}")
        print(f"Packet loss events: {len(packet_loss_events)}")
        
        if communication_failures:
            print(f"CRITICAL: {len(communication_failures)} DU MESSAGES WITHOUT RU RESPONSE")
        if latency_violations:
            print(f"WARNING: {len(latency_violations)} LATENCY VIOLATIONS (>100μs)")
        if jitter_issues:
            max_jitter = max(issue['jitter_us'] for issue in jitter_issues)
            print(f"WARNING: JITTER DETECTED - {max_jitter:.1f}μs maximum")
        
        # Prepare data for AI analysis
        analysis_data = {
            'total_du_messages': total_du_messages,
            'responded_messages': responded_messages,
            'communication_failures': communication_failures[:10],  # Limit for AI analysis
            'failure_rate': float(failure_rate),
            'avg_latency_us': float(avg_latency),
            'latency_violations': len(latency_violations),
            'jitter_issues': len(jitter_issues),
            'packet_loss_events': len(packet_loss_events),
            'equipment_info': {
                'DU_MAC': self.DU_MAC,
                'RU_MAC': self.RU_MAC
            }
        }
        
        return analysis_data
    
    def analyze_packet_loss_windows(self, packets, du_messages, ru_responses, window_size=1.0):
        """Analyze packet loss in time windows"""
        if not packets:
            return []
        
        start_time = float(packets[0].time) if hasattr(packets[0], 'time') else 0
        end_time = float(packets[-1].time) if hasattr(packets[-1], 'time') else start_time + 1
        
        windows = []
        current_time = start_time
        
        while current_time < end_time:
            window_end = current_time + window_size
            
            # Count messages and responses in this window
            window_du_msgs = [msg for msg in du_messages if current_time <= msg['timestamp'] < window_end]
            window_ru_resps = [resp for resp in ru_responses if current_time <= resp['timestamp'] < window_end]
            
            if window_du_msgs:
                expected_responses = len(window_du_msgs)
                actual_responses = len(window_ru_resps)
                loss_rate = (expected_responses - actual_responses) / expected_responses
                
                windows.append({
                    'start_time': current_time,
                    'end_time': window_end,
                    'expected_responses': expected_responses,
                    'actual_responses': actual_responses,
                    'loss_rate': loss_rate
                })
            
            current_time = window_end
        
        return windows
    
    def analyze_pcap_with_llm(self, packets, pcap_file):
        """Let LLM directly analyze PCAP packet data for communication issues"""
        print()
        print("LLM-POWERED PCAP ANALYSIS:")
        print("=" * 70)
        
        try:
            # Extract detailed packet information for LLM analysis
            packet_data = self.extract_packet_data_for_llm(packets, pcap_file)
            
            # Create comprehensive prompt with packet details
            prompt = self.create_llm_pcap_analysis_prompt(packet_data, pcap_file)
            
            # Write prompt to temporary file to avoid command line length limits
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(prompt)
                temp_file_path = temp_file.name
            
            try:
                # Run llama-cli with file input
                cmd = [
                    self.llama_binary,
                    "-m", self.model_path,
                    "-f", temp_file_path,
                    "-n", "2048",  # Increased for detailed analysis
                    "--temp", "0.1",
                    "-c", "4096"   # Increased context
                ]
                
                print("LLM is streaming analysis of PCAP packet data...")
                print("LLM STREAMING ANALYSIS RESULTS:")
                print("-" * 40)
                
                # Use streaming subprocess for real-time output
                findings = self.stream_llm_analysis_subprocess(cmd)
                return findings
                    
            finally:
                # Clean up temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
                    
        except subprocess.TimeoutExpired:
            print("LLM analysis timed out, performing basic analysis...")
            return self.provide_basic_packet_analysis(packets)
        except Exception as e:
            print(f"LLM Analysis error: {e}")
            return self.provide_basic_packet_analysis(packets)
    
    def extract_packet_data_for_llm(self, packets, pcap_file):
        """Extract detailed packet information for LLM analysis"""
        packet_details = []
        du_ru_packets = []
        
        for i, packet in enumerate(packets[:100]):  # Limit to first 100 packets for LLM to reduce tokens
            if not Ether in packet:
                continue
                
            src_mac = packet[Ether].src.lower()
            dst_mac = packet[Ether].dst.lower()
            timestamp = float(packet.time) if hasattr(packet, 'time') else 0
            
            # Focus on DU-RU communication
            communication_type = self.get_communication_direction(src_mac, dst_mac)
            if communication_type:
                packet_info = {
                    'packet_id': i,
                    'timestamp': timestamp,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'size': len(packet),
                    'direction': communication_type,
                    'protocols': []
                }
                
                # Extract protocol information
                if IP in packet:
                    packet_info['protocols'].append('IP')
                    packet_info['src_ip'] = packet[IP].src
                    packet_info['dst_ip'] = packet[IP].dst
                    
                if UDP in packet:
                    packet_info['protocols'].append('UDP')
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                
                # Check for specific protocols that might indicate fronthaul traffic
                if hasattr(packet, 'load') and packet.load:
                    payload_len = len(packet.load)
                    packet_info['payload_size'] = payload_len
                    # Sample first few bytes of payload (hex representation)
                    if payload_len > 0:
                        packet_info['payload_sample'] = packet.load[:16].hex()
                
                du_ru_packets.append(packet_info)
        
        return {
            'pcap_file': pcap_file,
            'total_packets': len(packets),
            'du_ru_packets': du_ru_packets,
            'analysis_scope': f"First {len(du_ru_packets)} DU-RU packets out of {len(packets)} total",
            'du_mac': self.DU_MAC,
            'ru_mac': self.RU_MAC
        }
    
    def create_llm_pcap_analysis_prompt(self, packet_data, pcap_file):
        """Create concise prompt for LLM to analyze PCAP data within token limits"""
        
        # Create a concise packet summary for the LLM (limit to 20 packets to reduce tokens)
        du_packets = []
        ru_packets = []
        
        for pkt in packet_data['du_ru_packets'][:20]:  # Analyze first 20 packets only
            if pkt['direction'] == 'DU_TO_RU':
                du_packets.append(f"DU#{pkt['packet_id']}@{pkt['timestamp']:.3f}s")
            else:
                ru_packets.append(f"RU#{pkt['packet_id']}@{pkt['timestamp']:.3f}s")
        
        prompt = f"""5G fronthaul PCAP analysis for DU-RU communication failures.

File: {pcap_file}
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
    
    def format_llm_packet_analysis(self, ai_response):
        """Format and display LLM's direct packet analysis (NO recommendations)"""
        lines = ai_response.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Skip recommendation lines as user doesn't want them
            if any(keyword in line.lower() for keyword in ['recommend', 'check', 'verify', 'action', 'should', 'troubleshoot']):
                continue
                
            # Format different types of analysis with prefixes
            if any(keyword in line.lower() for keyword in ['packet', 'communication failure', 'no response']):
                print(f"PACKET ANALYSIS: {line}")
            elif any(keyword in line.lower() for keyword in ['latency', 'timing', 'microsecond', 'μs']):
                print(f"TIMING ANALYSIS: {line}")
            elif any(keyword in line.lower() for keyword in ['jitter', 'synchronization', 'sync']):
                print(f"SYNC ANALYSIS: {line}")
            elif any(keyword in line.lower() for keyword in ['root cause', 'reason', 'likely cause']):
                print(f"ROOT CAUSE: {line}")
            elif any(keyword in line.lower() for keyword in ['critical', 'urgent', 'immediate']):
                print(f"CRITICAL FINDING: {line}")
            else:
                print(f"ANALYSIS: {line}")
    
    def extract_findings_from_llm_response(self, ai_response):
        """Extract structured findings from LLM response for further processing"""
        findings = {
            'communication_failures': [],
            'timing_violations': [],
            'critical_issues': [],
            'recommendations': []
        }
        
        lines = ai_response.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Extract specific findings based on keywords
            if 'packet' in line.lower() and any(kw in line.lower() for kw in ['fail', 'no response', 'missing']):
                findings['communication_failures'].append(line)
            elif any(kw in line.lower() for kw in ['latency', 'timing', '100μs', 'violation']):
                findings['timing_violations'].append(line)
            elif any(kw in line.lower() for kw in ['critical', 'urgent', 'immediate']):
                findings['critical_issues'].append(line)
            elif any(kw in line.lower() for kw in ['recommend', 'check', 'action']):
                findings['recommendations'].append(line)
        
        return findings
    
    def stream_llm_analysis_subprocess(self, cmd):
        """Stream LLM output in real-time and format analysis (NO recommendations)"""
        import sys
        import time
        
        findings = {
            'communication_failures': [],
            'timing_violations': [],
            'critical_issues': [],
            'recommendations': []  # Will be empty since user doesn't want them
        }
        
        try:
            # Start subprocess with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                universal_newlines=True
            )
            
            output_buffer = ""
            
            # Read output line by line as it comes
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    output_buffer += line + "\n"
                    
                    # Filter out recommendation lines as user doesn't want them
                    if any(keyword in line.lower() for keyword in ['recommend', 'check', 'verify', 'action', 'should', 'troubleshoot']):
                        continue
                    
                    # Format and display analysis in real-time
                    if any(keyword in line.lower() for keyword in ['packet', 'communication failure', 'no response']):
                        print(f"PACKET ANALYSIS: {line}")
                        findings['communication_failures'].append(line)
                        sys.stdout.flush()
                    elif any(keyword in line.lower() for keyword in ['latency', 'timing', 'microsecond', 'μs']):
                        print(f"TIMING ANALYSIS: {line}")
                        findings['timing_violations'].append(line)
                        sys.stdout.flush()
                    elif any(keyword in line.lower() for keyword in ['jitter', 'synchronization', 'sync']):
                        print(f"SYNC ANALYSIS: {line}")
                        sys.stdout.flush()
                    elif any(keyword in line.lower() for keyword in ['root cause', 'reason', 'likely cause']):
                        print(f"ROOT CAUSE: {line}")
                        sys.stdout.flush()
                    elif any(keyword in line.lower() for keyword in ['critical', 'urgent', 'immediate']):
                        print(f"CRITICAL FINDING: {line}")
                        findings['critical_issues'].append(line)
                        sys.stdout.flush()
                    elif line and not line.startswith(('#', '>', '<', '|')):  # Skip system messages
                        print(f"ANALYSIS: {line}")
                        sys.stdout.flush()
                    
                    # Small delay to show streaming effect
                    time.sleep(0.1)
            
            # Wait for process to complete
            process.wait()
            
            if process.returncode != 0:
                stderr_output = process.stderr.read()
                print(f"LLM streaming error: {stderr_output}")
                return self.provide_basic_packet_analysis([])
                
            return findings
            
        except Exception as e:
            print(f"Streaming error: {e}")
            return self.provide_basic_packet_analysis([])
    
    def provide_basic_packet_analysis(self, packets):
        """Provide basic packet analysis when LLM is unavailable"""
        print("BASIC PACKET ANALYSIS (LLM unavailable):")
        print("-" * 50)
        
        du_count = 0
        ru_count = 0
        
        for packet in packets:
            if not Ether in packet:
                continue
                
            src_mac = packet[Ether].src.lower()
            dst_mac = packet[Ether].dst.lower()
            
            if src_mac == self.DU_MAC.lower() and dst_mac == self.RU_MAC.lower():
                du_count += 1
            elif src_mac == self.RU_MAC.lower() and dst_mac == self.DU_MAC.lower():
                ru_count += 1
        
        print(f"DU->RU packets found: {du_count}")
        print(f"RU->DU packets found: {ru_count}")
        
        if du_count > ru_count:
            failure_rate = ((du_count - ru_count) / du_count) * 100
            print(f"Potential communication failures: {failure_rate:.1f}%")
            print("RECOMMENDATION: Check RU connectivity and response capability")
        
        return {
            'du_packets': du_count,
            'ru_packets': ru_count,
            'analysis_method': 'basic'
        }
    
    def create_fronthaul_analysis_prompt(self, data):
        """Create a focused prompt for fronthaul analysis"""
        prompt = f"""You are a 5G network expert analyzing fronthaul communication between DU and RU equipment.

ANALYSIS DATA:
- Total DU messages: {data['total_du_messages']}
- Messages with RU response: {data['responded_messages']}
- Communication failure rate: {data['failure_rate']:.1f}%
- Average latency: {data['avg_latency_us']:.1f}μs
- Latency violations: {data['latency_violations']}
- Jitter issues: {data['jitter_issues']}
- Packet loss events: {data['packet_loss_events']}
- DU MAC: {data['equipment_info']['DU_MAC']}
- RU MAC: {data['equipment_info']['RU_MAC']}

REQUIREMENTS:
- 5G fronthaul requires ≤100μs latency
- Jitter should be <50μs
- Packet loss should be <1%

CRITICAL ISSUE: DU is sending messages but RU is not responding in {data['failure_rate']:.1f}% of cases.

Provide specific analysis for each issue type found and actionable remediation steps. Focus on the DU→RU communication breakdown."""
        
        return prompt
    
    def format_ai_fronthaul_analysis(self, ai_response, data):
        """Format and display AI analysis with fronthaul-specific formatting"""
        lines = ai_response.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Format different types of analysis
            if any(keyword in line.lower() for keyword in ['critical', 'urgent', 'failure', 'violation']):
                print(f"FRONTHAUL ISSUE: {line}")
            elif any(keyword in line.lower() for keyword in ['latency', 'timing', 'jitter', 'loss']):
                print(f"MEASUREMENT: {line}")
            elif any(keyword in line.lower() for keyword in ['recommend', 'check', 'verify', 'test']):
                print(f"REMEDIATION: {line}")
            elif any(keyword in line.lower() for keyword in ['cause', 'reason', 'likely']):
                print(f"ROOT CAUSE: {line}")
            elif any(keyword in line.lower() for keyword in ['action', 'step', 'immediate']):
                print(f"ACTION PLAN: {line}")
            else:
                print(f"ANALYSIS: {line}")
    
    def provide_fallback_analysis(self, data):
        """Provide expert analysis when AI is unavailable"""
        print("EXPERT FRONTHAUL ANALYSIS:")
        print("-" * 40)
        
        # Communication breakdown analysis
        if data['failure_rate'] > 5:
            print(f"FRONTHAUL ISSUE: COMMUNICATION_BREAKDOWN - CRITICAL")
            print(f"MEASUREMENT: {data['failure_rate']:.1f}% of DU control messages received no RU response")
            print("REMEDIATION: Verify RU power status, check physical fiber connections, test signal strength")
            print()
        
        # Latency violation analysis
        if data['avg_latency_us'] > 100:
            print(f"FRONTHAUL ISSUE: ULTRA_LOW_LATENCY_VIOLATION - CRITICAL")
            print(f"MEASUREMENT: {data['latency_violations']} messages exceeded 100μs (avg: {data['avg_latency_us']:.1f}μs vs required ≤100μs)")
            print("REMEDIATION: Check DU processing delays, network congestion, and hardware bottlenecks")
            print()
        
        # Severe timing issues
        if data['avg_latency_us'] > 1000:
            print(f"FRONTHAUL ISSUE: SEVERE_LATENCY_VIOLATION - CRITICAL")
            print(f"MEASUREMENT: Round-trip latencies averaging {data['avg_latency_us']:.1f}μs detected ({data['avg_latency_us']/100:.1f}x over threshold)")
            print("REMEDIATION: Immediate investigation of network path and hardware performance")
            print()
        
        # Jitter analysis
        if data['jitter_issues'] > 0:
            print(f"FRONTHAUL ISSUE: JITTER_VIOLATION - HIGH")
            print(f"MEASUREMENT: {data['jitter_issues']} jitter events exceeding 50μs synchronization threshold")
            print("REMEDIATION: Check buffer management, clock synchronization, and network stability")
            print()
        
        # Packet loss analysis  
        if data['packet_loss_events'] > 0:
            print(f"FRONTHAUL ISSUE: PACKET_LOSS_BURST - HIGH")
            print(f"MEASUREMENT: {data['packet_loss_events']} windows with >20% packet loss detected affecting protocol reliability")
            print("REMEDIATION: Inspect physical layer - cables, connectors, interference sources")
            print()
        
        # Root cause analysis
        print("ROOT CAUSE ANALYSIS:")
        if data['failure_rate'] > 10:
            print("Primary issue appears to be RU processing delays or connectivity problems")
        if data['avg_latency_us'] > 200:
            print("Secondary issue is network congestion causing timing violations")
        print("Recommend immediate physical layer inspection and RU diagnostics")
        print()
        
        # Action plan
        print("IMMEDIATE ACTIONS REQUIRED:")
        print("1. Check RU power status and LED indicators")
        print("2. Verify all fiber optic connections and signal quality")
        print("3. Test DU-RU link with reduced traffic load")
        print("4. Update RU firmware if outdated")
        print("5. Monitor for electromagnetic interference")

def main():
    if len(sys.argv) != 2:
        print("Usage: python stream_pcap_analysis.py <pcap_file>")
        print("Example: python stream_pcap_analysis.py fronthaul_capture.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file '{pcap_file}' not found")
        sys.exit(1)
    
    print("Starting LLM-powered PCAP analysis...")
    print("=" * 60)
    print(f"Processing: {pcap_file}")
    
    try:
        # Load packets
        packets = rdpcap(pcap_file)
        print(f"Total Packets: {len(packets)}")
        
        # Initialize analyzer
        analyzer = UnifiedFronthaulAnalyzer()
        
        # Count DU-RU packets for overview
        du_count = 0
        ru_count = 0
        for packet in packets:
            if Ether in packet:
                communication_type = analyzer.get_communication_direction(
                    packet[Ether].src, packet[Ether].dst
                )
                if communication_type == 'DU_TO_RU':
                    du_count += 1
                elif communication_type == 'RU_TO_DU':
                    ru_count += 1
        
        print(f"DU->RU Communications: {du_count}")
        print(f"RU->DU Responses: {ru_count}")
        
        if du_count > ru_count:
            potential_failures = du_count - ru_count
            print(f"Potential Communication Issues: {potential_failures}")
        
        # Let LLM analyze the PCAP data directly
        llm_findings = analyzer.analyze_pcap_with_llm(packets, pcap_file)
        
        # Display structured summary from LLM analysis
        if llm_findings and isinstance(llm_findings, dict):
            print()
            print("LLM ANALYSIS SUMMARY:")
            print("-" * 40)
            
            if llm_findings.get('communication_failures'):
                print(f"Communication Failures Found: {len(llm_findings['communication_failures'])}")
                for failure in llm_findings['communication_failures'][:3]:
                    print(f"  - {failure}")
            
            if llm_findings.get('timing_violations'):
                print(f"Timing Violations Found: {len(llm_findings['timing_violations'])}")
                for violation in llm_findings['timing_violations'][:3]:
                    print(f"  - {violation}")
            
            if llm_findings.get('critical_issues'):
                print("Critical Issues:")
                for issue in llm_findings['critical_issues'][:3]:
                    print(f"  - {issue}")
            
            if llm_findings.get('recommendations'):
                print("Key Recommendations:")
                for rec in llm_findings['recommendations'][:3]:
                    print(f"  - {rec}")
        
        print()
        print("LLM PCAP ANALYSIS COMPLETE")
        print("The LLM has directly analyzed your packet data for communication issues.")
        
    except Exception as e:
        print(f"Error processing PCAP file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()