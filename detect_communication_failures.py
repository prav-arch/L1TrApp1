#!/usr/bin/env python3
"""
Enhanced communication failure detection for DU→RU fronthaul analysis
Specifically detects cases where DU sends messages but RU doesn't receive or respond
"""

import json
import subprocess
import sys
from scapy.all import rdpcap, Ether, IP, UDP
from decimal import Decimal

class CommunicationFailureDetector:
    def __init__(self):
        self.DU_MAC = "00:11:22:33:44:67"
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        self.model_path = "/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"
        
    def analyze_pcap_for_failures(self, pcap_file):
        """Analyze PCAP specifically for DU→RU communication failures and fronthaul issues"""
        print(f"🔍 ANALYZING FRONTHAUL COMMUNICATION FAILURES: {pcap_file}")
        print("=" * 70)
        
        try:
            packets = rdpcap(pcap_file)
            print(f"📊 Total packets loaded: {len(packets)}")
        except Exception as e:
            print(f"❌ Error reading PCAP: {e}")
            return None
        
        # Track DU messages and RU responses separately
        du_messages = []
        ru_responses = []
        communication_failures = []
        latency_violations = []
        jitter_issues = []
        packet_loss_events = []
        
        print("🔄 Processing packets for fronthaul analysis...")
        
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
        
        print(f"📤 DU→RU messages found: {len(du_messages)}")
        print(f"📥 RU→DU responses found: {len(ru_responses)}")
        
        # Analyze fronthaul requirements
        response_window = 0.0001  # 100μs critical threshold for 5G fronthaul
        extended_window = 0.001   # 1ms extended window
        
        print("\n🔄 Analyzing fronthaul timing requirements...")
        
        for du_msg in du_messages:
            # Look for corresponding RU response within critical window (100μs)
            critical_response = None
            extended_response = None
            
            for ru_resp in ru_responses:
                if ru_resp['timestamp'] > du_msg['timestamp']:
                    response_time = ru_resp['timestamp'] - du_msg['timestamp']
                    
                    # Check critical 100μs window
                    if response_time <= response_window and not critical_response:
                        critical_response = ru_resp
                        du_msg['responded'] = True
                        du_msg['response_time'] = response_time
                        du_msg['latency_us'] = response_time * 1_000_000
                        break
                    # Check extended 1ms window
                    elif response_time <= extended_window and not extended_response:
                        extended_response = ru_resp
            
            # Analyze latency violations
            if critical_response:
                latency_us = du_msg['latency_us']
                if latency_us > 100:  # Ultra-low latency violation
                    latency_violations.append({
                        'packet_id': du_msg['packet_id'],
                        'timestamp': du_msg['timestamp'],
                        'latency_us': latency_us,
                        'severity': 'CRITICAL',
                        'issue_type': 'ULTRA_LOW_LATENCY_VIOLATION',
                        'description': f"Round-trip latency {latency_us:.1f}μs exceeds 100μs fronthaul requirement"
                    })
            elif extended_response:
                # Response beyond critical window but within extended
                latency_us = (extended_response['timestamp'] - du_msg['timestamp']) * 1_000_000
                du_msg['responded'] = True
                du_msg['response_time'] = extended_response['timestamp'] - du_msg['timestamp']
                du_msg['latency_us'] = latency_us
                
                latency_violations.append({
                    'packet_id': du_msg['packet_id'],
                    'timestamp': du_msg['timestamp'],
                    'latency_us': latency_us,
                    'severity': 'CRITICAL',
                    'issue_type': 'SEVERE_LATENCY_VIOLATION',
                    'description': f"Round-trip latency {latency_us:.1f}μs severely exceeds 100μs fronthaul requirement"
                })
            else:
                # No response at all - communication failure
                communication_failures.append({
                    'packet_id': du_msg['packet_id'],
                    'timestamp': du_msg['timestamp'],
                    'size': du_msg['size'],
                    'issue_type': 'NO_RU_RESPONSE',
                    'severity': 'CRITICAL',
                    'description': f"DU message #{du_msg['packet_id']} - RU never responded (>1ms timeout)"
                })
        
        # Analyze jitter in response times
        response_times = [msg['response_time'] for msg in du_messages if msg['response_time'] is not None]
        if len(response_times) > 1:
            jitter_analysis = self.analyze_jitter(response_times)
            if jitter_analysis['max_jitter_us'] > 50:  # Jitter >50μs is concerning
                jitter_issues.append(jitter_analysis)
        
        # Detect packet loss patterns
        packet_loss_events = self.detect_packet_loss(du_messages, ru_responses)
        
        # Calculate statistics
        total_du_messages = len(du_messages)
        responded_messages = sum(1 for msg in du_messages if msg['responded'])
        failure_rate = ((total_du_messages - responded_messages) / total_du_messages * 100) if total_du_messages > 0 else 0
        
        # Calculate timing performance
        valid_latencies = [msg['latency_us'] for msg in du_messages if msg['latency_us'] is not None]
        avg_latency = sum(valid_latencies) / len(valid_latencies) if valid_latencies else 0
        violations_over_100us = len([l for l in valid_latencies if l > 100])
        
        print(f"\n📈 FRONTHAUL ANALYSIS RESULTS:")
        print("-" * 50)
        print(f"Total DU→RU messages: {total_du_messages}")
        print(f"Messages with RU response: {responded_messages}")
        print(f"Communication failure rate: {failure_rate:.1f}%")
        print(f"Average round-trip latency: {avg_latency:.1f}μs")
        print(f"Ultra-low latency violations (>100μs): {violations_over_100us}")
        print(f"Jitter issues detected: {len(jitter_issues)}")
        print(f"Packet loss events: {len(packet_loss_events)}")
        
        if communication_failures:
            print(f"\n🚨 CRITICAL: {len(communication_failures)} DU MESSAGES WITHOUT RU RESPONSE")
        if latency_violations:
            print(f"⚠️  WARNING: {len(latency_violations)} LATENCY VIOLATIONS (>100μs)")
        if jitter_issues:
            print(f"⚠️  WARNING: JITTER DETECTED - {jitter_issues[0]['max_jitter_us']:.1f}μs maximum")
        
        # Analyze timing patterns for failures
        silent_periods = self.detect_silent_periods(du_messages, ru_responses)
        
        analysis_data = {
            'total_du_messages': total_du_messages,
            'responded_messages': responded_messages,
            'failure_rate': failure_rate,
            'avg_latency_us': avg_latency,
            'latency_violations': latency_violations[:15],
            'communication_failures': communication_failures[:15],
            'jitter_issues': jitter_issues,
            'packet_loss_events': packet_loss_events,
            'silent_periods': silent_periods,
            'violations_over_100us': violations_over_100us,
            'unresponded_count': len(communication_failures)
        }
        
        return analysis_data
    
    def analyze_jitter(self, response_times):
        """Analyze jitter in response times"""
        if len(response_times) < 2:
            return {'max_jitter_us': 0, 'avg_jitter_us': 0, 'jitter_violations': 0}
        
        # Convert to microseconds
        response_times_us = [rt * 1_000_000 for rt in response_times]
        
        # Calculate jitter as variation in consecutive response times
        jitter_values = []
        for i in range(1, len(response_times_us)):
            jitter = abs(response_times_us[i] - response_times_us[i-1])
            jitter_values.append(jitter)
        
        max_jitter = max(jitter_values) if jitter_values else 0
        avg_jitter = sum(jitter_values) / len(jitter_values) if jitter_values else 0
        jitter_violations = len([j for j in jitter_values if j > 50])  # >50μs jitter
        
        return {
            'max_jitter_us': max_jitter,
            'avg_jitter_us': avg_jitter,
            'jitter_violations': jitter_violations,
            'severity': 'CRITICAL' if max_jitter > 100 else 'HIGH' if max_jitter > 50 else 'NORMAL'
        }
    
    def detect_packet_loss(self, du_messages, ru_responses):
        """Detect packet loss patterns in fronthaul communication"""
        packet_loss_events = []
        
        if not du_messages:
            return packet_loss_events
        
        # Look for patterns indicating packet loss
        # 1. Sudden drops in communication rate
        # 2. Missing sequence patterns
        # 3. Burst losses
        
        # Analyze communication rate changes
        window_size = 10  # Analyze in windows of 10 messages
        
        for i in range(0, len(du_messages) - window_size, window_size):
            window_messages = du_messages[i:i + window_size]
            
            # Count responses in this window
            responses_in_window = sum(1 for msg in window_messages if msg['responded'])
            response_rate = responses_in_window / len(window_messages)
            
            # Flag windows with low response rates as potential packet loss
            if response_rate < 0.8:  # Less than 80% response rate
                packet_loss_events.append({
                    'window_start': window_messages[0]['packet_id'],
                    'window_end': window_messages[-1]['packet_id'],
                    'response_rate': response_rate,
                    'lost_packets': len(window_messages) - responses_in_window,
                    'severity': 'CRITICAL' if response_rate < 0.5 else 'HIGH',
                    'issue_type': 'PACKET_LOSS_BURST'
                })
        
        return packet_loss_events
    
    def detect_silent_periods(self, du_messages, ru_responses):
        """Detect periods where RU goes silent despite DU messages"""
        silent_periods = []
        
        if not du_messages or not ru_responses:
            return silent_periods
        
        # Sort by timestamp
        du_sorted = sorted(du_messages, key=lambda x: x['timestamp'])
        ru_sorted = sorted(ru_responses, key=lambda x: x['timestamp'])
        
        # Look for gaps where DU keeps sending but RU stops responding
        silent_threshold = 0.01  # 10ms of silence is concerning for fronthaul
        
        for i in range(len(du_sorted) - 1):
            current_time = du_sorted[i]['timestamp']
            next_time = du_sorted[i + 1]['timestamp']
            
            # Check if there are any RU responses in this time window
            ru_in_window = [r for r in ru_sorted if current_time <= r['timestamp'] <= next_time]
            
            if not ru_in_window and (next_time - current_time) > silent_threshold:
                silent_periods.append({
                    'start_time': current_time,
                    'end_time': next_time,
                    'duration_ms': (next_time - current_time) * 1000,
                    'severity': 'CRITICAL' if (next_time - current_time) > 0.1 else 'HIGH',
                    'issue_type': 'RU_SILENT_PERIOD'
                })
        
        return silent_periods
    
    def create_failure_analysis_prompt(self, analysis_data, filename):
        """Create AI prompt focused on fronthaul communication failures"""
        
        def serialize_for_json(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            elif hasattr(obj, '__dict__'):
                return {k: serialize_for_json(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, list):
                return [serialize_for_json(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: serialize_for_json(v) for k, v in obj.items()}
            return obj
        
        prompt = f"""<s>[INST] You are analyzing CRITICAL 5G fronthaul issues between DU (00:11:22:33:44:67) and RU (6c:ad:ad:00:03:2a).

5G FRONTHAUL ANALYSIS RESULTS:
File: {filename}
Total DU→RU messages: {analysis_data['total_du_messages']}
Average round-trip latency: {analysis_data['avg_latency_us']:.1f}μs
Ultra-low latency violations (>100μs): {analysis_data['violations_over_100us']}
Communication failure rate: {analysis_data['failure_rate']:.1f}%
Jitter issues detected: {len(analysis_data['jitter_issues'])}
Packet loss events: {len(analysis_data['packet_loss_events'])}

ULTRA-LOW LATENCY VIOLATIONS (>100μs):
{json.dumps(serialize_for_json(analysis_data['latency_violations']), indent=2)}

COMMUNICATION FAILURES (NO RU RESPONSE):
{json.dumps(serialize_for_json(analysis_data['communication_failures']), indent=2)}

JITTER ANALYSIS:
{json.dumps(serialize_for_json(analysis_data['jitter_issues']), indent=2)}

PACKET LOSS EVENTS:
{json.dumps(serialize_for_json(analysis_data['packet_loss_events']), indent=2)}

STREAM YOUR ANALYSIS focusing on these 5G fronthaul requirements:

1. ULTRA-LOW LATENCY VIOLATIONS (≤100μs requirement):
   - {analysis_data['violations_over_100us']} messages exceeded 100μs round-trip latency
   - Average latency is {analysis_data['avg_latency_us']:.1f}μs (should be ≤100μs)
   - Impact on 5G real-time functions and advanced RAN operations
   - Root causes: processing delays, network congestion, hardware bottlenecks

2. SYNCHRONIZATION AND TIMING ISSUES:
   - Clock synchronization problems affecting network operation
   - Timing impairments causing performance degradation
   - Synchronization loss between DU and RU
   - Impact on 5G protocol timing requirements

3. JITTER AND PACKET LOSS ANALYSIS:
   - Jitter affecting fronthaul link reliability
   - Packet loss impacting 5G protocol performance
   - Communication reliability degradation
   - Buffer overflow/underflow conditions

4. COMMUNICATION BREAKDOWN DETECTION:
   - {analysis_data['failure_rate']:.1f}% of DU messages got no RU response
   - Silent periods where RU stops responding
   - Physical layer problems preventing communication
   - Protocol stack failures

For each critical finding, output:
🚨 FRONTHAUL ISSUE: [TYPE] - [SEVERITY]
📊 MEASUREMENT: [Specific timing/performance data]
🔧 REMEDIATION: [Specific 5G fronthaul troubleshooting action]

Focus on fronthaul-specific issues: ultra-low latency, synchronization, jitter, and packet loss.

Start your fronthaul analysis now: [/INST]</s>"""
        
        return prompt
    
    def run_failure_analysis(self, pcap_file):
        """Complete communication failure analysis with AI recommendations"""
        analysis_data = self.analyze_pcap_for_failures(pcap_file)
        
        if not analysis_data:
            print("❌ Analysis failed - no data to process")
            return
        
        if analysis_data['failure_rate'] > 10:  # More than 10% failure rate
            print(f"\n🚨 CRITICAL COMMUNICATION FAILURE DETECTED: {analysis_data['failure_rate']:.1f}% failure rate")
            
            prompt = self.create_failure_analysis_prompt(analysis_data, pcap_file)
            
            print("\n🤖 STREAMING AI ANALYSIS FOR COMMUNICATION FAILURES:")
            print("=" * 70)
            
            try:
                cmd = [
                    "/tmp/llama.cpp/build/bin/llama-cli",
                    "--model", self.model_path,
                    "--prompt", prompt,
                    "--n-predict", "1000",
                    "--temp", "0.1",
                    "--ctx-size", "4096",
                    "--stream",
                    "--no-display-prompt"
                ]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
                
                for line in iter(process.stdout.readline, ''):
                    if line.strip():
                        print(f"📡 {line.strip()}")
                
                process.wait()
                
            except Exception as e:
                print(f"⚠️ AI analysis error: {e}")
                print("Manual analysis suggests checking RU connectivity and power")
        
        else:
            print(f"✅ Communication appears healthy: {analysis_data['failure_rate']:.1f}% failure rate is acceptable")

def main():
    if len(sys.argv) != 2:
        print("Usage: python detect_communication_failures.py <pcap_file>")
        print("Example: python detect_communication_failures.py fronthaul_dump.pcap")
        return
    
    pcap_file = sys.argv[1]
    detector = CommunicationFailureDetector()
    detector.run_failure_analysis(pcap_file)

if __name__ == "__main__":
    main()