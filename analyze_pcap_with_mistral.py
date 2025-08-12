#!/usr/bin/env python3

import sys
import json
import subprocess
from scapy.all import rdpcap, Ether, IP, TCP, UDP
import argparse
from datetime import datetime

class PCAPMistralAnalyzer:
    def __init__(self, model_path="/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"):
        self.model_path = model_path
        
    def extract_pcap_summary(self, pcap_file):
        """Extract key information from PCAP file"""
        packets = rdpcap(pcap_file)
        
        summary = {
            "total_packets": len(packets),
            "protocols": {},
            "mac_addresses": set(),
            "ip_addresses": set(),
            "port_pairs": {},
            "timing_issues": [],
            "packet_sizes": []
        }
        
        prev_time = None
        
        for packet in packets[:500]:  # Analyze first 500 packets
            # Protocol analysis
            if Ether in packet:
                summary["mac_addresses"].add(packet[Ether].src)
                summary["mac_addresses"].add(packet[Ether].dst)
                
            if IP in packet:
                summary["ip_addresses"].add(packet[IP].src)
                summary["ip_addresses"].add(packet[IP].dst)
                
                if TCP in packet:
                    summary["protocols"]["TCP"] = summary["protocols"].get("TCP", 0) + 1
                    port_pair = f"{packet[TCP].sport}:{packet[TCP].dport}"
                    summary["port_pairs"][port_pair] = summary["port_pairs"].get(port_pair, 0) + 1
                elif UDP in packet:
                    summary["protocols"]["UDP"] = summary["protocols"].get("UDP", 0) + 1
                    port_pair = f"{packet[UDP].sport}:{packet[UDP].dport}"
                    summary["port_pairs"][port_pair] = summary["port_pairs"].get(port_pair, 0) + 1
                else:
                    summary["protocols"]["Other IP"] = summary["protocols"].get("Other IP", 0) + 1
            else:
                summary["protocols"]["Non-IP"] = summary["protocols"].get("Non-IP", 0) + 1
            
            # Timing analysis for fronthaul issues
            if hasattr(packet, 'time') and prev_time:
                gap = packet.time - prev_time
                if gap > 0.001:  # > 1ms gap (potential fronthaul issue)
                    summary["timing_issues"].append(f"Gap: {gap:.4f}s")
            
            prev_time = packet.time if hasattr(packet, 'time') else None
            summary["packet_sizes"].append(len(packet))
        
        # Convert sets to lists for JSON
        summary["mac_addresses"] = list(summary["mac_addresses"])
        summary["ip_addresses"] = list(summary["ip_addresses"])
        
        return summary
    
    def create_analysis_prompt(self, pcap_summary, pcap_file):
        """Create prompt for Mistral model"""
        
        prompt = f"""<s>[INST] You are a network security expert analyzing 5G L1 network traffic for anomalies and security threats.

PCAP File: {pcap_file}
Analysis Data:
- Total Packets: {pcap_summary['total_packets']}
- Protocols: {json.dumps(pcap_summary['protocols'])}
- Unique MAC Addresses: {len(pcap_summary['mac_addresses'])}
- Unique IP Addresses: {len(pcap_summary['ip_addresses'])}
- Top Port Communications: {dict(list(pcap_summary['port_pairs'].items())[:10])}
- Timing Issues Found: {len(pcap_summary['timing_issues'])}
- Average Packet Size: {sum(pcap_summary['packet_sizes'])/len(pcap_summary['packet_sizes']) if pcap_summary['packet_sizes'] else 0:.2f} bytes

Sample Timing Issues: {pcap_summary['timing_issues'][:5]}

ANALYSIS REQUIRED:
1. Identify potential security threats or network anomalies
2. Check for suspicious MAC address patterns (broadcast storms, unusual OUIs)
3. Analyze timing patterns for 5G fronthaul DU-RU communication issues
4. Detect protocol violations or unusual traffic patterns
5. Flag potential network attacks or misconfigurations

Provide your analysis focusing on:
- L1 5G network specific issues
- Fronthaul communication problems
- Security threats
- Network performance issues

Response format: List each anomaly with type, severity (Low/Medium/High), and description. [/INST]</s>"""
        
        return prompt
    
    def query_mistral(self, prompt):
        """Query Mistral model using llama.cpp"""
        try:
            # Command for llama.cpp using correct path
            cmd = [
                "/tmp/llama.cpp/build/bin/llama-cli",  # Using correct llama.cpp path
                "--model", self.model_path,
                "--prompt", prompt,
                "--n-predict", "1024",
                "--temp", "0.3",
                "--ctx-size", "4096",
                "--no-display-prompt"
            ]
            
            print("Querying Mistral model...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return f"Error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return "Error: Model query timeout"
        except FileNotFoundError:
            return "Error: llama.cpp not found. Please install and add to PATH"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def analyze_pcap(self, pcap_file):
        """Main analysis function"""
        print(f"Analyzing PCAP file: {pcap_file}")
        
        # Extract PCAP data
        pcap_summary = self.extract_pcap_summary(pcap_file)
        
        # Create prompt
        prompt = self.create_analysis_prompt(pcap_summary, pcap_file)
        
        # Query Mistral
        analysis = self.query_mistral(prompt)
        
        # Display results
        print("\n" + "="*60)
        print("PCAP ANALYSIS SUMMARY")
        print("="*60)
        print(f"File: {pcap_file}")
        print(f"Packets: {pcap_summary['total_packets']}")
        print(f"Protocols: {pcap_summary['protocols']}")
        print(f"MAC Addresses: {len(pcap_summary['mac_addresses'])}")
        print(f"IP Addresses: {len(pcap_summary['ip_addresses'])}")
        print(f"Timing Issues: {len(pcap_summary['timing_issues'])}")
        
        print("\n" + "="*60)
        print("MISTRAL LLM ANALYSIS")
        print("="*60)
        print(analysis)
        
        return analysis

def main():
    parser = argparse.ArgumentParser(description='Analyze PCAP files for anomalies using Mistral LLM')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--model', default='/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf',
                        help='Path to Mistral GGUF model')
    
    args = parser.parse_args()
    
    analyzer = PCAPMistralAnalyzer(model_path=args.model)
    result = analyzer.analyze_pcap(args.pcap_file)

if __name__ == "__main__":
    main()