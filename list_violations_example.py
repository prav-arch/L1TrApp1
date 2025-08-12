#!/usr/bin/env python3
"""
Example output showing timing violations detected by stream_pcap_analysis.py
This simulates what you would see when running the actual analysis
"""

def show_typical_violations():
    """Show typical violations found in 5G fronthaul analysis"""
    
    print("🚨 L1 TROUBLESHOOTING TOOL - TIMING VIOLATIONS DETECTED")
    print("=" * 70)
    
    # Simulate typical timing violations found in real analysis
    violations = [
        {'packet_id': 1247, 'latency_us': 187.4, 'severity': 'HIGH', 'timestamp': '14:23:15.123456'},
        {'packet_id': 1289, 'latency_us': 1234.7, 'severity': 'CRITICAL', 'timestamp': '14:23:15.156789'},
        {'packet_id': 1301, 'latency_us': 298.2, 'severity': 'HIGH', 'timestamp': '14:23:15.198012'},
        {'packet_id': 1356, 'latency_us': 2156.9, 'severity': 'CRITICAL', 'timestamp': '14:23:15.234567'},
        {'packet_id': 1398, 'latency_us': 165.3, 'severity': 'HIGH', 'timestamp': '14:23:15.267890'},
        {'packet_id': 1445, 'latency_us': 3421.8, 'severity': 'CRITICAL', 'timestamp': '14:23:15.301234'},
        {'packet_id': 1467, 'latency_us': 223.1, 'severity': 'HIGH', 'timestamp': '14:23:15.334567'},
        {'packet_id': 1501, 'latency_us': 134.7, 'severity': 'HIGH', 'timestamp': '14:23:15.367890'},
        {'packet_id': 1533, 'latency_us': 1876.4, 'severity': 'CRITICAL', 'timestamp': '14:23:15.401234'},
        {'packet_id': 1578, 'latency_us': 276.9, 'severity': 'HIGH', 'timestamp': '14:23:15.434567'},
        {'packet_id': 1612, 'latency_us': 4123.5, 'severity': 'CRITICAL', 'timestamp': '14:23:15.467890'},
        {'packet_id': 1645, 'latency_us': 198.7, 'severity': 'HIGH', 'timestamp': '14:23:15.501234'},
        {'packet_id': 1689, 'latency_us': 156.2, 'severity': 'HIGH', 'timestamp': '14:23:15.534567'},
        {'packet_id': 1723, 'latency_us': 2987.1, 'severity': 'CRITICAL', 'timestamp': '14:23:15.567890'},
        {'packet_id': 1756, 'latency_us': 245.8, 'severity': 'HIGH', 'timestamp': '14:23:15.601234'}
    ]
    
    high_count = sum(1 for v in violations if v['severity'] == 'HIGH')
    critical_count = sum(1 for v in violations if v['severity'] == 'CRITICAL')
    
    print(f"SUMMARY:")
    print(f"Total Violations: {len(violations)}")
    print(f"HIGH Severity: {high_count} (100μs - 1000μs)")
    print(f"CRITICAL Severity: {critical_count} (>1000μs)")
    print()
    
    print("DETAILED VIOLATION LIST:")
    print("-" * 70)
    print(f"{'Packet':<8} {'Latency':<12} {'Severity':<10} {'Timestamp':<18}")
    print("-" * 70)
    
    for v in violations:
        print(f"{v['packet_id']:<8} {v['latency_us']:.1f}μs{'':<6} {v['severity']:<10} {v['timestamp']:<18}")
    
    print("-" * 70)
    print()
    
    print("FRONTHAUL IMPACT ANALYSIS:")
    print("• HIGH violations cause timing jitter affecting synchronization")
    print("• CRITICAL violations break 5G fronthaul timing requirements")
    print("• Multiple violations indicate network congestion or hardware issues")
    print("• DU-RU communication may experience dropped packets")
    print()
    
    print("RECOMMENDED ACTIONS:")
    print("1. Check network switch buffer settings")
    print("2. Verify fronthaul link quality and cable integrity")
    print("3. Review DU and RU synchronization configuration")
    print("4. Monitor for network congestion during peak hours")
    print("5. Consider hardware upgrade if violations persist")

if __name__ == "__main__":
    show_typical_violations()