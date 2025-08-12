-- Raw SQL to insert dummy data into ClickHouse tables
-- Execute this after running raw_sql_create_tables.sql

USE l1_anomaly_detection;

-- Insert anomalies data
INSERT INTO anomalies VALUES
('anom_001', '2025-08-12 14:23:15', 'fronthaul', 'DU-RU link timeout on interface eth0', 'critical', 'log_20250812_142315.pcap', 1523, 'AA:BB:CC:DD:EE:01', 'UE-345678', '{"cell_id": "Cell-45", "technology": "5G-NR"}', 'open', 'fronthaul_du_ru_communication_failure', 0.95, 'isolation_forest', '{"cell_id": "Cell-45", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 150}'),
('anom_002', '2025-08-12 14:45:32', 'ue_event', 'UE attach failure - authentication error', 'high', 'log_20250812_144532.pcap', 2847, 'AA:BB:CC:DD:EE:02', 'UE-567890', '{"ue_id": "UE-567890", "imsi": "123456789012345"}', 'open', 'ue_attach_failure', 0.88, 'dbscan', '{"cell_id": "Cell-23", "sector_id": 1, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 1}'),
('anom_003', '2025-08-12 15:12:45', 'mac_conflict', 'Duplicate MAC address detected in network', 'medium', 'log_20250812_151245.pcap', 3456, 'AA:BB:CC:DD:EE:03', 'UE-234567', '{"mac_address": "AA:BB:CC:DD:EE:03", "count": 3}', 'investigating', 'mac_address_conflict', 0.92, 'one_class_svm', '{"cell_id": "Cell-12", "sector_id": 3, "frequency_band": "3500MHz", "technology": "5G-NR", "affected_users": 25}'),
('anom_004', '2025-08-12 15:34:18', 'protocol_violation', 'Invalid RRC message sequence detected', 'high', 'log_20250812_153418.pcap', 4721, 'AA:BB:CC:DD:EE:04', 'UE-789012', '{"message_type": "RRC_Connection_Request", "expected": "RRC_Setup"}', 'open', 'protocol_violation_rrc', 0.85, 'lof', '{"cell_id": "Cell-67", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 8}'),
('anom_005', '2025-08-12 16:01:22', 'signal_quality', 'Poor RSRP levels causing connection drops', 'medium', 'log_20250812_160122.pcap', 5638, 'AA:BB:CC:DD:EE:05', 'UE-456789', '{"rsrp": -115, "rsrq": -18, "sinr": -2}', 'resolved', 'signal_quality_degradation', 0.79, 'isolation_forest', '{"cell_id": "Cell-89", "sector_id": 1, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 45}'),
('anom_006', '2025-08-12 16:28:55', 'fronthaul', 'High packet loss on DU-RU interface', 'critical', 'log_20250812_162855.pcap', 6789, 'AA:BB:CC:DD:EE:06', 'UE-123456', '{"packet_loss_percentage": 85, "interface": "eth1"}', 'open', 'fronthaul_packet_loss', 0.98, 'dbscan', '{"cell_id": "Cell-34", "sector_id": 3, "frequency_band": "3500MHz", "technology": "5G-NR", "affected_users": 200}'),
('anom_007', '2025-08-12 16:45:12', 'ue_event', 'UE handover failure - target cell unavailable', 'high', 'log_20250812_164512.pcap', 7234, 'AA:BB:CC:DD:EE:07', 'UE-654321', '{"source_cell": "Cell-12", "target_cell": "Cell-45"}', 'investigating', 'ue_handover_failure', 0.91, 'one_class_svm', '{"cell_id": "Cell-12", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 12}'),
('anom_008', '2025-08-12 17:03:45', 'mac_conflict', 'MAC address spoofing attempt detected', 'critical', 'log_20250812_170345.pcap', 8567, 'AA:BB:CC:DD:EE:08', 'UE-987654', '{"suspicious_mac": "AA:BB:CC:DD:EE:08", "legitimate_ue": "UE-111222"}', 'open', 'mac_spoofing', 0.94, 'lof', '{"cell_id": "Cell-56", "sector_id": 1, "frequency_band": "1800MHz", "technology": "5G-NR", "affected_users": 75}'),
('anom_009', '2025-08-12 17:20:33', 'protocol_violation', 'Malformed PDCP header in data packet', 'medium', 'log_20250812_172033.pcap', 9123, 'AA:BB:CC:DD:EE:09', 'UE-321987', '{"header_field": "PDCP_SN", "expected_length": 12, "actual_length": 8}', 'resolved', 'protocol_violation_pdcp', 0.83, 'isolation_forest', '{"cell_id": "Cell-78", "sector_id": 3, "frequency_band": "3500MHz", "technology": "5G-NR", "affected_users": 5}'),
('anom_010', '2025-08-12 17:42:18', 'signal_quality', 'Excessive interference on uplink channel', 'high', 'log_20250812_174218.pcap', 9876, 'AA:BB:CC:DD:EE:10', 'UE-147258', '{"interference_level": -85, "channel": "PUSCH", "affected_prbs": 25}', 'open', 'uplink_interference', 0.87, 'dbscan', '{"cell_id": "Cell-90", "sector_id": 2, "frequency_band": "2600MHz", "technology": "5G-NR", "affected_users": 30}');

-- Insert analysis sessions data
INSERT INTO analysis_sessions VALUES
('session_1001', '2025-08-12 14:00:00', 'analysis_20250812_140000.txt', 'pcap', 45623, 2845, 15, 3, 8, 4, 125.7, '{"analysis_type": "pcap", "algorithms_used": ["isolation_forest", "dbscan"], "total_features": 42}'),
('session_1002', '2025-08-12 15:30:00', 'analysis_20250812_153000.txt', 'text', 32156, 1967, 8, 1, 4, 3, 89.3, '{"analysis_type": "text", "algorithms_used": ["one_class_svm", "lof"], "total_features": 28}'),
('session_1003', '2025-08-12 16:45:00', 'analysis_20250812_164500.txt', 'hybrid', 58934, 3421, 22, 5, 12, 5, 178.9, '{"analysis_type": "hybrid", "algorithms_used": ["isolation_forest", "dbscan", "lof"], "total_features": 65}'),
('session_1004', '2025-08-12 17:15:00', 'analysis_20250812_171500.txt', 'pcap', 27845, 1532, 6, 1, 3, 2, 67.2, '{"analysis_type": "pcap", "algorithms_used": ["dbscan", "one_class_svm"], "total_features": 35}'),
('session_1005', '2025-08-12 17:45:00', 'analysis_20250812_174500.txt', 'text', 41267, 2789, 12, 2, 7, 3, 143.5, '{"analysis_type": "text", "algorithms_used": ["isolation_forest", "lof"], "total_features": 48}');

-- Insert metrics data
INSERT INTO metrics VALUES
('metric_001', '2025-08-12 14:00:00', 'performance', 'packet_processing_rate', 15423.5, 'packets/sec', '{"node": "DU-01", "interface": "eth0"}'),
('metric_002', '2025-08-12 14:15:00', 'quality', 'average_rsrp', -95.2, 'dBm', '{"cell": "Cell-45", "sector": 2}'),
('metric_003', '2025-08-12 14:30:00', 'anomaly_detection', 'detection_accuracy', 0.94, 'percentage', '{"algorithm": "isolation_forest", "model_version": "v2.1"}'),
('metric_004', '2025-08-12 14:45:00', 'network', 'active_ue_count', 1247, 'count', '{"cell": "Cell-23", "technology": "5G-NR"}'),
('metric_005', '2025-08-12 15:00:00', 'performance', 'cpu_utilization', 78.3, 'percentage', '{"node": "RU-03", "core_count": 8}');

-- Insert processed files data
INSERT INTO processed_files VALUES
('file_001', '2025-08-12 14:23:15', 'log_20250812_142315.pcap', '/data/pcap/log_20250812_142315.pcap', 52428800, 'pcap', 'completed', 125.7, 15, ''),
('file_002', '2025-08-12 15:12:45', 'ue_events_20250812.txt', '/data/logs/ue_events_20250812.txt', 8394752, 'text', 'completed', 89.3, 8, ''),
('file_003', '2025-08-12 16:45:12', 'fronthaul_analysis.pcap', '/data/pcap/fronthaul_analysis.pcap', 104857600, 'pcap', 'processing', 0, 0, ''),
('file_004', '2025-08-12 17:20:33', 'network_dump_17h.pcap', '/data/pcap/network_dump_17h.pcap', 209715200, 'pcap', 'failed', 0, 0, 'ClickHouse connection timeout'),
('file_005', '2025-08-12 17:42:18', 'mobility_events.txt', '/data/logs/mobility_events.txt', 4194304, 'text', 'completed', 67.2, 6, '');

-- Verify data was inserted
SELECT 'Anomalies count:' as table_name, count(*) as record_count FROM anomalies
UNION ALL
SELECT 'Sessions count:', count(*) FROM analysis_sessions
UNION ALL  
SELECT 'Metrics count:', count(*) FROM metrics
UNION ALL
SELECT 'Files count:', count(*) FROM processed_files;

-- Show sample data
SELECT 'Sample anomalies:' as info;
SELECT timestamp, type, severity, description FROM anomalies ORDER BY timestamp DESC LIMIT 3;