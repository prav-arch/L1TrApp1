-- Insert data into ClickHouse 18.16.1 anomalies table
-- Execute after creating the table with raw_sql_create_tables.sql

USE l1_anomaly_detection;

-- Insert anomalies one by one
INSERT INTO anomalies VALUES ('anom_001', '2025-08-12 14:23:15', 'fronthaul', 'DU-RU link timeout on interface eth0', 'critical', 'log_20250812_142315.pcap', 1523, 'AA:BB:CC:DD:EE:01', 'UE-345678', 'Cell-45 timeout issue', 'open');

INSERT INTO anomalies VALUES ('anom_002', '2025-08-12 14:45:32', 'ue_event', 'UE attach failure - authentication error', 'high', 'log_20250812_144532.pcap', 2847, 'AA:BB:CC:DD:EE:02', 'UE-567890', 'Authentication failed', 'open');

INSERT INTO anomalies VALUES ('anom_003', '2025-08-12 15:12:45', 'mac_conflict', 'Duplicate MAC address detected in network', 'medium', 'log_20250812_151245.pcap', 3456, 'AA:BB:CC:DD:EE:03', 'UE-234567', 'MAC address conflict', 'investigating');

INSERT INTO anomalies VALUES ('anom_004', '2025-08-12 15:34:18', 'protocol_violation', 'Invalid RRC message sequence detected', 'high', 'log_20250812_153418.pcap', 4721, 'AA:BB:CC:DD:EE:04', 'UE-789012', 'RRC protocol error', 'open');

INSERT INTO anomalies VALUES ('anom_005', '2025-08-12 16:01:22', 'signal_quality', 'Poor RSRP levels causing connection drops', 'medium', 'log_20250812_160122.pcap', 5638, 'AA:BB:CC:DD:EE:05', 'UE-456789', 'RSRP -115 dBm detected', 'resolved');

INSERT INTO anomalies VALUES ('anom_006', '2025-08-12 16:28:55', 'fronthaul', 'High packet loss on DU-RU interface', 'critical', 'log_20250812_162855.pcap', 6789, 'AA:BB:CC:DD:EE:06', 'UE-123456', 'Packet loss 85 percent', 'open');

INSERT INTO anomalies VALUES ('anom_007', '2025-08-12 16:45:12', 'ue_event', 'UE handover failure - target cell unavailable', 'high', 'log_20250812_164512.pcap', 7234, 'AA:BB:CC:DD:EE:07', 'UE-654321', 'Handover to Cell-45 failed', 'investigating');

INSERT INTO anomalies VALUES ('anom_008', '2025-08-12 17:03:45', 'mac_conflict', 'MAC address spoofing attempt detected', 'critical', 'log_20250812_170345.pcap', 8567, 'AA:BB:CC:DD:EE:08', 'UE-987654', 'Spoofing detected', 'open');

INSERT INTO anomalies VALUES ('anom_009', '2025-08-12 17:20:33', 'protocol_violation', 'Malformed PDCP header in data packet', 'medium', 'log_20250812_172033.pcap', 9123, 'AA:BB:CC:DD:EE:09', 'UE-321987', 'PDCP header malformed', 'resolved');

INSERT INTO anomalies VALUES ('anom_010', '2025-08-12 17:42:18', 'signal_quality', 'Excessive interference on uplink channel', 'high', 'log_20250812_174218.pcap', 9876, 'AA:BB:CC:DD:EE:10', 'UE-147258', 'Uplink interference detected', 'open');

-- Verify insertion
SELECT count(*) as total_rows FROM anomalies;

-- Show sample data
SELECT * FROM anomalies LIMIT 3;