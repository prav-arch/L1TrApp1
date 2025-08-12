#!/usr/bin/env python3
"""
Debug script to check table schemas and identify column mismatches
"""

import clickhouse_connect

def check_table_schemas():
    """Check all table schemas and identify issues"""
    try:
        client = clickhouse_connect.get_client(
            host='localhost',
            port=8123,
            username='default',
            password='',
            database='l1_anomaly_detection'
        )
        
        print("=== ClickHouse Table Schema Analysis ===\n")
        
        # Get all tables
        tables_result = client.query('SHOW TABLES FROM l1_anomaly_detection')
        tables = [row[0] for row in tables_result.result_rows]
        print(f"Available tables: {tables}\n")
        
        # Check each table schema
        for table in tables:
            print(f"=== {table.upper()} TABLE ===")
            desc = client.query(f'DESCRIBE l1_anomaly_detection.{table}')
            for row in desc.result_rows:
                print(f"  {row[0]:<25} {row[1]}")
            print()
            
        # Check what the frontend expects
        print("=== FRONTEND EXPECTED SCHEMA ===")
        print("The web application expects 'anomalies' table with these columns:")
        expected_anomalies = [
            "id", "timestamp", "type", "description", "severity", 
            "source_file", "packet_number", "mac_address", "ue_id", 
            "details", "status"
        ]
        for col in expected_anomalies:
            print(f"  {col}")
            
        return True
        
    except Exception as e:
        print(f"Error connecting to ClickHouse: {e}")
        return False

if __name__ == "__main__":
    check_table_schemas()