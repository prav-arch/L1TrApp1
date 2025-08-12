# ClickHouse Setup for L1 Troubleshooting System

## Overview
This guide helps you set up ClickHouse database for the L1 Troubleshooting system to store and display anomaly records with packet numbers and recommendations.

## Prerequisites
- ClickHouse server installed and running on localhost:8123
- Python 3 with clickhouse-connect package installed

## Setup Instructions

### 1. Start ClickHouse Server

#### Option A: Using systemd (Linux)
```bash
sudo systemctl start clickhouse-server
sudo systemctl status clickhouse-server
```

#### Option B: Using Docker
```bash
docker run -d --name clickhouse-server \
  -p 8123:8123 -p 9000:9000 \
  yandex/clickhouse-server
```

#### Option C: Direct Installation
Download and install ClickHouse from: https://clickhouse.com/docs/en/install

### 2. Verify ClickHouse is Running
```bash
curl http://localhost:8123/ping
# Should return "Ok."
```

### 3. Run the Setup Script
```bash
# Make the script executable
chmod +x setup_clickhouse_data.sh

# Run the setup
./setup_clickhouse_data.sh
```

**OR** run the Python script directly:
```bash
python3 clickhouse_local_setup.py
```

## What the Setup Creates

### Database: `l1_anomaly_detection`

### Tables Created:
1. **anomalies** - Stores detected network anomalies
   - Contains packet numbers, severity levels, descriptions
   - Includes DU/RU MAC addresses and UE IDs
   - MergeTree engine optimized for time-series data

2. **processed_files** - Tracks uploaded and processed files
3. **sessions** - Records analysis sessions 
4. **metrics** - Dashboard performance metrics

### Sample Data Inserted:
- **10 comprehensive anomaly records** covering:
  - DU-RU Communication issues (packet #150, #275, #89)
  - UE Event Pattern failures (packet #45, #127, #203)  
  - Protocol violations (packet #412, #568)
  - Resolved historical issues (packet #95, #234)

- **5 processed file records**
- **4 analysis session records**

## Verification

After setup, the system will display:
- Total anomalies count
- Breakdown by severity (critical, high, medium, low)
- Breakdown by type (DU-RU Communication, UE Event Pattern, etc.)
- Sample recent anomalies with packet numbers

## Frontend Features

Once connected, your L1 Troubleshooting frontend will show:
- ✅ Anomalies table with "Packet #XXX" displayed for each record
- ✅ "Get Recommendations" button for each anomaly row
- ✅ Real-time dashboard metrics from ClickHouse
- ✅ Filtering by type and severity
- ✅ Historical trend analysis

## Troubleshooting

### Connection Issues
```bash
# Check if ClickHouse is listening
netstat -tlnp | grep 8123

# Check ClickHouse logs
sudo journalctl -u clickhouse-server -f
```

### Database Issues
```bash
# Connect to ClickHouse CLI
clickhouse-client

# List databases
SHOW DATABASES;

# Use the database
USE l1_anomaly_detection;

# Check tables
SHOW TABLES;

# Count anomalies
SELECT count() FROM anomalies;
```

## Environment Variables

The system uses these ClickHouse connection settings:
- `CLICKHOUSE_HOST`: localhost (default)
- `CLICKHOUSE_PORT`: 8123 (default)
- `CLICKHOUSE_USER`: default (default)
- `CLICKHOUSE_PASSWORD`: (empty by default)
- `CLICKHOUSE_DATABASE`: l1_anomaly_detection

## Next Steps

1. Start your L1 Troubleshooting application
2. Navigate to the Anomalies page
3. Verify you see 10 test anomalies with packet numbers
4. Test the "Get Recommendations" feature
5. Check the Dashboard for updated metrics

Your system is now ready for production use with ClickHouse backend!