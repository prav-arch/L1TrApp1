# ClickHouse Database Schema for Network Anomaly Detection

## Database Configuration
- **Host**: localhost
- **Port**: 9000  
- **Database**: l1_tool_db
- **Username**: default
- **Password**: (empty)

## Complete Table Schemas

### 1. **anomalies** Table
Stores all detected network anomalies from PCAP and log file analysis.

```sql
CREATE TABLE IF NOT EXISTS anomalies (
    id String,                    -- Unique UUID identifier
    timestamp DateTime,           -- Detection timestamp
    type String,                 -- Anomaly type: 'fronthaul', 'ue_event', 'mac_address', 'protocol'
    description String,           -- Detailed description of the anomaly
    severity String,             -- Severity level: 'low', 'medium', 'high', 'critical'
    source_file String,          -- Source file that generated this anomaly
    mac_address Nullable(String), -- MAC address (for fronthaul/MAC anomalies)
    ue_id Nullable(String),      -- UE identifier (for UE event anomalies)
    details Nullable(String),    -- Additional JSON details about the anomaly
    status String DEFAULT 'open' -- Status: 'open', 'investigating', 'resolved'
) ENGINE = MergeTree()
ORDER BY timestamp;
```

**Usage Examples:**
- Fronthaul anomalies: High latency between DU-RU with MAC addresses
- UE events: Abnormal attach/detach patterns with UE IDs
- MAC address anomalies: Suspicious MAC patterns or spoofing
- Protocol violations: Invalid packet structures or sequences

### 2. **processed_files** Table
Tracks all uploaded files and their processing status.

```sql
CREATE TABLE IF NOT EXISTS processed_files (
    id String,                   -- Unique UUID identifier
    filename String,             -- Original filename
    file_type String,           -- File type: 'pcap', 'pcapng', 'log', 'txt'
    file_size UInt64,           -- File size in bytes
    upload_date DateTime,        -- Upload timestamp
    processing_status String DEFAULT 'pending', -- Status: 'pending', 'processing', 'completed', 'failed'
    anomalies_found UInt32 DEFAULT 0,          -- Number of anomalies detected
    processing_time Nullable(UInt32),          -- Processing time in seconds
    error_message Nullable(String)             -- Error message if processing failed
) ENGINE = MergeTree()
ORDER BY upload_date;
```

### 3. **sessions** Table
Records analysis sessions for tracking and auditing.

```sql
CREATE TABLE IF NOT EXISTS sessions (
    id String,                   -- Unique UUID identifier
    session_id String,           -- Session identifier for grouping
    start_time DateTime,         -- Session start timestamp
    end_time Nullable(DateTime), -- Session end timestamp (null if ongoing)
    packets_analyzed UInt32 DEFAULT 0,     -- Total packets analyzed
    anomalies_detected UInt32 DEFAULT 0,   -- Anomalies found in this session
    source_file String          -- Source file for this session
) ENGINE = MergeTree()
ORDER BY start_time;
```

### 4. **metrics** Table
Stores system performance and detection metrics.

```sql
CREATE TABLE IF NOT EXISTS metrics (
    id String,                   -- Unique UUID identifier
    metric_name String,          -- Metric name (e.g., 'processing_speed', 'detection_rate')
    metric_value Float64,        -- Metric value
    timestamp DateTime,          -- Metric collection timestamp
    category String             -- Category: 'performance', 'detection', 'system'
) ENGINE = MergeTree()
ORDER BY timestamp;
```

## Data Types and Field Descriptions

### Anomaly Types
1. **fronthaul**: DU-RU communication issues
   - Uses `mac_address` field
   - Typically high severity
   - Examples: latency, packet loss, timing issues

2. **ue_event**: User Equipment events
   - Uses `ue_id` field
   - Attach/detach patterns
   - Examples: abnormal sequences, failed handovers

3. **mac_address**: MAC-level anomalies
   - Uses `mac_address` field
   - Examples: spoofing, invalid addresses, conflicts

4. **protocol**: Protocol violations
   - May use both `mac_address` and `ue_id`
   - Examples: malformed packets, invalid sequences

### Severity Levels
- **low**: Minor issues, informational
- **medium**: Notable issues requiring investigation
- **high**: Serious issues affecting performance
- **critical**: Severe issues requiring immediate action

### Processing Statuses
- **pending**: File uploaded, waiting for processing
- **processing**: Currently being analyzed
- **completed**: Processing finished successfully
- **failed**: Processing failed with error

## API Endpoints Using ClickHouse

### Dashboard Metrics
- `GET /api/dashboard/metrics` - Real-time metrics from database
- `GET /api/dashboard/trends` - Anomaly trends over time
- `GET /api/dashboard/breakdown` - Anomaly type distribution

### Anomalies Management
- `GET /api/anomalies` - List anomalies with filtering
- `GET /api/anomalies/:id` - Get specific anomaly
- `POST /api/anomalies` - Create new anomaly
- `PATCH /api/anomalies/:id` - Update anomaly status

### File Processing
- `GET /api/files` - List processed files
- `POST /api/files/upload` - Upload new file for processing
- `GET /api/files/:id/status` - Check processing status

## Integration with Python Services

### PCAP Processor
```python
# Creates anomalies in database
def detect_fronthaul_anomalies(pcap_file):
    # Analysis logic...
    anomaly = {
        'type': 'fronthaul',
        'description': f'High latency detected: {latency}ms',
        'severity': 'high',
        'source_file': pcap_file,
        'mac_address': mac_addr,
        'status': 'open'
    }
    clickhouse_client.insert_anomaly(anomaly)
```

### UE Event Analyzer
```python
# Creates UE event anomalies
def analyze_ue_events(log_file):
    # Analysis logic...
    anomaly = {
        'type': 'ue_event',
        'description': f'Abnormal detach sequence for UE {ue_id}',
        'severity': 'medium',
        'source_file': log_file,
        'ue_id': ue_id,
        'status': 'open'
    }
    clickhouse_client.insert_anomaly(anomaly)
```

## Query Examples

### Get Recent High-Severity Anomalies
```sql
SELECT * FROM anomalies 
WHERE severity = 'high' 
AND timestamp >= now() - INTERVAL 24 HOUR
ORDER BY timestamp DESC;
```

### Anomaly Count by Type
```sql
SELECT type, count() as count
FROM anomalies 
GROUP BY type 
ORDER BY count DESC;
```

### Processing Performance
```sql
SELECT 
    avg(processing_time) as avg_time,
    count() as total_files
FROM processed_files 
WHERE processing_status = 'completed';
```

## Environment Variables
Set these environment variables for ClickHouse connection:

```bash
export CLICKHOUSE_HOST=localhost
export CLICKHOUSE_PORT=9000
export CLICKHOUSE_DATABASE=l1_tool_db
export CLICKHOUSE_USERNAME=default
export CLICKHOUSE_PASSWORD=""
```

## Installation Requirements

### ClickHouse Server
```bash
# Install ClickHouse
curl https://clickhouse.com/ | sh
sudo ./clickhouse install

# Start service
sudo systemctl start clickhouse-server
sudo systemctl enable clickhouse-server

# Create database
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS l1_tool_db"
```

### Python Dependencies
```bash
pip install clickhouse-connect
```

This data model ensures all anomaly data is persistently stored in ClickHouse and no dummy/mock data is displayed in the UI. All dashboard metrics, trends, and anomaly lists are pulled directly from the database.