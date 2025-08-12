# Database Setup Guide for L1 Anomaly Detection System

## PostgreSQL Database Creation and Setup

### Quick Setup (Already Completed)

The database has been automatically created and configured. Here's what was set up:

### Database Tables Created

#### 1. `anomalies` Table
Stores all detected network anomalies with detailed information.

```sql
CREATE TABLE anomalies (
    id SERIAL PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_type VARCHAR(10) NOT NULL CHECK (file_type IN ('PCAP', 'TEXT')),
    line_number INTEGER NOT NULL,
    anomaly_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    description TEXT,
    details JSONB,
    ue_id VARCHAR(50),
    du_mac VARCHAR(17) DEFAULT '00:11:22:33:44:67',
    ru_mac VARCHAR(17) DEFAULT '6c:ad:ad:00:03:2a',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'resolved', 'ignored'))
);
```

**Purpose:** Track all anomalies with line numbers, MAC addresses, and detailed issue descriptions.

#### 2. `processed_files` Table
Tracks all files that have been analyzed.

```sql
CREATE TABLE processed_files (
    id SERIAL PRIMARY KEY,
    file_path TEXT NOT NULL UNIQUE,
    file_name VARCHAR(255) NOT NULL,
    file_type VARCHAR(10) NOT NULL,
    file_size BIGINT NOT NULL,
    processing_status VARCHAR(20) DEFAULT 'pending',
    events_extracted INTEGER DEFAULT 0,
    anomalies_found INTEGER DEFAULT 0,
    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT
);
```

**Purpose:** Monitor file processing status and statistics.

#### 3. `sessions` Table
Records analysis sessions for batch processing.

```sql
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    session_name VARCHAR(255),
    folder_path TEXT NOT NULL,
    total_files INTEGER DEFAULT 0,
    pcap_files INTEGER DEFAULT 0,
    text_files INTEGER DEFAULT 0,
    total_anomalies INTEGER DEFAULT 0,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    duration_seconds INTEGER,
    status VARCHAR(20) DEFAULT 'running'
);
```

**Purpose:** Track folder analysis sessions and performance metrics.

#### 4. `metrics` Table
Stores analysis metrics and performance data.

```sql
CREATE TABLE metrics (
    id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(id),
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC,
    metric_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Purpose:** Store detailed metrics for dashboard and reporting.

### Database Access Information

The following environment variables are automatically available:

- `DATABASE_URL` - Complete connection string
- `PGHOST` - Database host
- `PGPORT` - Database port  
- `PGUSER` - Database username
- `PGPASSWORD` - Database password
- `PGDATABASE` - Database name

### Verify Database Setup

Check that tables were created successfully:

```sql
SELECT table_name, column_name, data_type 
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name IN ('anomalies', 'processed_files', 'sessions', 'metrics')
ORDER BY table_name, ordinal_position;
```

### Performance Indexes

Indexes were created for optimal query performance:

```sql
CREATE INDEX idx_anomalies_file_type ON anomalies(file_type);
CREATE INDEX idx_anomalies_timestamp ON anomalies(timestamp);
CREATE INDEX idx_anomalies_severity ON anomalies(severity);
CREATE INDEX idx_processed_files_status ON processed_files(processing_status);
CREATE INDEX idx_sessions_status ON sessions(status);
```

## Usage with Folder Analyzer

### Database Integration (Future Enhancement)

The folder analyzer currently works standalone but can be enhanced to store results in the database:

#### Insert Anomaly Example
```sql
INSERT INTO anomalies (
    file_path, file_type, line_number, anomaly_type, 
    severity, description, details, ue_id
) VALUES (
    '/path/to/file.txt', 'TEXT', 33, 'UE Event Pattern',
    'high', 'Failed attach procedures', 
    '{"issues": ["Context Failures: 2 detected"]}', '460110123456789'
);
```

#### Query Anomalies Example
```sql
SELECT * FROM anomalies 
WHERE file_type = 'PCAP' 
AND severity IN ('high', 'critical')
ORDER BY timestamp DESC;
```

### Database Schema Benefits

1. **Persistent Storage**: All anomalies saved permanently
2. **Historical Analysis**: Track patterns over time
3. **Dashboard Integration**: Real-time metrics and charts
4. **Reporting**: Generate comprehensive reports
5. **Performance Tracking**: Monitor analysis efficiency

### Manual Database Commands (If Needed)

#### Connect to Database
```bash
psql $DATABASE_URL
```

#### Check Table Status
```sql
\dt
\d anomalies
```

#### View Recent Anomalies
```sql
SELECT file_path, anomaly_type, severity, timestamp 
FROM anomalies 
ORDER BY timestamp DESC 
LIMIT 10;
```

#### Clear Test Data (If Needed)
```sql
TRUNCATE anomalies, processed_files, sessions, metrics RESTART IDENTITY CASCADE;
```

## Integration with Web Dashboard

The database tables integrate with the existing web dashboard:

- **Dashboard**: Shows real-time anomaly counts from `anomalies` table
- **File Manager**: Tracks processing status via `processed_files` table  
- **Sessions**: Records analysis history in `sessions` table
- **Metrics**: Performance data stored in `metrics` table

## Backup and Maintenance

### Backup Database
```bash
pg_dump $DATABASE_URL > l1_anomaly_backup.sql
```

### Restore Database
```bash
psql $DATABASE_URL < l1_anomaly_backup.sql
```

### Database Size Monitoring
```sql
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    most_common_vals
FROM pg_stats 
WHERE tablename IN ('anomalies', 'processed_files', 'sessions', 'metrics');
```

## Troubleshooting

### Connection Issues
```bash
# Test database connection
psql $DATABASE_URL -c "SELECT version();"
```

### Permission Issues
```bash
# Check database permissions
psql $DATABASE_URL -c "SELECT current_user, session_user;"
```

### Table Issues
```sql
-- Recreate tables if needed
DROP TABLE IF EXISTS metrics, sessions, processed_files, anomalies CASCADE;
-- Then run the CREATE TABLE commands again
```

## Status: Database Ready ✅

The PostgreSQL database has been successfully created and configured with all necessary tables and indexes. The L1 Anomaly Detection System is ready to use with persistent data storage capabilities.