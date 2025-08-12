# Simplified Linux Deployment Guide
# Network Anomaly Detection System (GPU & ClickHouse Ready)

This guide assumes you already have:
- ✅ GPU with NVIDIA drivers and CUDA installed
- ✅ Mistral AI model running on GPU  
- ✅ ClickHouse database installed and running

## Step 1: Verify Existing Setup

### Test ClickHouse Connection
```bash
# Test ClickHouse is running
clickhouse-client --query "SELECT version()"

# Check if l1_tool_db database exists
clickhouse-client --query "SHOW DATABASES" | grep l1_tool_db
```

### Create Database Schema (if needed)
```bash
# Create database if it doesn't exist
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS l1_tool_db"

# Create required tables
clickhouse-client --database=l1_tool_db --multiquery << 'EOF'
CREATE TABLE IF NOT EXISTS anomalies (
    id String,
    timestamp DateTime,
    type String,
    description String,
    severity String,
    source_file String,
    mac_address Nullable(String),
    ue_id Nullable(String),
    details String,
    status String
) ENGINE = MergeTree()
ORDER BY timestamp;

CREATE TABLE IF NOT EXISTS processed_files (
    id String,
    filename String,
    file_type String,
    file_size UInt64,
    upload_time DateTime,
    processing_status String,
    processing_start_time Nullable(DateTime),
    processing_end_time Nullable(DateTime),
    anomalies_found UInt32,
    error_message Nullable(String)
) ENGINE = MergeTree()
ORDER BY upload_time;

CREATE TABLE IF NOT EXISTS sessions (
    id String,
    session_id String,
    start_time DateTime,
    end_time DateTime,
    packets_analyzed UInt64,
    anomalies_detected UInt32,
    source_file String
) ENGINE = MergeTree()
ORDER BY start_time;

CREATE TABLE IF NOT EXISTS metrics (
    id String,
    metric_name String,
    metric_value Float64,
    timestamp DateTime,
    category String
) ENGINE = MergeTree()
ORDER BY timestamp;
EOF

# Verify tables
clickhouse-client --database=l1_tool_db --query "SHOW TABLES"
```

## Step 2: Install Node.js (if not installed)

### Check if Node.js exists
```bash
node --version
npm --version
```

### Install Node.js 20 (if needed)
```bash
# Using NodeSource repository
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Or using snap
sudo snap install node --classic

# Verify installation
node --version
npm --version
```

## Step 3: Install Python Dependencies

### Check Python version
```bash
python3 --version
python3 -m pip --version
```

### Install required Python packages
```bash
# Create virtual environment
python3 -m venv anomaly-detection-env
source anomaly-detection-env/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install clickhouse-connect scapy

# Verify installations
python -c "import clickhouse_connect; print('ClickHouse client installed')"
python -c "import scapy; print('Scapy installed')"
```

## Step 4: Deploy Application

### Clone/Copy Project Files
```bash
# If using git
git clone <your-repo-url> network-anomaly-detection
cd network-anomaly-detection

# Or copy your project files to a directory
mkdir -p ~/network-anomaly-detection
cd ~/network-anomaly-detection
# Copy all your project files here
```

### Install Node.js Dependencies
```bash
# Install all npm packages
npm install

# Check for any installation issues
npm audit
```

### Configure Environment
```bash
# Create environment configuration
cat > .env << EOF
NODE_ENV=production
DATABASE_URL=clickhouse://localhost:9000/l1_tool_db
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=9000
CLICKHOUSE_DATABASE=l1_tool_db
AI_MODEL_ENDPOINT=http://localhost:YOUR_MISTRAL_PORT
GPU_ENABLED=true
EOF

# Make sure to replace YOUR_MISTRAL_PORT with your actual Mistral API port
```

## Step 5: Build Application

### Build Production Version
```bash
# Build frontend for production
npm run build

# Verify build completed
ls -la dist/
```

## Step 6: Create Systemd Service

### Create service file
```bash
# Get current user and working directory
USER_NAME=$(whoami)
WORK_DIR=$(pwd)

# Create systemd service
sudo tee /etc/systemd/system/network-anomaly-detection.service > /dev/null << EOF
[Unit]
Description=Network Anomaly Detection System
After=network.target clickhouse-server.service

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$WORK_DIR
Environment=NODE_ENV=production
Environment=PATH=/usr/bin:/bin:/usr/local/bin
ExecStartPre=/bin/bash -c 'source $WORK_DIR/anomaly-detection-env/bin/activate'
ExecStart=/usr/bin/npm run start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload
sudo systemctl enable network-anomaly-detection
```

## Step 7: Configure Firewall

### Open required ports
```bash
# Ubuntu/Debian (UFW)
sudo ufw allow 5000/tcp
sudo ufw status

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload
```

## Step 8: Start and Test

### Start the service
```bash
# Start the application service
sudo systemctl start network-anomaly-detection

# Check service status
sudo systemctl status network-anomaly-detection

# Follow logs in real-time
sudo journalctl -u network-anomaly-detection -f
```

### Test Application
```bash
# Test API endpoints
curl http://localhost:5000/api/dashboard/metrics
curl http://localhost:5000/api/anomalies

# Test ClickHouse connectivity
curl http://localhost:5000/api/health  # if you have health endpoint
```

### Access Web Interface
```bash
# Get server IP
hostname -I

# Access application
echo "Application available at: http://$(hostname -I | awk '{print $1}'):5000"
```

## Step 9: Integrate with Your Mistral Model

### Update AI service configuration
```bash
# Edit the TSLAM service to use your Mistral endpoint
# Find your Mistral API endpoint and port
ps aux | grep mistral

# Update environment variables
echo "AI_MODEL_ENDPOINT=http://localhost:YOUR_MISTRAL_PORT" >> .env
```

### Test AI Integration
```bash
# Test if your Mistral model is accessible
curl http://localhost:YOUR_MISTRAL_PORT/health  # or appropriate endpoint

# Restart application to pick up changes
sudo systemctl restart network-anomaly-detection
```

## Step 10: Monitoring

### View logs
```bash
# Application logs
sudo journalctl -u network-anomaly-detection --no-pager -n 50

# ClickHouse logs (if needed)
sudo tail -f /var/log/clickhouse-server/clickhouse-server.log

# System resources
htop
```

### Monitor performance
```bash
# Check GPU usage (your Mistral model + any inference)
nvidia-smi -l 1

# Monitor application performance
curl http://localhost:5000/api/dashboard/metrics
```

## Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   # Check detailed logs
   sudo journalctl -u network-anomaly-detection -n 50
   
   # Try manual start for debugging
   cd ~/network-anomaly-detection
   source anomaly-detection-env/bin/activate
   npm run dev
   ```

2. **ClickHouse connection issues**
   ```bash
   # Test connection manually
   clickhouse-client --database=l1_tool_db --query "SELECT 1"
   
   # Check if ClickHouse is running
   sudo systemctl status clickhouse-server
   ```

3. **Port conflicts**
   ```bash
   # Check what's using port 5000
   sudo netstat -tlnp | grep :5000
   
   # Change port in package.json if needed
   ```

4. **Python environment issues**
   ```bash
   # Recreate virtual environment
   rm -rf anomaly-detection-env
   python3 -m venv anomaly-detection-env
   source anomaly-detection-env/bin/activate
   pip install clickhouse-connect scapy
   ```

## Quick Commands Summary

```bash
# Start application
sudo systemctl start network-anomaly-detection

# Stop application  
sudo systemctl stop network-anomaly-detection

# Restart application
sudo systemctl restart network-anomaly-detection

# View logs
sudo journalctl -u network-anomaly-detection -f

# Check status
sudo systemctl status network-anomaly-detection

# Test API
curl http://localhost:5000/api/dashboard/metrics
```

Your network anomaly detection system should now be running alongside your existing Mistral AI model and ClickHouse database!

Access the dashboard at: `http://your-server-ip:5000`