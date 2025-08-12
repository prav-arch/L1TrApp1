# Linux GPU Deployment Guide
# Network Anomaly Detection System

This guide provides complete instructions for deploying the network anomaly detection system on Linux with GPU support for TSLAM 4B model inference.

## System Requirements

### Hardware Requirements
- **GPU**: NVIDIA GPU with at least 8GB VRAM (RTX 3070/4070, Tesla V100, A100, etc.)
- **RAM**: Minimum 16GB, recommended 32GB+ 
- **Storage**: 50GB+ free space (for models and data)
- **CPU**: Multi-core processor (8+ cores recommended)

### Software Requirements
- **OS**: Ubuntu 20.04+ / CentOS 8+ / RHEL 8+
- **CUDA**: Version 11.8 or 12.0+
- **Docker**: Optional but recommended

## Step 1: System Preparation

### Update System
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# CentOS/RHEL
sudo yum update -y
```

### Install Essential Tools
```bash
# Ubuntu/Debian
sudo apt install -y curl wget git build-essential software-properties-common

# CentOS/RHEL  
sudo yum groupinstall -y "Development Tools"
sudo yum install -y curl wget git
```

## Step 2: NVIDIA GPU Setup

### Install NVIDIA Drivers
```bash
# Check if GPU is detected
lspci | grep -i nvidia

# Ubuntu - Install NVIDIA drivers
sudo apt install -y nvidia-driver-525 nvidia-utils-525

# CentOS/RHEL - Install NVIDIA drivers
sudo yum install -y nvidia-driver nvidia-settings
```

### Install CUDA Toolkit
```bash
# Download CUDA 12.0 (adjust version as needed)
wget https://developer.download.nvidia.com/compute/cuda/12.0.0/local_installers/cuda_12.0.0_525.60.13_linux.run

# Install CUDA
sudo sh cuda_12.0.0_525.60.13_linux.run

# Add to PATH
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# Verify installation
nvidia-smi
nvcc --version
```

## Step 3: Install ClickHouse Database

### Option A: Package Installation (Recommended)
```bash
# Add ClickHouse repository
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

# Ubuntu/Debian
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list
sudo apt update
sudo apt install -y clickhouse-server clickhouse-client

# CentOS/RHEL
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://packages.clickhouse.com/rpm/clickhouse.repo
sudo yum install -y clickhouse-server clickhouse-client
```

### Configure ClickHouse
```bash
# Start and enable ClickHouse
sudo systemctl start clickhouse-server
sudo systemctl enable clickhouse-server

# Create database and tables
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS l1_tool_db"

# Create tables (run each separately)
clickhouse-client --database=l1_tool_db --query "
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
ORDER BY timestamp;"

clickhouse-client --database=l1_tool_db --query "
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
ORDER BY upload_time;"

clickhouse-client --database=l1_tool_db --query "
CREATE TABLE IF NOT EXISTS sessions (
    id String,
    session_id String,
    start_time DateTime,
    end_time DateTime,
    packets_analyzed UInt64,
    anomalies_detected UInt32,
    source_file String
) ENGINE = MergeTree()
ORDER BY start_time;"

clickhouse-client --database=l1_tool_db --query "
CREATE TABLE IF NOT EXISTS metrics (
    id String,
    metric_name String,
    metric_value Float64,
    timestamp DateTime,
    category String
) ENGINE = MergeTree()
ORDER BY timestamp;"

# Verify tables created
clickhouse-client --database=l1_tool_db --query "SHOW TABLES"
```

## Step 4: Install Node.js and Python

### Install Node.js 20
```bash
# Install Node Version Manager
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc

# Install Node.js 20
nvm install 20
nvm use 20
nvm alias default 20

# Verify installation
node --version
npm --version
```

### Install Python 3.11
```bash
# Ubuntu/Debian
sudo apt install -y python3.11 python3.11-venv python3.11-dev python3-pip

# CentOS/RHEL (may need EPEL)
sudo yum install -y python3.11 python3.11-venv python3.11-devel python3-pip

# Create symlink for python3.11
sudo ln -sf /usr/bin/python3.11 /usr/bin/python3
```

## Step 5: Clone and Setup Project

### Clone Repository
```bash
# Clone your project (replace with your actual repository)
git clone <your-repo-url> network-anomaly-detection
cd network-anomaly-detection

# Or copy files from your development environment
```

### Install Node.js Dependencies
```bash
# Install all Node.js packages
npm install

# Verify installation
npm list
```

### Install Python Dependencies
```bash
# Create Python virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install clickhouse-connect scapy torch transformers accelerate

# For GPU support (CUDA)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# Verify GPU support
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"
```

## Step 6: Configure Environment

### Create Environment File
```bash
# Create .env file
cat > .env << EOF
NODE_ENV=production
DATABASE_URL=clickhouse://localhost:9000/l1_tool_db
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=9000
CLICKHOUSE_DATABASE=l1_tool_db
TSLAM_MODEL_PATH=/opt/models/tslam-4b
GPU_ENABLED=true
CUDA_VISIBLE_DEVICES=0
EOF
```

### Download TSLAM Model (if available)
```bash
# Create models directory
sudo mkdir -p /opt/models
sudo chown $USER:$USER /opt/models

# Download TSLAM 4B model (replace with actual model source)
# This is a placeholder - you'll need the actual model files
mkdir -p /opt/models/tslam-4b
# wget <model-download-url> -O /opt/models/tslam-4b/
```

## Step 7: Build and Deploy Application

### Build Frontend
```bash
# Build production frontend
npm run build

# Verify build files
ls -la dist/
```

### Create Systemd Service
```bash
# Create service file
sudo tee /etc/systemd/system/network-anomaly-detection.service > /dev/null << EOF
[Unit]
Description=Network Anomaly Detection System
After=network.target clickhouse-server.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=NODE_ENV=production
Environment=PATH=/home/$USER/.nvm/versions/node/v20.0.0/bin:/usr/local/cuda/bin:/usr/bin:/bin
ExecStart=/home/$USER/.nvm/versions/node/v20.0.0/bin/npm run start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable network-anomaly-detection
```

## Step 8: Start and Test System

### Start Services
```bash
# Start ClickHouse (if not already running)
sudo systemctl start clickhouse-server

# Start the application
sudo systemctl start network-anomaly-detection

# Check status
sudo systemctl status network-anomaly-detection
sudo systemctl status clickhouse-server
```

### Test Database Connection
```bash
# Test ClickHouse connection
clickhouse-client --database=l1_tool_db --query "SELECT 'Connection successful'"

# Test application endpoints
curl http://localhost:5000/api/dashboard/metrics
curl http://localhost:5000/api/anomalies
```

### Access Application
```bash
# The application should be running on:
echo "Access your application at: http://your-server-ip:5000"

# For local access:
echo "Local access: http://localhost:5000"
```

## Step 9: Firewall Configuration

### Configure Firewall
```bash
# Ubuntu/Debian (UFW)
sudo ufw allow 5000/tcp
sudo ufw allow 9000/tcp  # ClickHouse
sudo ufw reload

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --permanent --add-port=9000/tcp
sudo firewall-cmd --reload
```

## Step 10: Monitoring and Logs

### View Application Logs
```bash
# View application logs
sudo journalctl -u network-anomaly-detection -f

# View ClickHouse logs
sudo tail -f /var/log/clickhouse-server/clickhouse-server.log

# View system resources
htop
nvidia-smi -l 1
```

### Performance Monitoring
```bash
# Monitor GPU usage
watch -n 1 nvidia-smi

# Monitor system resources
htop
iotop

# Monitor ClickHouse performance
clickhouse-client --query "SELECT * FROM system.processes"
```

## Troubleshooting

### Common Issues

1. **GPU Not Detected**
   ```bash
   # Reinstall NVIDIA drivers
   sudo apt purge nvidia-*
   sudo apt autoremove
   sudo apt install nvidia-driver-525
   sudo reboot
   ```

2. **ClickHouse Connection Failed**
   ```bash
   # Check service status
   sudo systemctl status clickhouse-server
   
   # Restart service
   sudo systemctl restart clickhouse-server
   
   # Check logs
   sudo tail -f /var/log/clickhouse-server/clickhouse-server.log
   ```

3. **Application Won't Start**
   ```bash
   # Check logs
   sudo journalctl -u network-anomaly-detection --no-pager
   
   # Check port conflicts
   sudo netstat -tlnp | grep :5000
   
   # Manual start for debugging
   cd /path/to/project
   npm run dev
   ```

4. **Python Dependencies Issues**
   ```bash
   # Recreate virtual environment
   rm -rf venv
   python3.11 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

## Security Considerations

### Basic Security Setup
```bash
# Create dedicated user for the application
sudo useradd -m -s /bin/bash anomaly-detection
sudo usermod -aG docker anomaly-detection  # if using Docker

# Set proper file permissions
sudo chown -R anomaly-detection:anomaly-detection /path/to/project
chmod 750 /path/to/project

# Configure firewall to restrict access
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from trusted-ip-range to any port 5000
```

## Performance Optimization

### System Tuning
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize ClickHouse settings
sudo tee -a /etc/clickhouse-server/config.xml << EOF
<yandex>
    <max_connections>1000</max_connections>
    <max_concurrent_queries>100</max_concurrent_queries>
</yandex>
EOF

# Restart ClickHouse
sudo systemctl restart clickhouse-server
```

Your network anomaly detection system should now be running on Linux with full GPU support for TSLAM inference and ClickHouse for high-performance data storage!

Access your application at `http://your-server-ip:5000` and start uploading PCAP files for analysis.