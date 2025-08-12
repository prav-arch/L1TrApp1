#!/bin/bash

# ClickHouse Server Start Script for L1 Anomaly Detection

echo "🚀 Starting ClickHouse Server for L1 Anomaly Detection..."

# Create ClickHouse directories
mkdir -p /tmp/clickhouse-server
mkdir -p /tmp/clickhouse-server/data
mkdir -p /tmp/clickhouse-server/logs
mkdir -p /tmp/clickhouse-server/config

# Create minimal ClickHouse configuration
cat > /tmp/clickhouse-server/config/config.xml << 'EOF'
<?xml version="1.0"?>
<yandex>
    <logger>
        <level>warning</level>
        <log>/tmp/clickhouse-server/logs/clickhouse-server.log</log>
        <errorlog>/tmp/clickhouse-server/logs/clickhouse-server.err.log</errorlog>
        <size>1000M</size>
        <count>10</count>
    </logger>

    <http_port>8123</http_port>
    <tcp_port>9000</tcp_port>

    <path>/tmp/clickhouse-server/data/</path>
    <tmp_path>/tmp/clickhouse-server/tmp/</tmp_path>
    <user_files_path>/tmp/clickhouse-server/user_files/</user_files_path>
    <access_control_path>/tmp/clickhouse-server/access/</access_control_path>

    <users>
        <default>
            <password></password>
            <networks>
                <ip>::/0</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>
    </users>

    <profiles>
        <default>
            <max_memory_usage>10000000000</max_memory_usage>
            <use_uncompressed_cache>0</use_uncompressed_cache>
            <load_balancing>random</load_balancing>
        </default>
    </profiles>

    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
                <result_rows>0</result_rows>
                <read_rows>0</read_rows>
                <execution_time>0</execution_time>
            </interval>
        </default>
    </quotas>
</yandex>
EOF

# Create users configuration
cat > /tmp/clickhouse-server/config/users.xml << 'EOF'
<?xml version="1.0"?>
<yandex>
    <profiles>
        <default>
            <max_memory_usage>10000000000</max_memory_usage>
            <use_uncompressed_cache>0</use_uncompressed_cache>
            <load_balancing>random</load_balancing>
        </default>
    </profiles>

    <users>
        <default>
            <password></password>
            <networks>
                <ip>::/0</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>
    </users>

    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
                <result_rows>0</result_rows>
                <read_rows>0</read_rows>
                <execution_time>0</execution_time>
            </interval>
        </default>
    </quotas>
</yandex>
EOF

echo "📁 Created ClickHouse configuration files"

# Start ClickHouse server in background
echo "🔄 Starting ClickHouse server..."

# Check if ClickHouse is available
if command -v clickhouse-server >/dev/null 2>&1; then
    # Start ClickHouse server
    clickhouse-server --config-file=/tmp/clickhouse-server/config/config.xml --daemon --pid-file=/tmp/clickhouse-server/clickhouse-server.pid

    # Wait for server to start
    echo "⏳ Waiting for ClickHouse to start..."
    sleep 5
    
    # Check if server is running
    if curl -s http://localhost:8123/ >/dev/null; then
        echo "✅ ClickHouse server is running on port 8123"
        echo "🔗 HTTP interface: http://localhost:8123"
        echo "🔗 TCP interface: localhost:9000"
        
        # Test basic connection
        echo "🧪 Testing connection..."
        curl -s "http://localhost:8123/?query=SELECT%20version()" && echo ""
        
        exit 0
    else
        echo "❌ Failed to start ClickHouse server"
        exit 1
    fi
else
    echo "❌ ClickHouse server not found. Please install ClickHouse first."
    echo "💡 On Replit, this should be automatically available."
    exit 1
fi