#!/bin/bash

echo "🚀 Starting ClickHouse with default configuration..."

# Kill any existing ClickHouse processes
pkill -f clickhouse-server 2>/dev/null || true

# Start ClickHouse with minimal config
mkdir -p /tmp/clickhouse
cd /tmp/clickhouse

# Start ClickHouse server with default settings
clickhouse-server --daemon \
  --http_port=8123 \
  --tcp_port=9000 \
  --path=/tmp/clickhouse/ \
  --pid-file=/tmp/clickhouse/clickhouse.pid

echo "⏳ Waiting for ClickHouse to start..."
sleep 3

# Test connection
if curl -s http://localhost:8123/ping | grep -q "Ok"; then
    echo "✅ ClickHouse is running on port 8123"
    curl -s "http://localhost:8123/?query=SELECT%20version()" && echo ""
else
    echo "❌ ClickHouse failed to start, checking logs..."
    echo "Starting in foreground for debugging..."
    clickhouse-server --http_port=8123 --tcp_port=9000 --path=/tmp/clickhouse/ &
    sleep 2
    curl -s http://localhost:8123/ping || echo "Still not responding"
fi