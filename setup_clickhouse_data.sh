#!/bin/bash

# ClickHouse L1 Troubleshooting System Setup Script
echo "🗄️  Setting up ClickHouse for L1 Troubleshooting System"
echo "=================================================="

# Check if ClickHouse server is running
if ! curl -s http://localhost:8123/ping > /dev/null; then
    echo "❌ ClickHouse server is not running on localhost:8123"
    echo ""
    echo "🔧 To start ClickHouse server:"
    echo "   sudo systemctl start clickhouse-server"
    echo "   # or if using docker:"
    echo "   docker run -d --name clickhouse-server -p 8123:8123 -p 9000:9000 yandex/clickhouse-server"
    echo ""
    echo "⚠️  Make sure ClickHouse is running before proceeding"
    exit 1
fi

echo "✅ ClickHouse server is running"

# Run the Python setup script
echo "🐍 Running ClickHouse database setup..."
python3 clickhouse_local_setup.py

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 ClickHouse setup completed successfully!"
    echo "🔗 Your L1 Troubleshooting system should now connect to the database"
    echo "💡 Refresh your browser to see the anomalies with packet numbers"
else
    echo ""
    echo "❌ Setup failed. Please check the error messages above"
    exit 1
fi