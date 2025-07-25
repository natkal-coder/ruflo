#!/bin/bash

# Agentic Flow - Intelligent Startup Script
# This script starts all required services for the Agentic Flow UI

echo "🚀 Starting Agentic Flow Services..."
echo "=================================="

# Function to check if port is in use
check_port() {
    lsof -i :$1 > /dev/null 2>&1
}

# Function to get PID of process on port
get_port_pid() {
    lsof -ti :$1 2>/dev/null | head -1
}

# Check existing services
echo "🔍 Checking existing services..."

# Check API Server (port 3001)
if check_port 3001; then
    echo "✅ API Server already running on port 3001 (PID: $(get_port_pid 3001))"
    API_RUNNING=true
else
    echo "❌ API Server not running"
    API_RUNNING=false
fi

# Check Sync Manager (port 3007)
if check_port 3007; then
    echo "✅ Sync Manager already running on port 3007 (PID: $(get_port_pid 3007))"
    SYNC_RUNNING=true
else
    echo "❌ Sync Manager not running"
    SYNC_RUNNING=false
fi

# Check UI Server (port 5173)
if check_port 5173; then
    echo "✅ UI Server already running on port 5173 (PID: $(get_port_pid 5173))"
    UI_RUNNING=true
else
    echo "❌ UI Server not running"
    UI_RUNNING=false
fi

echo ""

# Start services that aren't running
if [ "$API_RUNNING" = false ]; then
    echo "📡 Starting Backend API Server..."
    node server.js &
    API_PID=$!
    echo "   ✅ API Server started (PID: $API_PID)"
    sleep 2
fi

if [ "$SYNC_RUNNING" = false ]; then
    echo "🔄 Starting Sync Manager..."
    node sync-manager.js &
    SYNC_PID=$!
    echo "   ✅ Sync Manager started (PID: $SYNC_PID)"
    sleep 1
fi

# For TypeScript server, we'll let the error handler in the code handle it
# since it runs on the same port as the API server

if [ "$UI_RUNNING" = false ]; then
    echo "🎨 Starting UI Development Server..."
    npm run dev > /dev/null 2>&1 &
    UI_PID=$!
    echo "   ✅ UI Server started (PID: $UI_PID)"
fi

echo ""
echo "=================================="
echo "✅ All services are running!"
echo ""
echo "🌐 Access the UI at:"
echo "   http://localhost:5173"
echo ""
echo "📊 Service Status:"
echo "   API Server: http://localhost:3001"
echo "   WebSocket: ws://localhost:3001"
echo "   Sync Manager: ws://localhost:3007"
echo "   Health Check: http://localhost:3001/api/health"
echo ""
echo "💡 Tips:"
echo "   - To stop all services: ./stop.sh"
echo "   - To restart a service: ./stop.sh && ./start.sh"
echo "   - To view logs: Check the terminal where services were started"
echo "=================================="

# Create/update PID file for cleanup
touch .pids
if [ "$API_RUNNING" = false ] && [ ! -z "$API_PID" ]; then
    echo "$API_PID" >> .pids
fi
if [ "$SYNC_RUNNING" = false ] && [ ! -z "$SYNC_PID" ]; then
    echo "$SYNC_PID" >> .pids
fi
if [ "$UI_RUNNING" = false ] && [ ! -z "$UI_PID" ]; then
    echo "$UI_PID" >> .pids
fi

# Only wait if we started new processes
if [ "$API_RUNNING" = false ] || [ "$SYNC_RUNNING" = false ] || [ "$UI_RUNNING" = false ]; then
    echo ""
    echo "Press Ctrl+C to stop all services..."
    wait
fi