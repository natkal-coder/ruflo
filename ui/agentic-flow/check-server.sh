#!/bin/bash

# Check if server is already running on port 3001
if lsof -i :3001 > /dev/null 2>&1; then
    echo ""
    echo "✅ Agentic Flow Backend Server is already running on port 3001"
    echo ""
    echo "📊 API Server: http://localhost:3001"
    echo "🔌 WebSocket: ws://localhost:3001"
    echo "🎯 UI Server: http://localhost:5173"
    echo ""
    echo "💡 To view the running server logs, check the other terminal."
    echo "   To restart, first stop the existing server with Ctrl+C."
    echo ""
    exit 0
else
    # Start the server if not running
    exec npx tsx server/index.ts
fi