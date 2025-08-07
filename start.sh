#!/bin/bash
# Security Monitor Startup Script

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "Starting Security Monitor..."

# Start dashboard in background
echo "Starting dashboard..."
python3 -m security_monitor.main dashboard --config config/security_monitor.json &
DASHBOARD_PID=$!
echo "Dashboard started with PID: $DASHBOARD_PID"

# Wait a moment for dashboard to start
sleep 3

# Start agent in background
echo "Starting agent..."
python3 -m security_monitor.main agent --config config/security_monitor.json &
AGENT_PID=$!
echo "Agent started with PID: $AGENT_PID"

# Write PIDs to file for stop script
echo "$DASHBOARD_PID" > dashboard.pid
echo "$AGENT_PID" > agent.pid

echo "Security Monitor started successfully!"
echo "Dashboard: http://localhost:8000"
echo "To stop, run: ./stop.sh"
