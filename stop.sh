#!/bin/bash
# Security Monitor Stop Script

echo "Stopping Security Monitor..."

# Kill dashboard
if [ -f "dashboard.pid" ]; then
    DASHBOARD_PID=$(cat dashboard.pid)
    if kill "$DASHBOARD_PID" 2>/dev/null; then
        echo "Dashboard stopped (PID: $DASHBOARD_PID)"
    fi
    rm -f dashboard.pid
fi

# Kill agent
if [ -f "agent.pid" ]; then
    AGENT_PID=$(cat agent.pid)
    if kill "$AGENT_PID" 2>/dev/null; then
        echo "Agent stopped (PID: $AGENT_PID)"
    fi
    rm -f agent.pid
fi

echo "Security Monitor stopped"
