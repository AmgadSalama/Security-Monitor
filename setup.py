#!/usr/bin/env python3
"""
Security Monitor Setup Script
"""

import os
import sys
import subprocess
import json
from pathlib import Path


def install_requirements():
    """Install Python requirements"""
    print("Installing Python requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Python requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install requirements: {e}")
        return False


def create_directories():
    """Create necessary directories"""
    print("Creating directories...")
    directories = [
        "logs",
        "reports",
        "data",
        "config"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")


def create_default_config():
    """Create default configuration file"""
    print("Creating default configuration...")
    
    config = {
        "agent": {
            "id": "default-agent",
            "hostname": "localhost"
        },
        "server": {
            "url": "ws://localhost:8000/ws/agent",
            "max_retries": 5,
            "retry_delay": 5
        },
        "monitoring": {
            "interval": 30
        },
        "file_monitoring": {
            "enabled": True,
            "watch_paths": [
                "/tmp",
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop")
            ],
            "max_events": 1000
        },
        "system": {
            "collect_processes": True,
            "collect_network": True
        },
        "detection": {
            "enabled": True,
            "custom_rules": []
        },
        "logging": {
            "level": "INFO",
            "file": "logs/security_monitor.log"
        },
        "database": {
            "url": "sqlite:///./data/security_monitor.db"
        },
        "email": {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "use_tls": True
        },
        "reporting": {
            "output_dir": "reports",
            "auto_generate": False,
            "schedule": "daily",
            "recipients": []
        }
    }
    
    config_path = "config/security_monitor.json"
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"✓ Created default configuration: {config_path}")


def initialize_database():
    """Initialize the database"""
    print("Initializing database...")
    try:
        from security_monitor.database.database import init_database
        init_database()
        print("✓ Database initialized successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to initialize database: {e}")
        return False


def create_systemd_service():
    """Create systemd service files for Linux"""
    if sys.platform != "linux":
        return
    
    print("Creating systemd service files...")
    
    current_dir = os.getcwd()
    python_path = sys.executable
    
    # Dashboard service
    dashboard_service = f"""[Unit]
Description=Security Monitor Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={current_dir}
Environment=PATH=/usr/bin:/usr/local/bin
Environment=PYTHONPATH={current_dir}
ExecStart={python_path} -m security_monitor.main dashboard --config config/security_monitor.json
Restart=always

[Install]
WantedBy=multi-user.target
"""
    
    # Agent service
    agent_service = f"""[Unit]
Description=Security Monitor Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={current_dir}
Environment=PATH=/usr/bin:/usr/local/bin
Environment=PYTHONPATH={current_dir}
ExecStart={python_path} -m security_monitor.main agent --config config/security_monitor.json --daemon
Restart=always

[Install]
WantedBy=multi-user.target
"""
    
    # Write service files
    with open("security-monitor-dashboard.service", 'w') as f:
        f.write(dashboard_service)
    
    with open("security-monitor-agent.service", 'w') as f:
        f.write(agent_service)
    
    print("✓ Created systemd service files:")
    print("  - security-monitor-dashboard.service")
    print("  - security-monitor-agent.service")
    print("\nTo install services, run:")
    print("  sudo cp *.service /etc/systemd/system/")
    print("  sudo systemctl daemon-reload")
    print("  sudo systemctl enable security-monitor-dashboard")
    print("  sudo systemctl enable security-monitor-agent")


def create_startup_scripts():
    """Create startup scripts"""
    print("Creating startup scripts...")
    
    # Linux/macOS startup script
    start_script = """#!/bin/bash
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
"""
    
    # Stop script
    stop_script = """#!/bin/bash
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
"""
    
    with open("start.sh", 'w') as f:
        f.write(start_script)
    os.chmod("start.sh", 0o755)
    
    with open("stop.sh", 'w') as f:
        f.write(stop_script)
    os.chmod("stop.sh", 0o755)
    
    print("✓ Created startup scripts: start.sh, stop.sh")


def print_usage_instructions():
    """Print usage instructions"""
    print("\n" + "="*60)
    print("Security Monitor Setup Complete!")
    print("="*60)
    print("\nQuick Start:")
    print("1. Start the system:")
    print("   ./start.sh")
    print("\n2. Open your browser and go to:")
    print("   http://localhost:8000")
    print("\n3. To stop the system:")
    print("   ./stop.sh")
    
    print("\nManual Commands:")
    print("• Start dashboard: python3 -m security_monitor.main dashboard")
    print("• Start agent: python3 -m security_monitor.main agent")
    print("• Generate report: python3 -m security_monitor.main report --type daily")
    print("• Initialize DB: python3 -m security_monitor.main database init")
    
    print("\nConfiguration:")
    print("• Edit config/security_monitor.json to customize settings")
    print("• Configure email settings for reports and alerts")
    print("• Add custom threat detection rules")
    
    print("\nLogs:")
    print("• Application logs: logs/security_monitor.log")
    print("• Reports: reports/")
    
    print("\nFor more information, see the documentation or run:")
    print("python3 -m security_monitor.main --help")
    print("="*60)


def main():
    print("Security Monitor Setup")
    print("="*30)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("✗ Python 3.8 or higher is required")
        sys.exit(1)
    
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Run setup steps
    steps = [
        ("Installing requirements", install_requirements),
        ("Creating directories", create_directories),
        ("Creating default configuration", create_default_config),
        ("Initializing database", initialize_database),
        ("Creating startup scripts", create_startup_scripts)
    ]
    
    for step_name, step_func in steps:
        print(f"\n{step_name}...")
        try:
            if step_func() is False:
                print(f"✗ {step_name} failed")
                sys.exit(1)
        except Exception as e:
            print(f"✗ {step_name} failed: {e}")
            sys.exit(1)
    
    # Optional systemd service creation
    if sys.platform == "linux":
        try:
            create_systemd_service()
        except Exception as e:
            print(f"Warning: Could not create systemd services: {e}")
    
    print_usage_instructions()


if __name__ == "__main__":
    main()