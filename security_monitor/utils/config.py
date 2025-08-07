import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file or environment variables"""
    
    # Default configuration
    default_config = {
        "agent": {
            "id": os.getenv("AGENT_ID", "default-agent"),
            "hostname": os.getenv("HOSTNAME", "localhost"),
            "ip_address": "127.0.0.1"
        },
        "server": {
            "url": os.getenv("SERVER_URL", "ws://localhost:8000/ws/agent"),
            "max_retries": int(os.getenv("SERVER_MAX_RETRIES", "5")),
            "retry_delay": int(os.getenv("SERVER_RETRY_DELAY", "5"))
        },
        "monitoring": {
            "interval": int(os.getenv("MONITORING_INTERVAL", "30"))
        },
        "file_monitoring": {
            "enabled": os.getenv("FILE_MONITORING_ENABLED", "true").lower() == "true",
            "watch_paths": [],
            "max_events": int(os.getenv("MAX_FILE_EVENTS", "1000"))
        },
        "system": {
            "collect_processes": os.getenv("COLLECT_PROCESSES", "true").lower() == "true",
            "collect_network": os.getenv("COLLECT_NETWORK", "true").lower() == "true"
        },
        "detection": {
            "enabled": os.getenv("DETECTION_ENABLED", "true").lower() == "true",
            "custom_rules": []
        },
        "logging": {
            "level": os.getenv("LOG_LEVEL", "INFO"),
            "file": os.getenv("LOG_FILE")
        },
        "database": {
            "url": os.getenv("DATABASE_URL", "sqlite:///./security_monitor.db")
        },
        "email": {
            "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
            "smtp_port": int(os.getenv("SMTP_PORT", "587")),
            "username": os.getenv("EMAIL_USERNAME"),
            "password": os.getenv("EMAIL_PASSWORD"),
            "use_tls": os.getenv("EMAIL_USE_TLS", "true").lower() == "true"
        },
        "reporting": {
            "output_dir": os.getenv("REPORTS_DIR", "reports"),
            "auto_generate": os.getenv("AUTO_GENERATE_REPORTS", "false").lower() == "true",
            "schedule": os.getenv("REPORT_SCHEDULE", "daily"),
            "recipients": os.getenv("REPORT_RECIPIENTS", "").split(",") if os.getenv("REPORT_RECIPIENTS") else []
        }
    }
    
    # Load from config file if provided
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
                # Merge with default config
                default_config = merge_configs(default_config, file_config)
        except Exception as e:
            logging.warning(f"Error loading config file {config_path}: {e}")
    
    # Look for default config files
    default_paths = [
        "security_monitor.json",
        "config.json",
        os.path.expanduser("~/.security_monitor/config.json"),
        "/etc/security_monitor/config.json"
    ]
    
    for path in default_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    file_config = json.load(f)
                    default_config = merge_configs(default_config, file_config)
                    break
            except Exception as e:
                logging.warning(f"Error loading config file {path}: {e}")
    
    return default_config


def merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge configuration dictionaries"""
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    
    return result


def save_config(config: Dict[str, Any], config_path: str) -> bool:
    """Save configuration to file"""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        logging.info(f"Configuration saved to {config_path}")
        return True
    except Exception as e:
        logging.error(f"Error saving config to {config_path}: {e}")
        return False


def get_config_template() -> Dict[str, Any]:
    """Get a template configuration with comments"""
    return {
        "_comment": "Security Monitor Configuration File",
        "agent": {
            "id": "agent-001",
            "hostname": "server.example.com",
            "_comment": "Unique identifier for this agent"
        },
        "server": {
            "url": "ws://security-monitor.local:8000/ws/agent",
            "max_retries": 5,
            "retry_delay": 5,
            "_comment": "Central server connection settings"
        },
        "monitoring": {
            "interval": 30,
            "_comment": "Data collection interval in seconds"
        },
        "file_monitoring": {
            "enabled": True,
            "watch_paths": [
                "/tmp",
                "/var/log",
                "~/Downloads",
                "~/Desktop"
            ],
            "max_events": 1000,
            "_comment": "File system monitoring configuration"
        },
        "system": {
            "collect_processes": True,
            "collect_network": True,
            "_comment": "System data collection settings"
        },
        "detection": {
            "enabled": True,
            "custom_rules": [],
            "_comment": "Threat detection settings"
        },
        "logging": {
            "level": "INFO",
            "file": "/var/log/security_monitor/agent.log",
            "_comment": "Logging configuration"
        },
        "email": {
            "smtp_server": "smtp.company.com",
            "smtp_port": 587,
            "username": "alerts@company.com",
            "password": "your-app-password",
            "use_tls": True,
            "_comment": "Email notification settings"
        },
        "reporting": {
            "output_dir": "/var/reports/security",
            "auto_generate": True,
            "schedule": "daily",
            "recipients": [
                "security@company.com",
                "admin@company.com"
            ],
            "_comment": "Report generation settings"
        }
    }


def validate_config(config: Dict[str, Any]) -> bool:
    """Validate configuration structure and required fields"""
    required_sections = ["agent", "server", "monitoring"]
    
    for section in required_sections:
        if section not in config:
            logging.error(f"Missing required configuration section: {section}")
            return False
    
    # Validate server URL
    server_url = config.get("server", {}).get("url")
    if not server_url or not (server_url.startswith("ws://") or server_url.startswith("wss://")):
        logging.error("Invalid server URL: must start with ws:// or wss://")
        return False
    
    # Validate monitoring interval
    interval = config.get("monitoring", {}).get("interval", 0)
    if not isinstance(interval, int) or interval < 1:
        logging.error("Invalid monitoring interval: must be positive integer")
        return False
    
    return True


def create_default_config_file(config_path: str) -> bool:
    """Create a default configuration file"""
    try:
        config = get_config_template()
        return save_config(config, config_path)
    except Exception as e:
        logging.error(f"Error creating default config file: {e}")
        return False


def get_environment_info() -> Dict[str, Any]:
    """Get environment information for configuration"""
    import platform
    import socket
    
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except:
        hostname = "unknown"
        ip_address = "127.0.0.1"
    
    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "platform": platform.system(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version()
    }