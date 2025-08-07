# Security Monitor Deployment Guide

This guide covers deployment options for the Security Monitor framework in different environments.

## Quick Start (Development)

```bash
# 1. Install and setup
python3 setup.py

# 2. Start the system
./start.sh

# 3. Access dashboard
open http://localhost:8000
```

## Production Deployment

### Linux Server Deployment

#### 1. System Requirements
- Python 3.8+
- 4GB RAM minimum
- 10GB disk space
- Network access for agents

#### 2. Installation
```bash
# Clone repository
git clone <repository-url>
cd SecurityMonitor

# Install dependencies
sudo python3 setup.py

# Create system user
sudo useradd -r -s /bin/false security-monitor
sudo chown -R security-monitor:security-monitor /opt/security-monitor
```

#### 3. Systemd Services
```bash
# Copy service files
sudo cp security-monitor-*.service /etc/systemd/system/

# Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable security-monitor-dashboard
sudo systemctl enable security-monitor-agent
sudo systemctl start security-monitor-dashboard
sudo systemctl start security-monitor-agent

# Check status
sudo systemctl status security-monitor-*
```

#### 4. Nginx Reverse Proxy
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Docker Deployment

#### 1. Build Docker Image
```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN python setup.py

EXPOSE 8000
CMD ["python", "-m", "security_monitor.main", "dashboard"]
```

#### 2. Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  dashboard:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - DATABASE_URL=sqlite:///data/security_monitor.db
    
  agent:
    build: .
    command: ["python", "-m", "security_monitor.main", "agent"]
    volumes:
      - ./config:/app/config
      - /:/host:ro
    network_mode: host
    privileged: true
```

### Multi-Agent Deployment

#### 1. Central Dashboard Server
```bash
# On central server
python3 -m security_monitor.main dashboard --host 0.0.0.0 --port 8000
```

#### 2. Remote Agent Configuration
```json
{
  "agent": {
    "id": "agent-web-01",
    "hostname": "web-server-01"
  },
  "server": {
    "url": "ws://central-dashboard.company.com:8000/ws/agent"
  },
  "monitoring": {
    "interval": 30
  }
}
```

#### 3. Agent Installation Script
```bash
#!/bin/bash
# install-agent.sh

CENTRAL_SERVER="https://central-dashboard.company.com"
AGENT_ID="agent-$(hostname)"

# Install agent
curl -sSL $CENTRAL_SERVER/install-agent.sh | bash

# Configure agent
cat > /etc/security-monitor/config.json << EOF
{
  "agent": {
    "id": "$AGENT_ID",
    "hostname": "$(hostname)"
  },
  "server": {
    "url": "ws://central-dashboard.company.com:8000/ws/agent"
  }
}
EOF

# Start agent
systemctl enable security-monitor-agent
systemctl start security-monitor-agent
```

## Security Considerations

### SSL/TLS Configuration
```bash
# Generate SSL certificate
sudo certbot certonly --nginx -d your-domain.com

# Update nginx configuration for HTTPS
# Use wss:// for WebSocket connections
```

### Firewall Rules
```bash
# Dashboard server
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8000/tcp  # Dashboard (if not using reverse proxy)

# Agent endpoints
sudo ufw allow out 8000/tcp  # Connection to dashboard
```

### Database Security
```bash
# Encrypt database file
sudo apt-get install sqlcipher
# Use encrypted SQLite database in production
```

### Log Management
```bash
# Rotate logs
sudo cat > /etc/logrotate.d/security-monitor << EOF
/var/log/security-monitor/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    create 644 security-monitor security-monitor
    postrotate
        systemctl reload security-monitor-dashboard
    endscript
}
EOF
```

## Monitoring and Maintenance

### Health Checks
```bash
# System health check
python3 status_check.py

# Service status
systemctl status security-monitor-*

# Log monitoring
tail -f /var/log/security-monitor/security_monitor.log
```

### Database Maintenance
```bash
# Backup database
sqlite3 security_monitor.db ".backup backup_$(date +%Y%m%d).db"

# Clean old events (keep last 30 days)
python3 -c "
from security_monitor.database.database import SessionLocal
from security_monitor.database.models import SecurityEvent
from datetime import datetime, timedelta
db = SessionLocal()
old_date = datetime.now() - timedelta(days=30)
db.query(SecurityEvent).filter(SecurityEvent.timestamp < old_date).delete()
db.commit()
"
```

### Updates and Patches
```bash
# Update system
git pull origin main
pip install -r requirements.txt

# Restart services
sudo systemctl restart security-monitor-*

# Verify update
python3 status_check.py
```

## Troubleshooting

### Common Issues

#### Agent Connection Problems
1. Check network connectivity: `curl -I http://dashboard-host:8000`
2. Verify configuration: `python3 -m security_monitor.main config validate`
3. Check firewall rules and DNS resolution

#### High Memory Usage
1. Adjust event retention: Set shorter retention periods in config
2. Monitor process count: Limit the number of monitored processes
3. Reduce monitoring frequency: Increase interval in configuration

#### Database Lock Issues
1. Check disk space: `df -h`
2. Stop conflicting processes: `fuser security_monitor.db`
3. Repair database: `sqlite3 security_monitor.db ".recover"`

### Performance Tuning

#### Dashboard Optimization
- Use reverse proxy with caching
- Enable gzip compression
- Optimize database queries with indexes

#### Agent Optimization
- Adjust monitoring intervals based on system load
- Use process-specific monitoring for high-traffic systems
- Implement sampling for high-volume events

## Scaling Considerations

### Horizontal Scaling
- Deploy multiple dashboard instances behind load balancer
- Use external database (PostgreSQL) for high availability
- Implement event queuing (Redis/RabbitMQ) for high throughput

### Vertical Scaling
- Increase server resources based on agent count
- Monitor database performance and optimize queries
- Use SSD storage for database and logs