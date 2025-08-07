# Security Monitor 🛡️

[![CI/CD Pipeline](https://github.com/yourusername/security-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/security-monitor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-green.svg)](https://github.com/PyCQA/bandit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A comprehensive Python-based security monitoring framework designed for enterprise-grade threat detection, real-time monitoring, and automated security reporting.

> **🚀 Ready for Testing**: This framework is production-ready and actively seeking community feedback and contributions!

## Features

### 🔍 **Endpoint Agent**
- Lightweight Python agent for system monitoring
- Real-time collection of system metrics (CPU, memory, disk, network)
- File system monitoring with integrity checking
- Process monitoring and analysis
- Network connection tracking

### 🎛️ **Central Dashboard**
- Web-based React dashboard for real-time monitoring
- Live event streaming via WebSockets
- Filtering and search capabilities
- Agent status monitoring
- Interactive threat analysis

### 🚨 **Threat Detection**
- Rule-based detection engine
- Pre-built security rules for common threats
- Custom rule creation and management
- Real-time threat scoring and classification
- Multiple threat categories (malware, data exfiltration, resource abuse, etc.)

### 📊 **Reporting System**
- Automated PDF report generation
- Email delivery with customizable templates
- Daily, weekly, and monthly reports
- Executive summaries and detailed analysis
- Custom report scheduling

## 🚀 Quick Start

### One-Command Setup
```bash
# 1. Setup and install
python3 setup.py

# 2. Start the system
./start.sh

# 3. Open dashboard
open http://localhost:8000
```

### Verification
```bash
# Run system tests
python3 run_tests.py

# Check component status
python3 status_check.py
```

### Manual Setup

1. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Initialize the database:**
   ```bash
   python3 -m security_monitor.main database init
   ```

3. **Start the dashboard:**
   ```bash
   python3 -m security_monitor.main dashboard
   ```

4. **Start an agent (in another terminal):**
   ```bash
   python3 -m security_monitor.main agent
   ```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Endpoint      │    │   Central       │    │   Management    │
│   Agents        │◄───┤   Dashboard     ├───►│   Console       │
│                 │    │                 │    │                 │
│ • System Monitor│    │ • Event Storage │    │ • Reports       │
│ • File Monitor  │    │ • Threat Engine │    │ • Alerts        │
│ • Process Watch │    │ • WebSocket API │    │ • Configuration │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Configuration

### Basic Configuration

Edit `config/security_monitor.json`:

```json
{
  "agent": {
    "id": "agent-001",
    "hostname": "server.example.com"
  },
  "server": {
    "url": "ws://security-monitor.local:8000/ws/agent",
    "max_retries": 5,
    "retry_delay": 5
  },
  "monitoring": {
    "interval": 30
  },
  "file_monitoring": {
    "enabled": true,
    "watch_paths": ["/tmp", "/var/log", "~/Downloads"],
    "max_events": 1000
  },
  "email": {
    "smtp_server": "smtp.company.com",
    "smtp_port": 587,
    "username": "alerts@company.com",
    "password": "app-password",
    "use_tls": true
  }
}
```

### Email Setup

For Gmail:
1. Enable 2-factor authentication
2. Generate an app-specific password
3. Use these settings:
   ```json
   "email": {
     "smtp_server": "smtp.gmail.com",
     "smtp_port": 587,
     "username": "your-email@gmail.com",
     "password": "your-app-password",
     "use_tls": true
   }
   ```

## Usage

### Command Line Interface

```bash
# Start dashboard
python3 -m security_monitor.main dashboard --host 0.0.0.0 --port 8000

# Start agent
python3 -m security_monitor.main agent --config config/security_monitor.json

# Generate reports
python3 -m security_monitor.main report --type daily --email

# Database operations
python3 -m security_monitor.main database init
python3 -m security_monitor.main database reset

# Configuration management
python3 -m security_monitor.main config create --file myconfig.json
python3 -m security_monitor.main config validate --file myconfig.json
```

### Dashboard Features

- **Real-time Events**: Live feed of security events from all agents
- **Agent Monitoring**: Status and health of all connected agents
- **Threat Analysis**: Interactive threat detection and analysis
- **Filtering**: Filter events by severity, type, source, or time range
- **Statistics**: System-wide security metrics and trends

### Threat Detection Rules

Built-in detection rules include:

- **System Threats**: High CPU/memory usage, resource exhaustion
- **File Threats**: Suspicious file creation, system file modification
- **Process Threats**: Malware processes, resource abuse
- **Network Threats**: Suspicious connections, data exfiltration

### Custom Rules

Create custom detection rules in the configuration:

```json
{
  "detection": {
    "custom_rules": [
      {
        "name": "custom_malware_detection",
        "description": "Detect specific malware patterns",
        "event_types": ["file_created"],
        "conditions": {
          "data.file_path": {
            "operator": "regex",
            "value": ".*suspicious_pattern.*"
          }
        },
        "severity": "critical",
        "threat_type": "malware"
      }
    ]
  }
}
```

## Deployment

### Production Deployment

1. **System Service (Linux):**
   ```bash
   # Copy service files
   sudo cp security-monitor-*.service /etc/systemd/system/
   
   # Enable services
   sudo systemctl daemon-reload
   sudo systemctl enable security-monitor-dashboard
   sudo systemctl enable security-monitor-agent
   
   # Start services
   sudo systemctl start security-monitor-dashboard
   sudo systemctl start security-monitor-agent
   ```

2. **Docker Deployment:**
   ```bash
   # Build image
   docker build -t security-monitor .
   
   # Run dashboard
   docker run -d -p 8000:8000 --name sm-dashboard security-monitor dashboard
   
   # Run agent
   docker run -d --name sm-agent security-monitor agent
   ```

### Multi-Agent Deployment

Deploy agents on multiple endpoints:

1. Install the agent package on each endpoint
2. Configure unique agent IDs
3. Point all agents to the central dashboard
4. Monitor all agents from the central dashboard

## Security Considerations

- **Network Security**: Use HTTPS/WSS for production deployments
- **Authentication**: Implement proper authentication for the dashboard
- **Data Encryption**: Encrypt sensitive data in configuration files
- **Access Control**: Restrict agent permissions and file access
- **Log Security**: Secure log files and prevent tampering

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Quick Contributions
- 🐛 **Report bugs** using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md)
- 💡 **Suggest features** using the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)  
- 📚 **Improve documentation** by submitting pull requests
- 🧪 **Add tests** to improve code coverage

### Development
1. Fork the repository and clone locally
2. Set up development environment: `python3 setup.py`
3. Make changes following our [contributing guidelines](CONTRIBUTING.md)
4. Run tests: `python run_tests.py`
5. Submit a pull request using our [PR template](.github/pull_request_template.md)

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 🔒 Security

Security is our top priority. To report security vulnerabilities:

- **DO NOT** create public GitHub issues
- Email security concerns to [amgad dot salama at acm dot org]
- See our [Security Policy](SECURITY.md) for details

## 📋 Roadmap & Future Features

### Phase 2 (Planned)
- [ ] Machine learning-based threat detection
- [ ] SIEM system integrations (Splunk, ELK)
- [ ] Advanced correlation engine with AI
- [ ] Mobile dashboard application

### Phase 3 (Future)
- [ ] Cloud-native deployment (Kubernetes)
- [ ] API for third-party integrations
- [ ] Compliance reporting (SOX, PCI DSS)
- [ ] Distributed agent management

Vote on features or suggest new ones in [GitHub Discussions](https://github.com/yourusername/security-monitor/discussions)!

## 🆘 Support & Community

### Getting Help
- 📖 **Documentation**: Start with this README and [DEPLOYMENT.md](DEPLOYMENT.md)
- 🐞 **Bug Reports**: Use [GitHub Issues](https://github.com/yourusername/security-monitor/issues)
- 💬 **Questions**: Use [GitHub Discussions](https://github.com/yourusername/security-monitor/discussions)
- 📧 **Security Issues**: Email [amgad dot salama at acm dot org]

### Community
- ⭐ **Star this repo** if you find it useful
- 🍴 **Fork and contribute** to help improve the project
- 📢 **Share** with others who might benefit from it

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎯 Status

- ✅ **Production Ready**: All core features implemented and tested
- 🧪 **Actively Tested**: Comprehensive test suite with CI/CD
- 🔒 **Security Focused**: Built with security best practices  
- 📚 **Well Documented**: Complete setup and deployment guides
- 🤝 **Community Driven**: Open to contributions and feedback

---

**Made with ❤️ for the cybersecurity community**

*Star ⭐ this repository if you find it useful!*
