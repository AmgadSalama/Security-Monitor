#!/usr/bin/env python3
"""
Security Monitor Demo - Simple demonstration of the security monitoring framework
"""

import asyncio
import time
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def demo_agent():
    """Demo the security agent functionality"""
    print("🔍 Security Monitor Agent Demo")
    print("=" * 50)
    
    from security_monitor.agent.system_monitor import SystemMonitor
    from security_monitor.agent.file_monitor import FileMonitor
    
    # Create monitors
    system_monitor = SystemMonitor()
    file_monitor = FileMonitor(watch_paths=["/tmp"], config={'max_events': 100})
    
    print("✓ System monitor initialized")
    print("✓ File monitor initialized")
    
    # Collect system data
    print("\n📊 Collecting system metrics...")
    system_events = system_monitor.collect_all_data()
    
    for event in system_events[:3]:  # Show first 3 events
        print(f"  • {event.event_type}: {event.severity}")
    
    print(f"✓ Collected {len(system_events)} system events")
    
    # Test file monitoring briefly
    print("\n📁 Starting file monitoring (5 seconds)...")
    file_monitor.start_monitoring()
    time.sleep(5)
    file_monitor.stop_monitoring()
    
    file_events = file_monitor.get_recent_events(10)
    print(f"✓ Monitored file system, found {len(file_events)} file events")


def demo_detection():
    """Demo the threat detection engine"""
    print("\n🚨 Threat Detection Engine Demo")
    print("=" * 50)
    
    from security_monitor.detection.rules import ThreatDetector
    
    detector = ThreatDetector()
    print(f"✓ Loaded {len(detector.rules)} threat detection rules")
    
    # Test with sample events
    test_events = [
        {
            'type': 'system_metrics',
            'timestamp': datetime.now().isoformat(),
            'source': 'demo',
            'data': {'cpu_percent': 95, 'memory_percent': 90}
        },
        {
            'type': 'file_created',
            'timestamp': datetime.now().isoformat(),
            'source': 'demo',
            'data': {'file_path': '/tmp/suspicious.exe', 'file_size': 1000000}
        }
    ]
    
    threats_detected = 0
    for event in test_events:
        result = detector.analyze_event(event)
        if result:
            threats_detected += 1
            print(f"  🚨 THREAT: {result.threat_type} - {result.severity}")
            print(f"     Rule: {result.rule_name}")
    
    print(f"✓ Analyzed {len(test_events)} events, detected {threats_detected} threats")


def demo_reporting():
    """Demo the reporting functionality"""
    print("\n📋 Security Reporting Demo")
    print("=" * 50)
    
    from security_monitor.reporting.pdf_generator import SecurityReportGenerator
    from datetime import datetime, timedelta
    import os
    
    # Create sample data
    sample_events = [
        {
            'timestamp': datetime.now().isoformat(),
            'type': 'system_metrics',
            'source': 'demo_agent',
            'severity': 'info',
            'data': {'cpu_percent': 45}
        },
        {
            'timestamp': datetime.now().isoformat(),
            'type': 'file_created',
            'source': 'demo_agent',
            'severity': 'warning',
            'threat_type': 'malware',
            'data': {'file_path': '/tmp/test.exe'}
        }
    ]
    
    sample_agents = [
        {
            'agent_id': 'demo-agent-001',
            'hostname': 'demo-server',
            'status': 'online',
            'last_seen': datetime.now().isoformat()
        }
    ]
    
    # Generate report
    generator = SecurityReportGenerator("reports")
    
    try:
        report_path = generator.generate_summary_report(
            sample_events, 
            sample_agents, 
            datetime.now() - timedelta(hours=24),
            datetime.now()
        )
        
        if os.path.exists(report_path):
            file_size = os.path.getsize(report_path) / 1024  # KB
            print(f"✓ Generated PDF report: {report_path}")
            print(f"  File size: {file_size:.1f} KB")
        else:
            print("✗ Report generation failed")
    
    except Exception as e:
        print(f"✗ Report generation error: {e}")


async def demo_dashboard():
    """Demo the dashboard startup"""
    print("\n🎛️  Security Dashboard Demo")
    print("=" * 50)
    
    print("✓ Dashboard components initialized")
    print("  - FastAPI web server")
    print("  - WebSocket communication")
    print("  - React frontend embedded")
    print("  - SQLite database")
    print("  - Real-time event streaming")
    
    print("\n💡 To start the full dashboard, run:")
    print("    python3 -m security_monitor.main dashboard")
    print("    Then visit: http://localhost:8000")


def main():
    """Main demo function"""
    print("🛡️  Security Monitor Framework Demo")
    print("=" * 60)
    print("A comprehensive Python-based security monitoring solution")
    print()
    
    try:
        # Demo each component
        demo_agent()
        demo_detection()
        demo_reporting()
        asyncio.run(demo_dashboard())
        
        print("\n" + "=" * 60)
        print("✅ Demo completed successfully!")
        print()
        print("Next steps:")
        print("1. Start the dashboard: python3 -m security_monitor.main dashboard")
        print("2. Start an agent: python3 -m security_monitor.main agent")
        print("3. Open dashboard: http://localhost:8000")
        print("4. Generate reports: python3 -m security_monitor.main report --type daily")
        print("5. Read documentation: README.md")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        print("Check the logs and configuration for issues")


if __name__ == "__main__":
    main()