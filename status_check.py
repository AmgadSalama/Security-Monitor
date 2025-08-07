#!/usr/bin/env python3
"""
Security Monitor Status Check - Verify all components are working correctly
"""

import sys
import os
import json
from datetime import datetime

def test_imports():
    """Test that all modules can be imported"""
    print("🔧 Testing Module Imports...")
    
    try:
        from security_monitor.agent.system_monitor import SystemMonitor
        from security_monitor.agent.file_monitor import FileMonitor
        from security_monitor.detection.rules import ThreatDetector
        from security_monitor.reporting.pdf_generator import SecurityReportGenerator
        from security_monitor.reporting.email_service import EmailReportService
        from security_monitor.database.database import init_database
        from security_monitor.utils.config import load_config
        print("✅ All modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_system_monitoring():
    """Test system monitoring functionality"""
    print("\n🖥️  Testing System Monitoring...")
    
    try:
        from security_monitor.agent.system_monitor import SystemMonitor
        
        monitor = SystemMonitor()
        
        # Test system metrics
        metrics_event = monitor.get_system_metrics()
        if metrics_event.event_type == "system_metrics":
            print("✅ System metrics collection working")
        else:
            print("❌ System metrics collection failed")
            return False
        
        # Test process monitoring
        process_event = monitor.get_running_processes()
        if process_event.event_type == "process_list":
            print("✅ Process monitoring working")
        else:
            print("❌ Process monitoring failed")
            return False
        
        # Test network monitoring
        network_event = monitor.get_network_connections()
        if network_event.event_type == "network_connections":
            print("✅ Network monitoring working")
        else:
            print("❌ Network monitoring failed")
            return False
        
        return True
    
    except Exception as e:
        print(f"❌ System monitoring error: {e}")
        return False

def test_threat_detection():
    """Test threat detection functionality"""
    print("\n🚨 Testing Threat Detection...")
    
    try:
        from security_monitor.detection.rules import ThreatDetector
        
        detector = ThreatDetector()
        
        if len(detector.rules) > 0:
            print(f"✅ Loaded {len(detector.rules)} threat detection rules")
        else:
            print("❌ No threat detection rules loaded")
            return False
        
        # Test with a sample threat event
        test_event = {
            'type': 'file_created',
            'timestamp': datetime.now().isoformat(),
            'source': 'test',
            'data': {'file_path': '/tmp/malware.exe', 'file_size': 1000000}
        }
        
        result = detector.analyze_event(test_event)
        if result and result.threat_type == 'malware':
            print("✅ Threat detection working correctly")
            return True
        else:
            print("❌ Threat detection not working as expected")
            return False
    
    except Exception as e:
        print(f"❌ Threat detection error: {e}")
        return False

def test_reporting():
    """Test reporting functionality"""
    print("\n📊 Testing Reporting System...")
    
    try:
        from security_monitor.reporting.pdf_generator import SecurityReportGenerator
        
        generator = SecurityReportGenerator("reports")
        
        # Create sample data
        sample_data = {
            'period': {
                'start': '2024-01-01 00:00:00',
                'end': '2024-01-02 00:00:00'
            },
            'stats': {
                'total_events': 10,
                'critical_events': 1,
                'warning_events': 3,
                'active_agents': 1
            },
            'events': [
                {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'test_event',
                    'source': 'test',
                    'severity': 'info',
                    'data': {}
                }
            ],
            'threats': [],
            'agents': [
                {
                    'agent_id': 'test-agent',
                    'hostname': 'test-host',
                    'status': 'online'
                }
            ]
        }
        
        report_path = generator.generate_security_report(sample_data, "test")
        
        if os.path.exists(report_path):
            file_size = os.path.getsize(report_path) / 1024
            print(f"✅ PDF report generated: {file_size:.1f} KB")
            return True
        else:
            print("❌ PDF report generation failed")
            return False
    
    except Exception as e:
        print(f"❌ Reporting error: {e}")
        return False

def test_database():
    """Test database functionality"""
    print("\n🗄️  Testing Database...")
    
    try:
        from security_monitor.database.database import init_database
        from security_monitor.database.models import SecurityEvent, Agent
        from security_monitor.database.database import SessionLocal
        
        # Initialize database
        init_database()
        print("✅ Database initialized successfully")
        
        # Test database connection
        db = SessionLocal()
        try:
            agents_count = db.query(Agent).count()
            events_count = db.query(SecurityEvent).count()
            print(f"✅ Database connection working (Agents: {agents_count}, Events: {events_count})")
            return True
        finally:
            db.close()
    
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def test_configuration():
    """Test configuration loading"""
    print("\n⚙️  Testing Configuration...")
    
    try:
        from security_monitor.utils.config import load_config
        
        config = load_config("config/security_monitor.json")
        
        if config and 'agent' in config and 'server' in config:
            print("✅ Configuration loaded successfully")
            return True
        else:
            print("❌ Configuration loading failed")
            return False
    
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

def main():
    """Run all status checks"""
    print("🛡️  Security Monitor Framework Status Check")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_imports),
        ("System Monitoring", test_system_monitoring),
        ("Threat Detection", test_threat_detection),
        ("Reporting System", test_reporting),
        ("Database", test_database),
        ("Configuration", test_configuration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ {test_name} test failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"📈 Status Check Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All systems operational! Security Monitor is ready to use.")
        print("\nTo start the system:")
        print("  ./start.sh")
        print("\nTo access the dashboard:")
        print("  http://localhost:8000")
    else:
        print(f"⚠️  {total - passed} issues found. Please check the errors above.")
        
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)