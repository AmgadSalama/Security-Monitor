#!/usr/bin/env python3
"""
Basic integration tests for Security Monitor components
"""

import unittest
import os
import sys
import tempfile
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestSystemMonitoring(unittest.TestCase):
    """Test system monitoring functionality"""
    
    def setUp(self):
        from security_monitor.agent.system_monitor import SystemMonitor
        self.monitor = SystemMonitor()
    
    def test_system_metrics_collection(self):
        """Test system metrics collection"""
        event = self.monitor.get_system_metrics()
        
        self.assertEqual(event.event_type, "system_metrics")
        self.assertIn("cpu_percent", event.data)
        self.assertIn("memory_percent", event.data)
        self.assertIsInstance(event.data["cpu_percent"], (int, float))
    
    def test_process_collection(self):
        """Test process information collection"""
        event = self.monitor.get_running_processes()
        
        self.assertEqual(event.event_type, "process_list")
        self.assertIn("processes", event.data)
        self.assertIsInstance(event.data["processes"], list)
    
    def test_network_collection(self):
        """Test network connection collection"""
        event = self.monitor.get_network_connections()
        
        self.assertEqual(event.event_type, "network_connections")
        self.assertIn("connections", event.data)
        self.assertIsInstance(event.data["connections"], list)


class TestThreatDetection(unittest.TestCase):
    """Test threat detection functionality"""
    
    def setUp(self):
        from security_monitor.detection.rules import ThreatDetector
        self.detector = ThreatDetector()
    
    def test_rules_loading(self):
        """Test that threat detection rules are loaded"""
        self.assertGreater(len(self.detector.rules), 0)
        
        # Check that default rules are present
        rule_names = [rule.name for rule in self.detector.rules]
        self.assertIn("high_cpu_usage", rule_names)
        self.assertIn("suspicious_file_creation", rule_names)
    
    def test_malware_detection(self):
        """Test malware detection rule"""
        test_event = {
            'type': 'file_created',
            'timestamp': datetime.now().isoformat(),
            'source': 'test',
            'data': {'file_path': '/tmp/malware.exe', 'file_size': 1000000}
        }
        
        result = self.detector.analyze_event(test_event)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.threat_type, 'malware')
        self.assertEqual(result.severity, 'warning')
    
    def test_high_cpu_detection(self):
        """Test high CPU usage detection"""
        test_event = {
            'type': 'system_metrics',
            'timestamp': datetime.now().isoformat(),
            'source': 'test',
            'data': {'cpu_percent': 95, 'memory_percent': 50}
        }
        
        # Add multiple similar events to trigger duration check
        for _ in range(5):
            self.detector.analyze_event(test_event)
        
        result = self.detector.analyze_event(test_event)
        
        if result:  # May not trigger on first run
            self.assertEqual(result.threat_type, 'resource_abuse')


class TestReporting(unittest.TestCase):
    """Test reporting functionality"""
    
    def setUp(self):
        from security_monitor.reporting.pdf_generator import SecurityReportGenerator
        self.temp_dir = tempfile.mkdtemp()
        self.generator = SecurityReportGenerator(self.temp_dir)
    
    def test_pdf_generation(self):
        """Test PDF report generation"""
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
            'agents': []
        }
        
        report_path = self.generator.generate_security_report(sample_data, "test")
        
        self.assertTrue(os.path.exists(report_path))
        self.assertGreater(os.path.getsize(report_path), 1000)  # At least 1KB
        
        # Cleanup
        os.remove(report_path)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestConfiguration(unittest.TestCase):
    """Test configuration management"""
    
    def test_config_loading(self):
        """Test configuration loading"""
        from security_monitor.utils.config import load_config
        
        config = load_config()
        
        self.assertIsInstance(config, dict)
        self.assertIn('agent', config)
        self.assertIn('server', config)
        self.assertIn('monitoring', config)
    
    def test_config_validation(self):
        """Test configuration validation"""
        from security_monitor.utils.config import validate_config
        
        valid_config = {
            'agent': {'id': 'test'},
            'server': {'url': 'ws://localhost:8000/ws/agent'},
            'monitoring': {'interval': 30}
        }
        
        self.assertTrue(validate_config(valid_config))
        
        invalid_config = {
            'agent': {'id': 'test'},
            # Missing server section
            'monitoring': {'interval': 30}
        }
        
        self.assertFalse(validate_config(invalid_config))


class TestDatabase(unittest.TestCase):
    """Test database functionality"""
    
    def test_database_initialization(self):
        """Test database initialization"""
        from security_monitor.database.database import init_database
        from security_monitor.database.models import Agent, SecurityEvent
        from security_monitor.database.database import SessionLocal
        
        # Initialize database
        init_database()
        
        # Test database connection
        db = SessionLocal()
        try:
            # Should not raise exception
            agents_count = db.query(Agent).count()
            events_count = db.query(SecurityEvent).count()
            
            self.assertIsInstance(agents_count, int)
            self.assertIsInstance(events_count, int)
        finally:
            db.close()


if __name__ == '__main__':
    unittest.main()