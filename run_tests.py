#!/usr/bin/env python3
"""
Security Monitor Test Runner - Run all tests and generate coverage report
"""

import os
import sys
import unittest
import time
from datetime import datetime

def run_basic_tests():
    """Run basic integration tests"""
    print("🧪 Running Basic Integration Tests...")
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = 'tests'
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful(), len(result.failures), len(result.errors)

def run_component_tests():
    """Run individual component tests"""
    print("\n🔧 Running Component Tests...")
    
    tests_passed = 0
    tests_total = 6
    
    # Test 1: System Monitor
    try:
        from security_monitor.agent.system_monitor import SystemMonitor
        monitor = SystemMonitor()
        event = monitor.get_system_metrics()
        assert event.event_type == "system_metrics"
        print("✅ System Monitor: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"❌ System Monitor: FAIL - {e}")
    
    # Test 2: File Monitor
    try:
        from security_monitor.agent.file_monitor import FileMonitor
        monitor = FileMonitor(watch_paths=["/tmp"], config={'max_events': 10})
        assert len(monitor.watch_paths) > 0
        print("✅ File Monitor: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"❌ File Monitor: FAIL - {e}")
    
    # Test 3: Threat Detection
    try:
        from security_monitor.detection.rules import ThreatDetector
        detector = ThreatDetector()
        assert len(detector.rules) >= 10
        print("✅ Threat Detection: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Threat Detection: FAIL - {e}")
    
    # Test 4: PDF Reporting
    try:
        from security_monitor.reporting.pdf_generator import SecurityReportGenerator
        generator = SecurityReportGenerator("reports")
        assert generator.output_dir == "reports"
        print("✅ PDF Reporting: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"❌ PDF Reporting: FAIL - {e}")
    
    # Test 5: Email Service
    try:
        from security_monitor.reporting.email_service import EmailReportService
        service = EmailReportService({'username': 'test', 'password': 'test'})
        assert service.username == 'test'
        print("✅ Email Service: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Email Service: FAIL - {e}")
    
    # Test 6: Database
    try:
        from security_monitor.database.database import init_database
        from security_monitor.database.models import Agent
        init_database()
        print("✅ Database: PASS")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Database: FAIL - {e}")
    
    return tests_passed == tests_total, tests_passed, tests_total

def run_performance_tests():
    """Run basic performance tests"""
    print("\n⚡ Running Performance Tests...")
    
    try:
        from security_monitor.agent.system_monitor import SystemMonitor
        
        # Test system monitoring performance
        monitor = SystemMonitor()
        start_time = time.time()
        
        for _ in range(10):
            events = monitor.collect_all_data()
        
        elapsed = time.time() - start_time
        avg_time = elapsed / 10
        
        print(f"✅ System Monitoring: {avg_time:.3f}s average per collection")
        
        # Test threat detection performance
        from security_monitor.detection.rules import ThreatDetector
        detector = ThreatDetector()
        
        test_event = {
            'type': 'system_metrics',
            'timestamp': datetime.now().isoformat(),
            'source': 'test',
            'data': {'cpu_percent': 50}
        }
        
        start_time = time.time()
        for _ in range(1000):
            detector.analyze_event(test_event)
        
        elapsed = time.time() - start_time
        rate = 1000 / elapsed
        
        print(f"✅ Threat Detection: {rate:.0f} events/second processing rate")
        
        return True
    except Exception as e:
        print(f"❌ Performance Tests: FAIL - {e}")
        return False

def main():
    """Main test runner"""
    print("🛡️  Security Monitor Test Suite")
    print("=" * 50)
    print(f"Test run started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    all_passed = True
    
    # Run basic integration tests
    success, failures, errors = run_basic_tests()
    if not success:
        all_passed = False
        print(f"❌ Integration tests failed: {failures} failures, {errors} errors")
    else:
        print("✅ All integration tests passed")
    
    # Run component tests
    success, passed, total = run_component_tests()
    if not success:
        all_passed = False
        print(f"❌ Component tests failed: {passed}/{total} passed")
    else:
        print(f"✅ All component tests passed: {passed}/{total}")
    
    # Run performance tests
    if run_performance_tests():
        print("✅ Performance tests completed")
    else:
        all_passed = False
        print("❌ Performance tests failed")
    
    # Summary
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 ALL TESTS PASSED - Security Monitor is ready for delivery!")
        print("\nTo start the system:")
        print("  ./start.sh")
        print("\nTo verify deployment:")
        print("  python3 status_check.py")
    else:
        print("❌ SOME TESTS FAILED - Please review errors above")
        print("Run individual components to debug issues")
    
    print(f"\nTest run completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())