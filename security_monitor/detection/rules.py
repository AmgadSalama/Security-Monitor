import re
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ThreatRule:
    name: str
    description: str
    event_types: List[str]
    conditions: Dict[str, Any]
    severity: str
    threat_type: str
    enabled: bool = True


@dataclass
class ThreatResult:
    rule_name: str
    threat_type: str
    severity: str
    confidence: float
    description: str
    indicators: List[str]


class ThreatDetector:
    def __init__(self, rules_config: Dict[str, Any] = None):
        self.logger = logging.getLogger("security_monitor.detection")
        self.rules: List[ThreatRule] = []
        self.event_history: List[Dict] = []
        self.max_history = 1000
        
        # Load default rules
        self._load_default_rules()
        
        # Load custom rules if provided
        if rules_config:
            self._load_custom_rules(rules_config)
    
    def _load_default_rules(self):
        default_rules = [
            # System-based threats
            ThreatRule(
                name="high_cpu_usage",
                description="Sustained high CPU usage indicating potential crypto mining or DoS",
                event_types=["system_metrics"],
                conditions={
                    "data.cpu_percent": {"operator": ">", "value": 90},
                    "duration_check": True
                },
                severity="warning",
                threat_type="resource_abuse"
            ),
            
            ThreatRule(
                name="memory_exhaustion",
                description="Memory exhaustion attack or memory leak",
                event_types=["system_metrics"],
                conditions={
                    "data.memory_percent": {"operator": ">", "value": 95}
                },
                severity="critical",
                threat_type="resource_abuse"
            ),
            
            ThreatRule(
                name="suspicious_network_activity",
                description="High network traffic indicating data exfiltration",
                event_types=["system_metrics"],
                conditions={
                    "data.network_bytes_sent": {"operator": ">", "value": 100000000}  # 100MB
                },
                severity="warning",
                threat_type="data_exfiltration"
            ),
            
            # File-based threats
            ThreatRule(
                name="suspicious_file_creation",
                description="Creation of executable files in suspicious locations",
                event_types=["file_created"],
                conditions={
                    "data.file_path": {"operator": "regex", "value": r".*\.(exe|bat|cmd|scr|pif|com|vbs|js)$"},
                    "data.file_path": {"operator": "contains_any", "value": ["/tmp", "/var/tmp", "\\Temp", "Downloads"]}
                },
                severity="warning",
                threat_type="malware"
            ),
            
            ThreatRule(
                name="system_file_modification",
                description="Modification of critical system files",
                event_types=["file_modified"],
                conditions={
                    "data.file_path": {"operator": "contains_any", "value": [
                        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
                        "\\Windows\\System32", "\\Windows\\SysWOW64"
                    ]}
                },
                severity="critical",
                threat_type="system_tampering"
            ),
            
            ThreatRule(
                name="large_file_operations",
                description="Large file operations indicating potential data theft",
                event_types=["file_created", "file_modified"],
                conditions={
                    "data.file_size": {"operator": ">", "value": 500000000}  # 500MB
                },
                severity="warning",
                threat_type="data_exfiltration"
            ),
            
            # Process-based threats
            ThreatRule(
                name="suspicious_process_names",
                description="Processes with suspicious names indicating malware",
                event_types=["process_list"],
                conditions={
                    "data.processes": {"operator": "process_name_regex", "value": r".*(miner|bot|trojan|keylog|backdoor).*"}
                },
                severity="critical",
                threat_type="malware"
            ),
            
            ThreatRule(
                name="high_cpu_processes",
                description="Processes consuming excessive CPU resources",
                event_types=["process_list"],
                conditions={
                    "data.processes": {"operator": "process_cpu", "value": 80.0}
                },
                severity="warning",
                threat_type="resource_abuse"
            ),
            
            # Network-based threats
            ThreatRule(
                name="suspicious_network_connections",
                description="Connections to suspicious ports or IPs",
                event_types=["network_connections"],
                conditions={
                    "data.connections": {"operator": "suspicious_ports", "value": [4444, 5555, 6666, 31337, 12345]}
                },
                severity="warning",
                threat_type="command_control"
            ),
            
            ThreatRule(
                name="multiple_failed_connections",
                description="Multiple failed connection attempts indicating brute force",
                event_types=["network_connections"],
                conditions={
                    "pattern_check": "failed_connections",
                    "threshold": 10,
                    "time_window": 300  # 5 minutes
                },
                severity="warning",
                threat_type="brute_force"
            )
        ]
        
        self.rules.extend(default_rules)
        self.logger.info(f"Loaded {len(default_rules)} default threat detection rules")
    
    def _load_custom_rules(self, rules_config: Dict[str, Any]):
        try:
            custom_rules = rules_config.get('custom_rules', [])
            for rule_data in custom_rules:
                rule = ThreatRule(**rule_data)
                self.rules.append(rule)
            
            self.logger.info(f"Loaded {len(custom_rules)} custom threat detection rules")
        except Exception as e:
            self.logger.error(f"Error loading custom rules: {e}")
    
    def analyze_event(self, event: Dict[str, Any]) -> Optional[ThreatResult]:
        # Add event to history
        self.event_history.append({
            **event,
            'analyzed_at': datetime.now()
        })
        
        # Trim history if needed
        if len(self.event_history) > self.max_history:
            self.event_history = self.event_history[-self.max_history:]
        
        # Check each rule
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if event['type'] in rule.event_types:
                result = self._evaluate_rule(rule, event)
                if result:
                    self.logger.warning(f"Threat detected: {result.rule_name} - {result.description}")
                    return result
        
        return None
    
    def _evaluate_rule(self, rule: ThreatRule, event: Dict[str, Any]) -> Optional[ThreatResult]:
        try:
            conditions_met = 0
            total_conditions = len(rule.conditions)
            indicators = []
            
            for condition_path, condition_spec in rule.conditions.items():
                if condition_path == "duration_check":
                    # Special duration-based check
                    if self._check_duration_condition(event, rule):
                        conditions_met += 1
                        indicators.append("Sustained condition detected")
                
                elif condition_path == "pattern_check":
                    # Special pattern-based check
                    if self._check_pattern_condition(event, rule, condition_spec):
                        conditions_met += 1
                        indicators.append(f"Pattern detected: {condition_spec}")
                
                else:
                    # Standard field-based check
                    if self._check_field_condition(event, condition_path, condition_spec):
                        conditions_met += 1
                        indicators.append(f"{condition_path}: {condition_spec}")
            
            # Calculate confidence based on conditions met
            confidence = conditions_met / total_conditions if total_conditions > 0 else 0
            
            # Rule triggers if confidence >= 0.8 (80% of conditions met)
            if confidence >= 0.8:
                return ThreatResult(
                    rule_name=rule.name,
                    threat_type=rule.threat_type,
                    severity=rule.severity,
                    confidence=confidence,
                    description=rule.description,
                    indicators=indicators
                )
            
        except Exception as e:
            self.logger.error(f"Error evaluating rule {rule.name}: {e}")
        
        return None
    
    def _check_field_condition(self, event: Dict[str, Any], field_path: str, condition: Dict[str, Any]) -> bool:
        try:
            # Navigate nested dictionary path
            value = event
            for key in field_path.split('.'):
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return False
            
            operator = condition.get('operator')
            expected = condition.get('value')
            
            if operator == '>':
                return isinstance(value, (int, float)) and value > expected
            elif operator == '<':
                return isinstance(value, (int, float)) and value < expected
            elif operator == '>=':
                return isinstance(value, (int, float)) and value >= expected
            elif operator == '<=':
                return isinstance(value, (int, float)) and value <= expected
            elif operator == '==':
                return value == expected
            elif operator == '!=':
                return value != expected
            elif operator == 'contains':
                return isinstance(value, str) and expected in value
            elif operator == 'contains_any':
                return isinstance(value, str) and any(item in value for item in expected)
            elif operator == 'regex':
                return isinstance(value, str) and re.search(expected, value, re.IGNORECASE)
            elif operator == 'process_name_regex':
                return self._check_process_names(value, expected)
            elif operator == 'process_cpu':
                return self._check_process_cpu(value, expected)
            elif operator == 'suspicious_ports':
                return self._check_suspicious_ports(value, expected)
            
        except Exception as e:
            self.logger.debug(f"Error checking field condition {field_path}: {e}")
        
        return False
    
    def _check_process_names(self, processes: List[Dict], pattern: str) -> bool:
        if not isinstance(processes, list):
            return False
        
        for process in processes:
            if isinstance(process, dict) and 'name' in process:
                if re.search(pattern, process['name'], re.IGNORECASE):
                    return True
        return False
    
    def _check_process_cpu(self, processes: List[Dict], threshold: float) -> bool:
        if not isinstance(processes, list):
            return False
        
        for process in processes:
            if isinstance(process, dict) and 'cpu_percent' in process:
                if process['cpu_percent'] > threshold:
                    return True
        return False
    
    def _check_suspicious_ports(self, connections: List[Dict], suspicious_ports: List[int]) -> bool:
        if not isinstance(connections, list):
            return False
        
        for conn in connections:
            if isinstance(conn, dict) and 'remote_addr' in conn and conn['remote_addr']:
                try:
                    port = int(conn['remote_addr'].split(':')[-1])
                    if port in suspicious_ports:
                        return True
                except (ValueError, IndexError):
                    continue
        return False
    
    def _check_duration_condition(self, event: Dict[str, Any], rule: ThreatRule) -> bool:
        # Check if similar events occurred in the last 5 minutes
        current_time = datetime.now()
        threshold_time = current_time - timedelta(minutes=5)
        
        similar_events = 0
        for hist_event in self.event_history:
            if (hist_event.get('analyzed_at', current_time) >= threshold_time and
                hist_event.get('type') == event.get('type')):
                # Check if this historical event would also trigger the rule
                temp_result = self._evaluate_simple_conditions(rule, hist_event)
                if temp_result:
                    similar_events += 1
        
        return similar_events >= 3  # At least 3 similar events in 5 minutes
    
    def _check_pattern_condition(self, event: Dict[str, Any], rule: ThreatRule, pattern_type: str) -> bool:
        if pattern_type == "failed_connections":
            # Count failed connection attempts in the time window
            threshold = rule.conditions.get('threshold', 10)
            time_window = rule.conditions.get('time_window', 300)  # seconds
            
            current_time = datetime.now()
            threshold_time = current_time - timedelta(seconds=time_window)
            
            failed_attempts = 0
            for hist_event in self.event_history:
                if (hist_event.get('analyzed_at', current_time) >= threshold_time and
                    'failed' in hist_event.get('type', '').lower()):
                    failed_attempts += 1
            
            return failed_attempts >= threshold
        
        return False
    
    def _evaluate_simple_conditions(self, rule: ThreatRule, event: Dict[str, Any]) -> bool:
        # Simple evaluation without duration/pattern checks
        for condition_path, condition_spec in rule.conditions.items():
            if condition_path in ["duration_check", "pattern_check", "threshold", "time_window"]:
                continue
            
            if not self._check_field_condition(event, condition_path, condition_spec):
                return False
        
        return True
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        current_time = datetime.now()
        last_24h = current_time - timedelta(hours=24)
        
        threats_24h = []
        for hist_event in self.event_history:
            if hist_event.get('analyzed_at', current_time) >= last_24h:
                # Re-analyze to see if it was a threat
                for rule in self.rules:
                    if hist_event.get('type') in rule.event_types:
                        result = self._evaluate_rule(rule, hist_event)
                        if result:
                            threats_24h.append(result)
                            break
        
        # Count by severity and threat type
        severity_counts = {"critical": 0, "warning": 0, "info": 0}
        threat_type_counts = {}
        
        for threat in threats_24h:
            severity_counts[threat.severity] = severity_counts.get(threat.severity, 0) + 1
            threat_type_counts[threat.threat_type] = threat_type_counts.get(threat.threat_type, 0) + 1
        
        return {
            "total_threats_24h": len(threats_24h),
            "severity_distribution": severity_counts,
            "threat_type_distribution": threat_type_counts,
            "active_rules": len([r for r in self.rules if r.enabled]),
            "total_rules": len(self.rules)
        }
    
    def add_custom_rule(self, rule: ThreatRule):
        self.rules.append(rule)
        self.logger.info(f"Added custom rule: {rule.name}")
    
    def disable_rule(self, rule_name: str) -> bool:
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = False
                self.logger.info(f"Disabled rule: {rule_name}")
                return True
        return False
    
    def enable_rule(self, rule_name: str) -> bool:
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = True
                self.logger.info(f"Enabled rule: {rule_name}")
                return True
        return False
    
    def get_rules_status(self) -> List[Dict[str, Any]]:
        return [{
            "name": rule.name,
            "description": rule.description,
            "event_types": rule.event_types,
            "severity": rule.severity,
            "threat_type": rule.threat_type,
            "enabled": rule.enabled
        } for rule in self.rules]