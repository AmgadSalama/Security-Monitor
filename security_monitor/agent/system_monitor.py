import psutil
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass, asdict


@dataclass
class SystemEvent:
    timestamp: str
    event_type: str
    source: str
    data: Dict[str, Any]
    severity: str = "info"


class SystemMonitor:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = self._setup_logger()
        self.baseline_metrics = self._get_baseline_metrics()
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("security_monitor.agent")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    def _get_baseline_metrics(self) -> Dict[str, Any]:
        return {
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'boot_time': psutil.boot_time(),
            'network_interfaces': list(psutil.net_if_addrs().keys())
        }
    
    def get_system_metrics(self) -> SystemEvent:
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            metrics = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used': memory.used,
                'memory_available': memory.available,
                'disk_percent': (disk.used / disk.total) * 100,
                'disk_free': disk.free,
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv,
                'network_packets_sent': network.packets_sent,
                'network_packets_recv': network.packets_recv
            }
            
            severity = self._determine_severity(metrics)
            
            return SystemEvent(
                timestamp=datetime.now().isoformat(),
                event_type="system_metrics",
                source="system_monitor",
                data=metrics,
                severity=severity
            )
            
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return SystemEvent(
                timestamp=datetime.now().isoformat(),
                event_type="error",
                source="system_monitor",
                data={"error": str(e)},
                severity="error"
            )
    
    def get_running_processes(self) -> SystemEvent:
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    process_info = proc.info
                    cpu_percent = process_info.get('cpu_percent') or 0
                    memory_percent = process_info.get('memory_percent') or 0
                    if cpu_percent > 0 or memory_percent > 1.0:
                        processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            top_processes = processes[:20]  # Top 20 processes
            
            return SystemEvent(
                timestamp=datetime.now().isoformat(),
                event_type="process_list",
                source="system_monitor",
                data={"processes": top_processes},
                severity="info"
            )
            
        except Exception as e:
            self.logger.error(f"Error collecting process information: {e}")
            return SystemEvent(
                timestamp=datetime.now().isoformat(),
                event_type="error",
                source="system_monitor",
                data={"error": str(e)},
                severity="error"
            )
    
    def get_network_connections(self) -> SystemEvent:
        try:
            connections = []
            # Try to get network connections, handle permission errors
            try:
                net_connections = psutil.net_connections(kind='inet')
            except (psutil.AccessDenied, PermissionError):
                # Fallback to process-level connections
                net_connections = []
                for proc in psutil.process_iter(['pid']):
                    try:
                        for conn in proc.connections(kind='inet'):
                            net_connections.append(conn)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError):
                        continue
            
            for conn in net_connections:
                if conn.status == psutil.CONN_ESTABLISHED:
                    conn_info = {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': getattr(conn, 'pid', None)
                    }
                    
                    # Try to get process name if PID is available
                    pid = getattr(conn, 'pid', None)
                    if pid:
                        try:
                            process = psutil.Process(pid)
                            conn_info['process_name'] = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            conn_info['process_name'] = 'Unknown'
                    else:
                        conn_info['process_name'] = 'Unknown'
                    
                    connections.append(conn_info)
            
            return SystemEvent(
                timestamp=datetime.now().isoformat(),
                event_type="network_connections",
                source="system_monitor",
                data={"connections": connections},
                severity="info"
            )
            
        except Exception as e:
            self.logger.error(f"Error collecting network connections: {e}")
            return SystemEvent(
                timestamp=datetime.now().isoformat(),
                event_type="error",
                source="system_monitor",
                data={"error": str(e)},
                severity="error"
            )
    
    def get_security_events(self) -> List[SystemEvent]:
        events = []
        
        # Check for suspicious CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 90:
            events.append(SystemEvent(
                timestamp=datetime.now().isoformat(),
                event_type="high_cpu_usage",
                source="security_monitor",
                data={"cpu_percent": cpu_percent},
                severity="warning"
            ))
        
        # Check for suspicious memory usage
        memory = psutil.virtual_memory()
        if memory.percent > 85:
            events.append(SystemEvent(
                timestamp=datetime.now().isoformat(),
                event_type="high_memory_usage",
                source="security_monitor",
                data={"memory_percent": memory.percent},
                severity="warning"
            ))
        
        # Check for unusual network activity
        network = psutil.net_io_counters()
        if hasattr(self, '_last_network_check'):
            time_diff = time.time() - self._last_network_check['time']
            bytes_diff = network.bytes_sent - self._last_network_check['bytes_sent']
            if time_diff > 0 and (bytes_diff / time_diff) > 100000000:  # 100MB/s
                events.append(SystemEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="high_network_activity",
                    source="security_monitor",
                    data={"bytes_per_second": bytes_diff / time_diff},
                    severity="warning"
                ))
        
        self._last_network_check = {
            'time': time.time(),
            'bytes_sent': network.bytes_sent
        }
        
        return events
    
    def _determine_severity(self, metrics: Dict[str, Any]) -> str:
        if metrics['cpu_percent'] > 90 or metrics['memory_percent'] > 85:
            return "warning"
        elif metrics['cpu_percent'] > 95 or metrics['memory_percent'] > 95:
            return "critical"
        return "info"
    
    def collect_all_data(self) -> List[SystemEvent]:
        events = []
        
        # Collect basic system metrics
        events.append(self.get_system_metrics())
        
        # Collect process information
        events.append(self.get_running_processes())
        
        # Collect network connections
        events.append(self.get_network_connections())
        
        # Collect security events
        events.extend(self.get_security_events())
        
        return events