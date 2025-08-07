import os
import time
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Set, Any
from dataclasses import dataclass, asdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path


@dataclass
class FileEvent:
    timestamp: str
    event_type: str
    file_path: str
    file_size: int = 0
    file_hash: str = ""
    severity: str = "info"
    additional_data: Dict[str, Any] = None


class SecurityFileHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        self.logger = logging.getLogger("security_monitor.file_monitor")
        
    def on_modified(self, event):
        if not event.is_directory:
            self.callback(self._create_file_event("modified", event.src_path))
    
    def on_created(self, event):
        if not event.is_directory:
            self.callback(self._create_file_event("created", event.src_path))
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.callback(self._create_file_event("deleted", event.src_path))
    
    def on_moved(self, event):
        if not event.is_directory:
            self.callback(self._create_file_event("moved", event.dest_path, 
                                                additional_data={"old_path": event.src_path}))
    
    def _create_file_event(self, event_type: str, file_path: str, additional_data: Dict = None) -> FileEvent:
        file_size = 0
        file_hash = ""
        
        try:
            if os.path.exists(file_path) and event_type != "deleted":
                stat_info = os.stat(file_path)
                file_size = stat_info.st_size
                
                # Calculate hash for small files only
                if file_size < 10 * 1024 * 1024:  # 10MB limit
                    file_hash = self._calculate_file_hash(file_path)
        except (OSError, IOError) as e:
            self.logger.warning(f"Could not get file info for {file_path}: {e}")
        
        severity = self._determine_severity(event_type, file_path, file_size)
        
        return FileEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            file_path=file_path,
            file_size=file_size,
            file_hash=file_hash,
            severity=severity,
            additional_data=additional_data or {}
        )
    
    def _calculate_file_hash(self, file_path: str) -> str:
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except (OSError, IOError):
            return ""
    
    def _determine_severity(self, event_type: str, file_path: str, file_size: int) -> str:
        # Check for suspicious file extensions
        suspicious_extensions = {'.exe', '.bat', '.cmd', '.scr', '.pif', '.com', 
                               '.vbs', '.js', '.jar', '.sh', '.php'}
        file_ext = Path(file_path).suffix.lower()
        
        # Check for sensitive directories
        sensitive_dirs = {'/etc', '/var/log', '/home', '/root', '/tmp', 
                         '/System', '/Library', '/Applications'}
        
        if any(sens_dir in file_path for sens_dir in sensitive_dirs):
            if event_type in ['created', 'modified']:
                return "warning"
        
        if file_ext in suspicious_extensions:
            if event_type == "created":
                return "warning"
        
        # Large file operations
        if file_size > 100 * 1024 * 1024:  # 100MB
            return "warning"
        
        return "info"


class FileMonitor:
    def __init__(self, watch_paths: List[str] = None, config: Dict[str, Any] = None):
        self.config = config or {}
        self.watch_paths = watch_paths or self._get_default_watch_paths()
        self.logger = self._setup_logger()
        self.observer = Observer()
        self.events = []
        self.max_events = self.config.get('max_events', 1000)
        
        # Setup file handler
        self.file_handler = SecurityFileHandler(self._handle_file_event)
        
        # Setup observers for each watch path
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.file_handler, path, recursive=True)
                self.logger.info(f"Watching directory: {path}")
            else:
                self.logger.warning(f"Watch path does not exist: {path}")
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("security_monitor.file_monitor")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def _get_default_watch_paths(self) -> List[str]:
        import platform
        system = platform.system().lower()
        
        if system == "linux" or system == "darwin":
            return [
                "/tmp",
                "/var/log",
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop")
            ]
        elif system == "windows":
            return [
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Desktop"),
                "C:\\temp"
            ]
        else:
            return [os.path.expanduser("~")]
    
    def _handle_file_event(self, event: FileEvent):
        self.events.append(event)
        
        # Rotate events if we exceed max
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
        
        # Log high severity events
        if event.severity in ['warning', 'critical']:
            self.logger.warning(f"Security event: {event.event_type} - {event.file_path}")
    
    def start_monitoring(self):
        self.observer.start()
        self.logger.info("File monitoring started")
    
    def stop_monitoring(self):
        self.observer.stop()
        self.observer.join()
        self.logger.info("File monitoring stopped")
    
    def get_recent_events(self, limit: int = 100) -> List[FileEvent]:
        return self.events[-limit:] if self.events else []
    
    def get_events_by_severity(self, severity: str) -> List[FileEvent]:
        return [event for event in self.events if event.severity == severity]
    
    def clear_events(self):
        self.events.clear()
        self.logger.info("File events cleared")
    
    def scan_directory(self, directory: str) -> List[FileEvent]:
        scan_events = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat_info = os.stat(file_path)
                        
                        event = FileEvent(
                            timestamp=datetime.now().isoformat(),
                            event_type="scan",
                            file_path=file_path,
                            file_size=stat_info.st_size,
                            file_hash=self.file_handler._calculate_file_hash(file_path) if stat_info.st_size < 10*1024*1024 else "",
                            severity="info"
                        )
                        scan_events.append(event)
                        
                    except (OSError, IOError) as e:
                        self.logger.warning(f"Could not scan file {file_path}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
        
        return scan_events
    
    def check_file_integrity(self, file_paths: List[str]) -> List[FileEvent]:
        integrity_events = []
        
        for file_path in file_paths:
            if not os.path.exists(file_path):
                event = FileEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="integrity_check_failed",
                    file_path=file_path,
                    severity="critical",
                    additional_data={"reason": "file_not_found"}
                )
                integrity_events.append(event)
                continue
            
            try:
                stat_info = os.stat(file_path)
                current_hash = self.file_handler._calculate_file_hash(file_path)
                
                event = FileEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="integrity_check",
                    file_path=file_path,
                    file_size=stat_info.st_size,
                    file_hash=current_hash,
                    severity="info"
                )
                integrity_events.append(event)
                
            except Exception as e:
                event = FileEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="integrity_check_failed",
                    file_path=file_path,
                    severity="warning",
                    additional_data={"reason": str(e)}
                )
                integrity_events.append(event)
        
        return integrity_events