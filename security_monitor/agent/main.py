import asyncio
import json
import time
import logging
import argparse
import websockets
from typing import Dict, Any, List
from datetime import datetime
from .system_monitor import SystemMonitor
from .file_monitor import FileMonitor
from ..utils.config import load_config


class SecurityAgent:
    def __init__(self, config_path: str = None):
        self.config = load_config(config_path)
        self.logger = self._setup_logger()
        self.system_monitor = SystemMonitor(self.config.get('system', {}))
        self.file_monitor = FileMonitor(
            watch_paths=self.config.get('file_monitoring', {}).get('watch_paths'),
            config=self.config.get('file_monitoring', {})
        )
        self.running = False
        self.websocket = None
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("security_monitor.agent")
        logger.setLevel(self.config.get('logging', {}).get('level', 'INFO'))
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
            # Add file handler if configured
            log_file = self.config.get('logging', {}).get('file')
            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
                
        return logger
    
    async def connect_to_server(self):
        server_url = self.config.get('server', {}).get('url', 'ws://localhost:8000/ws/agent')
        max_retries = self.config.get('server', {}).get('max_retries', 5)
        retry_delay = self.config.get('server', {}).get('retry_delay', 5)
        
        for attempt in range(max_retries):
            try:
                self.websocket = await websockets.connect(server_url)
                self.logger.info(f"Connected to server: {server_url}")
                return True
            except Exception as e:
                self.logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
        
        self.logger.error("Failed to connect to server after all retries")
        return False
    
    async def send_events(self, events: List[Dict]):
        if not self.websocket:
            return False
            
        try:
            message = {
                'type': 'security_events',
                'timestamp': datetime.now().isoformat(),
                'agent_id': self.config.get('agent', {}).get('id', 'default'),
                'events': events
            }
            
            await self.websocket.send(json.dumps(message))
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send events: {e}")
            self.websocket = None
            return False
    
    def collect_events(self) -> List[Dict]:
        all_events = []
        
        # Collect system events
        system_events = self.system_monitor.collect_all_data()
        for event in system_events:
            all_events.append({
                'type': event.event_type,
                'timestamp': event.timestamp,
                'source': event.source,
                'data': event.data,
                'severity': event.severity
            })
        
        # Collect file events
        file_events = self.file_monitor.get_recent_events(50)
        for event in file_events:
            all_events.append({
                'type': f"file_{event.event_type}",
                'timestamp': event.timestamp,
                'source': 'file_monitor',
                'data': {
                    'file_path': event.file_path,
                    'file_size': event.file_size,
                    'file_hash': event.file_hash,
                    **(event.additional_data or {})
                },
                'severity': event.severity
            })
        
        return all_events
    
    async def run_monitoring_cycle(self):
        collection_interval = self.config.get('monitoring', {}).get('interval', 30)
        
        while self.running:
            try:
                # Collect events
                events = self.collect_events()
                
                if events:
                    self.logger.info(f"Collected {len(events)} events")
                    
                    # Send events to server if connected
                    if self.websocket:
                        success = await self.send_events(events)
                        if not success:
                            # Try to reconnect
                            await self.connect_to_server()
                    else:
                        # Try to connect if not connected
                        await self.connect_to_server()
                        if self.websocket:
                            await self.send_events(events)
                
                # Clear old file events to prevent memory buildup
                if len(self.file_monitor.events) > 500:
                    self.file_monitor.events = self.file_monitor.events[-250:]
                
                await asyncio.sleep(collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring cycle: {e}")
                await asyncio.sleep(5)
    
    async def start(self):
        self.logger.info("Starting Security Agent...")
        
        # Start file monitoring
        self.file_monitor.start_monitoring()
        
        # Connect to server
        await self.connect_to_server()
        
        # Start monitoring loop
        self.running = True
        await self.run_monitoring_cycle()
    
    def stop(self):
        self.logger.info("Stopping Security Agent...")
        self.running = False
        self.file_monitor.stop_monitoring()
        
        if self.websocket:
            asyncio.create_task(self.websocket.close())


def main():
    parser = argparse.ArgumentParser(description='Security Monitor Agent')
    parser.add_argument('--config', '-c', type=str, help='Configuration file path')
    parser.add_argument('--daemon', '-d', action='store_true', help='Run as daemon')
    parser.add_argument('--scan', '-s', type=str, help='Scan directory for security events')
    parser.add_argument('--test', '-t', action='store_true', help='Run test mode')
    
    args = parser.parse_args()
    
    # Initialize agent
    agent = SecurityAgent(args.config)
    
    if args.scan:
        # Directory scan mode
        print(f"Scanning directory: {args.scan}")
        events = agent.file_monitor.scan_directory(args.scan)
        print(f"Found {len(events)} files")
        
        for event in events:
            if event.severity in ['warning', 'critical']:
                print(f"ALERT: {event.file_path} - {event.severity}")
        
        return
    
    if args.test:
        # Test mode - collect events once and print
        print("Running in test mode...")
        events = agent.collect_events()
        print(f"Collected {len(events)} events:")
        
        for event in events:
            print(f"  {event['timestamp']} - {event['type']} - {event['severity']}")
        
        return
    
    # Normal operation mode
    try:
        if args.daemon:
            # In a real implementation, you would daemonize the process here
            agent.logger.info("Running in daemon mode")
        
        asyncio.run(agent.start())
        
    except KeyboardInterrupt:
        print("\nShutting down...")
        agent.stop()
    except Exception as e:
        agent.logger.error(f"Fatal error: {e}")
        agent.stop()


if __name__ == '__main__':
    main()