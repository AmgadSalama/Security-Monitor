#!/usr/bin/env python3
"""
Security Monitor - Main application entry point
"""

import asyncio
import argparse
import logging
import sys
import os
import json
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from security_monitor.dashboard.app import app
from security_monitor.database.database import init_database
from security_monitor.utils.config import load_config, create_default_config_file, get_config_template
import uvicorn


def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Setup logging configuration"""
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


def main():
    parser = argparse.ArgumentParser(
        description='Security Monitor - Comprehensive security monitoring framework'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Start the web dashboard')
    dashboard_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    dashboard_parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    dashboard_parser.add_argument('--config', '-c', help='Configuration file path')
    dashboard_parser.add_argument('--reload', action='store_true', help='Enable auto-reload')
    
    # Agent command
    agent_parser = subparsers.add_parser('agent', help='Start the monitoring agent')
    agent_parser.add_argument('--config', '-c', help='Configuration file path')
    agent_parser.add_argument('--daemon', '-d', action='store_true', help='Run as daemon')
    
    # Database command
    db_parser = subparsers.add_parser('database', help='Database operations')
    db_parser.add_argument('action', choices=['init', 'reset'], help='Database action')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('action', choices=['create', 'validate', 'show'], 
                              help='Configuration action')
    config_parser.add_argument('--file', '-f', help='Configuration file path')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate reports')
    report_parser.add_argument('--type', choices=['daily', 'weekly', 'monthly'], 
                              default='daily', help='Report type')
    report_parser.add_argument('--output', '-o', help='Output directory')
    report_parser.add_argument('--email', action='store_true', help='Send via email')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Load configuration
    config_path = getattr(args, 'config', None)
    config = load_config(config_path)
    
    # Setup logging
    log_config = config.get('logging', {})
    setup_logging(log_config.get('level', 'INFO'), log_config.get('file'))
    
    logger = logging.getLogger('security_monitor.main')
    
    try:
        if args.command == 'dashboard':
            logger.info("Starting Security Monitor Dashboard...")
            
            # Initialize database
            init_database()
            
            # Start dashboard
            uvicorn.run(
                "security_monitor.dashboard.app:app",
                host=args.host,
                port=args.port,
                reload=args.reload,
                log_level=log_config.get('level', 'info').lower()
            )
        
        elif args.command == 'agent':
            logger.info("Starting Security Monitor Agent...")
            
            from security_monitor.agent.main import SecurityAgent
            
            agent = SecurityAgent(config_path)
            
            if args.daemon:
                logger.info("Running in daemon mode")
                # In a production environment, you would implement proper daemonization
            
            try:
                asyncio.run(agent.start())
            except KeyboardInterrupt:
                logger.info("Agent shutdown requested")
                agent.stop()
        
        elif args.command == 'database':
            if args.action == 'init':
                logger.info("Initializing database...")
                init_database()
                logger.info("Database initialized successfully")
            
            elif args.action == 'reset':
                logger.warning("Resetting database (all data will be lost)...")
                response = input("Are you sure? Type 'yes' to continue: ")
                if response.lower() == 'yes':
                    from security_monitor.database.models import Base
                    from security_monitor.database.database import engine
                    
                    Base.metadata.drop_all(bind=engine)
                    init_database()
                    logger.info("Database reset successfully")
                else:
                    logger.info("Database reset cancelled")
        
        elif args.command == 'config':
            config_file = args.file or 'security_monitor.json'
            
            if args.action == 'create':
                logger.info(f"Creating configuration file: {config_file}")
                if create_default_config_file(config_file):
                    logger.info("Configuration file created successfully")
                else:
                    logger.error("Failed to create configuration file")
                    sys.exit(1)
            
            elif args.action == 'validate':
                logger.info(f"Validating configuration: {config_file}")
                from security_monitor.utils.config import validate_config
                
                if os.path.exists(config_file):
                    config = load_config(config_file)
                    if validate_config(config):
                        logger.info("Configuration is valid")
                    else:
                        logger.error("Configuration validation failed")
                        sys.exit(1)
                else:
                    logger.error(f"Configuration file not found: {config_file}")
                    sys.exit(1)
            
            elif args.action == 'show':
                print(json.dumps(get_config_template(), indent=2))
        
        elif args.command == 'report':
            logger.info(f"Generating {args.type} security report...")
            
            from security_monitor.reporting.pdf_generator import SecurityReportGenerator
            from security_monitor.reporting.email_service import EmailReportService
            from security_monitor.database.database import SessionLocal
            from security_monitor.database.models import SecurityEvent, Agent
            from datetime import datetime, timedelta
            
            # Calculate report period
            end_time = datetime.now()
            if args.type == 'daily':
                start_time = end_time - timedelta(days=1)
            elif args.type == 'weekly':
                start_time = end_time - timedelta(weeks=1)
            elif args.type == 'monthly':
                start_time = end_time - timedelta(days=30)
            
            # Get data from database
            db = SessionLocal()
            try:
                events = db.query(SecurityEvent).filter(
                    SecurityEvent.timestamp >= start_time,
                    SecurityEvent.timestamp <= end_time
                ).all()
                
                agents = db.query(Agent).all()
                
                # Convert to dict format
                events_data = []
                for event in events:
                    events_data.append({
                        'timestamp': event.timestamp.isoformat(),
                        'type': event.event_type,
                        'source': event.source,
                        'severity': event.severity,
                        'threat_type': event.threat_type,
                        'data': json.loads(event.data) if event.data else {}
                    })
                
                agents_data = []
                for agent in agents:
                    agents_data.append({
                        'agent_id': agent.agent_id,
                        'hostname': agent.hostname,
                        'ip_address': agent.ip_address,
                        'status': agent.status,
                        'last_seen': agent.last_seen.isoformat() if agent.last_seen else None
                    })
                
                # Generate PDF report
                output_dir = args.output or config.get('reporting', {}).get('output_dir', 'reports')
                generator = SecurityReportGenerator(output_dir)
                
                pdf_path = generator.generate_summary_report(
                    events_data, agents_data, start_time, end_time
                )
                
                logger.info(f"Report generated: {pdf_path}")
                
                # Send email if requested
                if args.email:
                    email_config = config.get('email', {})
                    recipients = config.get('reporting', {}).get('recipients', [])
                    
                    if recipients and email_config.get('username'):
                        email_service = EmailReportService(email_config)
                        
                        # Prepare report data for email
                        stats = generator._calculate_statistics(events_data)
                        report_data = {
                            'period': {
                                'start': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                                'end': end_time.strftime('%Y-%m-%d %H:%M:%S')
                            },
                            'stats': stats,
                            'threats': [e for e in events_data if e.get('severity') in ['critical', 'warning']]
                        }
                        
                        if email_service.send_security_report(recipients, report_data, pdf_path):
                            logger.info(f"Report emailed to {len(recipients)} recipients")
                        else:
                            logger.error("Failed to send report via email")
                    else:
                        logger.warning("Email configuration incomplete, skipping email send")
                
            finally:
                db.close()
    
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.command == 'agent':
            # Don't exit for agent errors, just log them
            return
        sys.exit(1)


if __name__ == '__main__':
    main()