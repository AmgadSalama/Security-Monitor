import smtplib
import ssl
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class EmailReportService:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("security_monitor.email")
        
        # Email configuration
        self.smtp_server = config.get('smtp_server', 'smtp.gmail.com')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username')
        self.password = config.get('password')
        self.use_tls = config.get('use_tls', True)
        
        # Validate configuration
        if not self.username or not self.password:
            self.logger.warning("Email credentials not configured. Email reports will not be available.")
    
    def send_security_report(self, 
                           recipients: List[str],
                           report_data: Dict[str, Any],
                           pdf_path: str = None,
                           report_type: str = "security") -> bool:
        
        if not self.username or not self.password:
            self.logger.error("Email credentials not configured")
            return False
        
        try:
            # Create message
            message = MIMEMultipart()
            message["From"] = self.username
            message["To"] = ", ".join(recipients)
            message["Subject"] = self._generate_subject(report_data, report_type)
            
            # Create HTML body
            html_body = self._create_html_report(report_data, report_type)
            message.attach(MIMEText(html_body, "html"))
            
            # Attach PDF if provided
            if pdf_path and Path(pdf_path).exists():
                with open(pdf_path, "rb") as pdf_file:
                    pdf_attachment = MIMEApplication(pdf_file.read(), _subtype="pdf")
                    pdf_attachment.add_header(
                        "Content-Disposition", 
                        f"attachment; filename={Path(pdf_path).name}"
                    )
                    message.attach(pdf_attachment)
            
            # Send email
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                
                server.login(self.username, self.password)
                server.sendmail(self.username, recipients, message.as_string())
            
            self.logger.info(f"Security report email sent to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send security report email: {e}")
            return False
    
    def send_alert_notification(self,
                              recipients: List[str],
                              alert_data: Dict[str, Any]) -> bool:
        
        if not self.username or not self.password:
            self.logger.error("Email credentials not configured")
            return False
        
        try:
            # Create message
            message = MIMEMultipart()
            message["From"] = self.username
            message["To"] = ", ".join(recipients)
            message["Subject"] = self._generate_alert_subject(alert_data)
            
            # Create HTML body for alert
            html_body = self._create_alert_html(alert_data)
            message.attach(MIMEText(html_body, "html"))
            
            # Send email
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                
                server.login(self.username, self.password)
                server.sendmail(self.username, recipients, message.as_string())
            
            self.logger.info(f"Security alert email sent to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send security alert email: {e}")
            return False
    
    def _generate_subject(self, report_data: Dict[str, Any], report_type: str) -> str:
        stats = report_data.get('stats', {})
        critical_count = stats.get('critical_events', 0)
        
        if critical_count > 0:
            urgency = f"🚨 CRITICAL ({critical_count})"
        elif stats.get('warning_events', 0) > 10:
            urgency = f"⚠️ WARNING"
        else:
            urgency = "✅ NORMAL"
        
        timestamp = datetime.now().strftime("%Y-%m-%d")
        return f"Security Monitor Report - {urgency} - {timestamp}"
    
    def _generate_alert_subject(self, alert_data: Dict[str, Any]) -> str:
        severity = alert_data.get('severity', 'info').upper()
        threat_type = alert_data.get('threat_type', 'Unknown').replace('_', ' ').title()
        
        severity_emoji = {
            'CRITICAL': '🚨',
            'WARNING': '⚠️',
            'INFO': 'ℹ️'
        }
        
        emoji = severity_emoji.get(severity, '🔔')
        timestamp = datetime.now().strftime("%H:%M")
        
        return f"{emoji} Security Alert - {threat_type} - {severity} - {timestamp}"
    
    def _create_html_report(self, report_data: Dict[str, Any], report_type: str) -> str:
        stats = report_data.get('stats', {})
        threats = report_data.get('threats', [])
        period = report_data.get('period', {})
        
        # Color scheme
        primary_color = "#2c3e50"
        critical_color = "#e74c3c"
        warning_color = "#f39c12"
        success_color = "#27ae60"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Security Monitor Report</title>
            <style>
                body {{
                    font-family: 'Arial', sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: {primary_color};
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                    gap: 15px;
                    margin: 20px 0;
                }}
                .stat-card {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                    border-left: 4px solid {primary_color};
                }}
                .stat-card.critical {{
                    border-left-color: {critical_color};
                }}
                .stat-card.warning {{
                    border-left-color: {warning_color};
                }}
                .stat-card.success {{
                    border-left-color: {success_color};
                }}
                .stat-value {{
                    font-size: 2em;
                    font-weight: bold;
                    margin-bottom: 5px;
                }}
                .stat-label {{
                    color: #666;
                    font-size: 0.9em;
                }}
                .section {{
                    background: white;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                }}
                .section-title {{
                    font-size: 1.2em;
                    font-weight: bold;
                    margin-bottom: 15px;
                    color: {primary_color};
                }}
                .threat-item {{
                    background: #f8f9fa;
                    border-radius: 6px;
                    padding: 12px;
                    margin: 10px 0;
                    border-left: 4px solid #ddd;
                }}
                .threat-item.critical {{
                    background: #fdf2f2;
                    border-left-color: {critical_color};
                }}
                .threat-item.warning {{
                    background: #fef9e7;
                    border-left-color: {warning_color};
                }}
                .threat-time {{
                    font-size: 0.9em;
                    color: #666;
                }}
                .threat-type {{
                    font-weight: bold;
                    text-transform: capitalize;
                }}
                .footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    text-align: center;
                    color: #666;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Security Monitor Report</h1>
                <p>{report_type.title()} Report | {period.get('start', 'N/A')} to {period.get('end', 'N/A')}</p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats.get('total_events', 0)}</div>
                    <div class="stat-label">Total Events</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-value" style="color: {critical_color}">{stats.get('critical_events', 0)}</div>
                    <div class="stat-label">Critical Threats</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-value" style="color: {warning_color}">{stats.get('warning_events', 0)}</div>
                    <div class="stat-label">Warning Events</div>
                </div>
                <div class="stat-card success">
                    <div class="stat-value" style="color: {success_color}">{stats.get('active_agents', 0)}</div>
                    <div class="stat-label">Active Agents</div>
                </div>
            </div>
        """
        
        # Add threats section
        if threats:
            html += f"""
            <div class="section">
                <div class="section-title">🚨 Security Threats Detected</div>
            """
            
            for threat in threats[:10]:  # Show top 10 threats
                threat_class = threat.get('severity', 'info')
                threat_type = threat.get('threat_type', 'unknown').replace('_', ' ').title()
                timestamp = threat.get('timestamp', 'N/A')[:16]
                source = threat.get('source', 'N/A')
                description = threat.get('description', 'No description available')
                
                html += f"""
                <div class="threat-item {threat_class}">
                    <div class="threat-type">{threat_type}</div>
                    <div class="threat-time">{timestamp} | Source: {source}</div>
                    <div style="margin-top: 5px;">{description}</div>
                </div>
                """
            
            html += "</div>"
        
        # Add summary section
        total_events = stats.get('total_events', 0)
        critical_events = stats.get('critical_events', 0)
        
        if critical_events > 0:
            status_color = critical_color
            status_text = "⚠️ ATTENTION REQUIRED"
            summary = f"This report contains {critical_events} critical security events that require immediate attention."
        elif stats.get('warning_events', 0) > 10:
            status_color = warning_color
            status_text = "📋 REVIEW RECOMMENDED"
            summary = f"Multiple warning events detected. Review recommended to ensure system security."
        else:
            status_color = success_color
            status_text = "✅ ALL CLEAR"
            summary = "No critical security issues detected during this reporting period."
        
        html += f"""
            <div class="section">
                <div class="section-title">📊 Summary</div>
                <div style="padding: 15px; background: #f8f9fa; border-radius: 6px; border-left: 4px solid {status_color};">
                    <div style="font-weight: bold; color: {status_color}; margin-bottom: 10px;">{status_text}</div>
                    <div>{summary}</div>
                </div>
            </div>
            
            <div class="footer">
                <p>Generated by Security Monitor System | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>For detailed analysis, please review the attached PDF report or access the dashboard.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_alert_html(self, alert_data: Dict[str, Any]) -> str:
        severity = alert_data.get('severity', 'info').upper()
        threat_type = alert_data.get('threat_type', 'Unknown').replace('_', ' ').title()
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        source = alert_data.get('source', 'N/A')
        description = alert_data.get('description', 'No description available')
        data = alert_data.get('data', {})
        
        # Color based on severity
        severity_colors = {
            'CRITICAL': '#e74c3c',
            'WARNING': '#f39c12',
            'INFO': '#3498db'
        }
        
        color = severity_colors.get(severity, '#3498db')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Security Alert</title>
            <style>
                body {{
                    font-family: 'Arial', sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .alert-header {{
                    background: {color};
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }}
                .alert-content {{
                    background: white;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    padding: 20px;
                }}
                .info-row {{
                    margin: 10px 0;
                    padding: 10px;
                    background: #f8f9fa;
                    border-radius: 4px;
                }}
                .info-label {{
                    font-weight: bold;
                    color: #555;
                }}
                .data-section {{
                    margin-top: 20px;
                    padding: 15px;
                    background: #f1f2f6;
                    border-radius: 6px;
                }}
                .footer {{
                    margin-top: 20px;
                    text-align: center;
                    color: #666;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <div class="alert-header">
                <h1>🚨 Security Alert</h1>
                <h2>{severity} - {threat_type}</h2>
            </div>
            
            <div class="alert-content">
                <div class="info-row">
                    <div class="info-label">Timestamp:</div>
                    <div>{timestamp[:19].replace('T', ' ')}</div>
                </div>
                
                <div class="info-row">
                    <div class="info-label">Source:</div>
                    <div>{source}</div>
                </div>
                
                <div class="info-row">
                    <div class="info-label">Severity:</div>
                    <div style="color: {color}; font-weight: bold;">{severity}</div>
                </div>
                
                <div class="info-row">
                    <div class="info-label">Threat Type:</div>
                    <div>{threat_type}</div>
                </div>
                
                <div class="info-row">
                    <div class="info-label">Description:</div>
                    <div>{description}</div>
                </div>
        """
        
        # Add data section if available
        if data:
            html += f"""
                <div class="data-section">
                    <div class="info-label">Additional Information:</div>
                    <pre>{self._format_data_for_display(data)}</pre>
                </div>
            """
        
        html += f"""
            </div>
            
            <div class="footer">
                <p>Generated by Security Monitor System | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Please investigate this alert promptly and take appropriate action.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _format_data_for_display(self, data: Dict[str, Any]) -> str:
        formatted = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                formatted.append(f"{key}: {str(value)[:100]}...")
            else:
                formatted.append(f"{key}: {value}")
        
        return "\n".join(formatted)
    
    def test_connection(self) -> bool:
        """Test the email configuration and connection"""
        if not self.username or not self.password:
            self.logger.error("Email credentials not configured")
            return False
        
        try:
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                
                server.login(self.username, self.password)
                self.logger.info("Email connection test successful")
                return True
                
        except Exception as e:
            self.logger.error(f"Email connection test failed: {e}")
            return False