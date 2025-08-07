import os
from datetime import datetime, timedelta
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, 
                                TableStyle, PageBreak, Image)
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
import logging


class SecurityReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.logger = logging.getLogger("security_monitor.reporting")
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        # Custom styles for the security report
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#2c3e50')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#34495e'),
            borderWidth=1,
            borderColor=HexColor('#bdc3c7'),
            borderPadding=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            textColor=HexColor('#e74c3c'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Warning',
            parent=self.styles['Normal'],
            textColor=HexColor('#f39c12'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Info',
            parent=self.styles['Normal'],
            textColor=HexColor('#3498db')
        ))
    
    def generate_security_report(self, 
                                data: Dict[str, Any], 
                                report_type: str = "daily",
                                filename: str = None) -> str:
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{report_type}_{timestamp}.pdf"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            # Create the PDF document
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build the story (content)
            story = []
            
            # Title Page
            story.extend(self._create_title_page(data, report_type))
            story.append(PageBreak())
            
            # Executive Summary
            story.extend(self._create_executive_summary(data))
            story.append(PageBreak())
            
            # Threat Overview
            story.extend(self._create_threat_overview(data))
            story.append(Spacer(1, 20))
            
            # Detailed Events
            story.extend(self._create_detailed_events(data))
            story.append(Spacer(1, 20))
            
            # System Status
            story.extend(self._create_system_status(data))
            story.append(Spacer(1, 20))
            
            # Recommendations
            story.extend(self._create_recommendations(data))
            
            # Build the PDF
            doc.build(story)
            
            self.logger.info(f"Security report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            raise
    
    def _create_title_page(self, data: Dict[str, Any], report_type: str) -> List:
        elements = []
        
        # Main title
        title = f"Security Monitor Report - {report_type.title()}"
        elements.append(Paragraph(title, self.styles['CustomTitle']))
        elements.append(Spacer(1, 30))
        
        # Report period
        period_info = data.get('period', {})
        start_date = period_info.get('start', 'N/A')
        end_date = period_info.get('end', 'N/A')
        
        period_text = f"<b>Report Period:</b> {start_date} to {end_date}"
        elements.append(Paragraph(period_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Generated timestamp
        generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        generated_text = f"<b>Generated:</b> {generated_time}"
        elements.append(Paragraph(generated_text, self.styles['Normal']))
        elements.append(Spacer(1, 40))
        
        # Key metrics summary table
        stats = data.get('stats', {})
        summary_data = [
            ['Metric', 'Count'],
            ['Total Security Events', str(stats.get('total_events', 0))],
            ['Critical Threats', str(stats.get('critical_events', 0))],
            ['Warning Events', str(stats.get('warning_events', 0))],
            ['Active Agents', str(stats.get('active_agents', 0))],
            ['System Uptime', stats.get('uptime', 'N/A')]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
        ]))
        
        elements.append(summary_table)
        
        return elements
    
    def _create_executive_summary(self, data: Dict[str, Any]) -> List:
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        elements.append(Spacer(1, 12))
        
        stats = data.get('stats', {})
        threats = data.get('threats', [])
        
        # Generate summary text based on the data
        total_events = stats.get('total_events', 0)
        critical_events = stats.get('critical_events', 0)
        warning_events = stats.get('warning_events', 0)
        
        summary_text = f"""
        During the reporting period, the Security Monitor system processed {total_events} security events
        across all monitored endpoints. Of these events, {critical_events} were classified as critical
        threats requiring immediate attention, and {warning_events} were identified as warning-level
        security incidents.
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 15))
        
        # Threat distribution
        if threats:
            threat_types = {}
            for threat in threats:
                threat_type = threat.get('threat_type', 'unknown')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            threat_text = "<b>Top Threat Categories:</b><br/>"
            for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:5]:
                threat_text += f"• {threat_type.replace('_', ' ').title()}: {count} incidents<br/>"
            
            elements.append(Paragraph(threat_text, self.styles['Normal']))
            elements.append(Spacer(1, 15))
        
        # Risk assessment
        if critical_events > 10:
            risk_level = "HIGH"
            risk_color = self.styles['Critical']
        elif warning_events > 20:
            risk_level = "MEDIUM" 
            risk_color = self.styles['Warning']
        else:
            risk_level = "LOW"
            risk_color = self.styles['Info']
        
        risk_text = f"<b>Overall Security Risk Level: </b>"
        elements.append(Paragraph(risk_text, self.styles['Normal']))
        elements.append(Paragraph(risk_level, risk_color))
        
        return elements
    
    def _create_threat_overview(self, data: Dict[str, Any]) -> List:
        elements = []
        
        elements.append(Paragraph("Threat Analysis", self.styles['SectionHeader']))
        elements.append(Spacer(1, 12))
        
        threats = data.get('threats', [])
        
        if not threats:
            elements.append(Paragraph("No security threats detected during this period.", 
                                    self.styles['Normal']))
            return elements
        
        # Group threats by severity
        critical_threats = [t for t in threats if t.get('severity') == 'critical']
        warning_threats = [t for t in threats if t.get('severity') == 'warning']
        
        # Critical threats table
        if critical_threats:
            elements.append(Paragraph("Critical Threats", self.styles['Critical']))
            elements.append(Spacer(1, 10))
            
            crit_data = [['Timestamp', 'Threat Type', 'Source', 'Description']]
            for threat in critical_threats[:10]:  # Limit to top 10
                crit_data.append([
                    threat.get('timestamp', 'N/A')[:16],
                    threat.get('threat_type', 'N/A').replace('_', ' ').title(),
                    threat.get('source', 'N/A'),
                    threat.get('description', 'N/A')[:50] + '...'
                ])
            
            crit_table = Table(crit_data, colWidths=[1.2*inch, 1.5*inch, 1*inch, 2.5*inch])
            crit_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e74c3c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#c0392b')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            elements.append(crit_table)
            elements.append(Spacer(1, 20))
        
        # Warning threats table
        if warning_threats:
            elements.append(Paragraph("Warning Events", self.styles['Warning']))
            elements.append(Spacer(1, 10))
            
            warn_data = [['Timestamp', 'Threat Type', 'Source', 'Description']]
            for threat in warning_threats[:10]:  # Limit to top 10
                warn_data.append([
                    threat.get('timestamp', 'N/A')[:16],
                    threat.get('threat_type', 'N/A').replace('_', ' ').title(),
                    threat.get('source', 'N/A'),
                    threat.get('description', 'N/A')[:50] + '...'
                ])
            
            warn_table = Table(warn_data, colWidths=[1.2*inch, 1.5*inch, 1*inch, 2.5*inch])
            warn_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f39c12')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#e67e22')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            elements.append(warn_table)
        
        return elements
    
    def _create_detailed_events(self, data: Dict[str, Any]) -> List:
        elements = []
        
        elements.append(Paragraph("Detailed Event Analysis", self.styles['SectionHeader']))
        elements.append(Spacer(1, 12))
        
        events = data.get('events', [])
        
        if not events:
            elements.append(Paragraph("No detailed events available for this period.", 
                                    self.styles['Normal']))
            return elements
        
        # Group events by type
        event_types = {}
        for event in events:
            event_type = event.get('type', 'unknown')
            if event_type not in event_types:
                event_types[event_type] = []
            event_types[event_type].append(event)
        
        # Create summary for each event type
        for event_type, type_events in event_types.items():
            elements.append(Paragraph(f"{event_type.replace('_', ' ').title()} Events ({len(type_events)})", 
                                    self.styles['Normal']))
            elements.append(Spacer(1, 8))
            
            # Show top 5 events of this type
            for event in type_events[:5]:
                timestamp = event.get('timestamp', 'N/A')
                severity = event.get('severity', 'info')
                source = event.get('source', 'N/A')
                
                event_text = f"• <b>{timestamp[:16]}</b> | <b>{severity.upper()}</b> | {source}"
                
                if severity == 'critical':
                    style = self.styles['Critical']
                elif severity == 'warning':
                    style = self.styles['Warning']
                else:
                    style = self.styles['Info']
                
                elements.append(Paragraph(event_text, style))
            
            elements.append(Spacer(1, 15))
        
        return elements
    
    def _create_system_status(self, data: Dict[str, Any]) -> List:
        elements = []
        
        elements.append(Paragraph("System Status", self.styles['SectionHeader']))
        elements.append(Spacer(1, 12))
        
        agents = data.get('agents', [])
        system_metrics = data.get('system_metrics', {})
        
        # Agent status table
        if agents:
            agent_data = [['Agent ID', 'Hostname', 'Status', 'Last Seen']]
            for agent in agents:
                status = agent.get('status', 'unknown')
                status_color = '🟢' if status == 'online' else '🔴'
                
                agent_data.append([
                    agent.get('agent_id', 'N/A'),
                    agent.get('hostname', 'N/A'),
                    f"{status_color} {status}",
                    agent.get('last_seen', 'N/A')[:16]
                ])
            
            agent_table = Table(agent_data, colWidths=[1.5*inch, 2*inch, 1*inch, 1.5*inch])
            agent_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#2980b9'))
            ]))
            
            elements.append(agent_table)
            elements.append(Spacer(1, 20))
        
        # System metrics summary
        if system_metrics:
            metrics_text = "<b>System Performance Metrics:</b><br/>"
            metrics_text += f"• Average CPU Usage: {system_metrics.get('avg_cpu', 'N/A')}%<br/>"
            metrics_text += f"• Average Memory Usage: {system_metrics.get('avg_memory', 'N/A')}%<br/>"
            metrics_text += f"• Network Traffic: {system_metrics.get('network_traffic', 'N/A')}<br/>"
            metrics_text += f"• Disk Usage: {system_metrics.get('disk_usage', 'N/A')}<br/>"
            
            elements.append(Paragraph(metrics_text, self.styles['Normal']))
        
        return elements
    
    def _create_recommendations(self, data: Dict[str, Any]) -> List:
        elements = []
        
        elements.append(Paragraph("Security Recommendations", self.styles['SectionHeader']))
        elements.append(Spacer(1, 12))
        
        stats = data.get('stats', {})
        threats = data.get('threats', [])
        
        recommendations = []
        
        # Generate recommendations based on the data
        critical_count = stats.get('critical_events', 0)
        warning_count = stats.get('warning_events', 0)
        
        if critical_count > 5:
            recommendations.append(
                "• Immediate action required: Multiple critical threats detected. "
                "Review and remediate critical security events within 24 hours."
            )
        
        if warning_count > 20:
            recommendations.append(
                "• Enhanced monitoring recommended: High volume of warning events detected. "
                "Consider tuning detection rules to reduce false positives."
            )
        
        # Analyze threat types for specific recommendations
        threat_types = {}
        for threat in threats:
            threat_type = threat.get('threat_type', 'unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        if threat_types.get('malware', 0) > 3:
            recommendations.append(
                "• Update antivirus definitions and perform full system scans on affected endpoints."
            )
        
        if threat_types.get('resource_abuse', 0) > 5:
            recommendations.append(
                "• Investigate potential crypto-mining or DoS attacks. "
                "Monitor system resources and network traffic patterns."
            )
        
        if threat_types.get('data_exfiltration', 0) > 2:
            recommendations.append(
                "• Implement data loss prevention (DLP) controls. "
                "Review file access logs and network traffic for sensitive data."
            )
        
        # Default recommendations
        if not recommendations:
            recommendations = [
                "• Continue monitoring current security posture.",
                "• Regular review of security logs and event patterns.",
                "• Ensure all security agents are operational and up-to-date.",
                "• Conduct periodic security awareness training for users."
            ]
        
        rec_text = "<b>Recommended Actions:</b><br/><br/>"
        rec_text += "<br/>".join(recommendations)
        
        elements.append(Paragraph(rec_text, self.styles['Normal']))
        
        return elements
    
    def generate_summary_report(self, events: List[Dict], agents: List[Dict], 
                               period_start: datetime, period_end: datetime) -> str:
        
        # Process the raw data into report format
        stats = self._calculate_statistics(events)
        threats = [e for e in events if e.get('severity') in ['critical', 'warning']]
        
        report_data = {
            'period': {
                'start': period_start.strftime('%Y-%m-%d %H:%M:%S'),
                'end': period_end.strftime('%Y-%m-%d %H:%M:%S')
            },
            'stats': stats,
            'events': events,
            'threats': threats,
            'agents': agents,
            'system_metrics': self._calculate_system_metrics(events)
        }
        
        return self.generate_security_report(report_data, "summary")
    
    def _calculate_statistics(self, events: List[Dict]) -> Dict[str, Any]:
        total_events = len(events)
        critical_events = len([e for e in events if e.get('severity') == 'critical'])
        warning_events = len([e for e in events if e.get('severity') == 'warning'])
        
        return {
            'total_events': total_events,
            'critical_events': critical_events,
            'warning_events': warning_events,
            'info_events': total_events - critical_events - warning_events
        }
    
    def _calculate_system_metrics(self, events: List[Dict]) -> Dict[str, Any]:
        # Extract system metrics from events
        system_events = [e for e in events if e.get('type') == 'system_metrics']
        
        if not system_events:
            return {}
        
        cpu_values = []
        memory_values = []
        
        for event in system_events:
            data = event.get('data', {})
            if 'cpu_percent' in data:
                cpu_values.append(data['cpu_percent'])
            if 'memory_percent' in data:
                memory_values.append(data['memory_percent'])
        
        metrics = {}
        if cpu_values:
            metrics['avg_cpu'] = round(sum(cpu_values) / len(cpu_values), 1)
        if memory_values:
            metrics['avg_memory'] = round(sum(memory_values) / len(memory_values), 1)
        
        return metrics