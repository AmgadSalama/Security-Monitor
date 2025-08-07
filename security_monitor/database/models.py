from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class Agent(Base):
    __tablename__ = "agents"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), unique=True, index=True, nullable=False)
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    os_type = Column(String(50), nullable=True)
    os_version = Column(String(100), nullable=True)
    agent_version = Column(String(20), nullable=True)
    status = Column(String(20), default="offline")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship with security events
    security_events = relationship("SecurityEvent", back_populates="agent")


class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    data = Column(Text, nullable=True)
    threat_type = Column(String(100), nullable=True, index=True)
    rule_name = Column(String(100), nullable=True)
    confidence = Column(Integer, nullable=True)
    status = Column(String(20), default="new")
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship with agent
    agent = relationship("Agent", back_populates="security_events")


class ThreatRule(Base):
    __tablename__ = "threat_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    rule_type = Column(String(50), nullable=False)
    event_types = Column(Text, nullable=False)  # JSON array as text
    conditions = Column(Text, nullable=False)   # JSON object as text
    severity = Column(String(20), nullable=False)
    threat_type = Column(String(100), nullable=False)
    enabled = Column(Boolean, default=True)
    created_by = Column(String(100), default="system")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    report_type = Column(String(50), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    status = Column(String(20), default="generated")
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)
    recipients = Column(Text, nullable=True)  # JSON array as text
    email_sent = Column(Boolean, default=False)
    created_by = Column(String(100), default="system")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Statistics
    total_events = Column(Integer, default=0)
    critical_events = Column(Integer, default=0)
    warning_events = Column(Integer, default=0)
    info_events = Column(Integer, default=0)


class AlertSubscription(Base):
    __tablename__ = "alert_subscriptions"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False)
    name = Column(String(100), nullable=True)
    severity_filter = Column(String(100), default="critical,warning")  # Comma-separated
    threat_type_filter = Column(String(200), nullable=True)  # Comma-separated
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    cpu_percent = Column(Integer, nullable=True)
    memory_percent = Column(Integer, nullable=True)
    disk_percent = Column(Integer, nullable=True)
    network_bytes_sent = Column(Integer, nullable=True)
    network_bytes_recv = Column(Integer, nullable=True)
    process_count = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship with agent
    agent = relationship("Agent")


class Configuration(Base):
    __tablename__ = "configurations"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=True)
    data_type = Column(String(20), default="string")  # string, integer, boolean, json
    is_sensitive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)