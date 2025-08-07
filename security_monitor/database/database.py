from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from typing import Generator
import os
from .models import Base

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./security_monitor.db")

# Create engine
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False  # Set to True for SQL logging
    )
else:
    engine = create_engine(DATABASE_URL, echo=False)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_tables():
    """Create all database tables"""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database():
    """Initialize the database with default data"""
    create_tables()
    
    # Add default configuration values
    db = SessionLocal()
    try:
        from .models import Configuration
        
        default_configs = [
            {
                "key": "system.monitoring_interval",
                "value": "30",
                "description": "System monitoring interval in seconds",
                "category": "monitoring",
                "data_type": "integer"
            },
            {
                "key": "alerts.email_enabled",
                "value": "false",
                "description": "Enable email alerts",
                "category": "alerts",
                "data_type": "boolean"
            },
            {
                "key": "alerts.critical_threshold",
                "value": "5",
                "description": "Number of critical events to trigger alert",
                "category": "alerts",
                "data_type": "integer"
            },
            {
                "key": "retention.events_days",
                "value": "30",
                "description": "Number of days to retain security events",
                "category": "retention",
                "data_type": "integer"
            },
            {
                "key": "retention.metrics_days",
                "value": "7",
                "description": "Number of days to retain system metrics",
                "category": "retention",
                "data_type": "integer"
            },
            {
                "key": "detection.rules_enabled",
                "value": "true",
                "description": "Enable threat detection rules",
                "category": "detection",
                "data_type": "boolean"
            }
        ]
        
        for config_data in default_configs:
            existing = db.query(Configuration).filter(
                Configuration.key == config_data["key"]
            ).first()
            
            if not existing:
                config = Configuration(**config_data)
                db.add(config)
        
        db.commit()
        print("Database initialized with default configuration")
        
    except Exception as e:
        db.rollback()
        print(f"Error initializing database: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    init_database()