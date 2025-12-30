# app/db/models.py
"""SQLModel database models for storing scan results."""

from sqlmodel import SQLModel, Field, Column, JSON, create_engine, Session
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid


class Scan(SQLModel, table=True):
    """Database model for storing scan information and results."""
    
    __tablename__ = "scans"
    
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        primary_key=True,
        description="Unique scan identifier"
    )
    host: str = Field(description="Target host scanned")
    ports: str = Field(description="Port specification used")
    status: str = Field(default="queued", description="Scan status: queued, running, done, error")
    
    started_at: Optional[datetime] = Field(default=None, description="Scan start timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Scan completion timestamp")
    
    risk_score: Optional[int] = Field(default=None, description="Overall risk score (0-100)")
    risk_level: Optional[str] = Field(default=None, description="Risk level: LOW, MEDIUM, HIGH")
    
    open_ports: Optional[int] = Field(default=None, description="Number of open ports found")
    closed_ports: Optional[int] = Field(default=None, description="Number of closed ports")
    error_count: Optional[int] = Field(default=None, description="Number of errors encountered")
    total_findings: Optional[int] = Field(default=None, description="Total security findings")
    critical_findings: Optional[int] = Field(default=None, description="Critical severity findings")
    high_findings: Optional[int] = Field(default=None, description="High severity findings")
    
    elapsed_time: Optional[float] = Field(default=None, description="Scan duration in seconds")
    
    results: Optional[List[Dict[str, Any]]] = Field(
        sa_column=Column(JSON),
        default=None,
        description="Full scan results as JSON"
    )
    
    ai_summary: Optional[Dict] = Field(
        default=None,
        sa_column=Column(JSON)
    )
    
    error_message: Optional[str] = Field(default=None, description="Error message if scan failed")


def init_db(database_url: str = "sqlite:///./nscanner.db") -> Any:
    """
    Initialize the database engine and create tables.
    
    Args:
        database_url: SQLAlchemy database URL
        
    Returns:
        SQLAlchemy engine instance
    """
    engine = create_engine(
        database_url,
        echo=False,
        connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {}
    )
    SQLModel.metadata.create_all(engine)
    return engine


def get_session(engine: Any) -> Session:
    """
    Get a new database session.
    
    Args:
        engine: SQLAlchemy engine instance
        
    Returns:
        Database session
    """
    return Session(engine)