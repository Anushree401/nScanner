# app/api/schemas.py
"""Pydantic models for API request/response validation."""

from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
import ipaddress
# Import constant for consistency
from app.core.config import MAX_PORTS_PER_SCAN


class ScanRequest(BaseModel):
    """Request model for initiating a port scan."""
    
    host: str = Field(..., description="Target hostname or IP address")
    ports: str = Field(default="1-1024", description="Port specification (e.g., '22,80,443' or '1-1024')")

    @validator('host')
    def validate_host(cls, v):        
        return v
    
    @validator('ports')
    def validate_ports(cls, v):
        """Basic validation of port specification format."""
        v = v.strip()
        if not v:
            raise ValueError("Ports specification cannot be empty")
        
        # Count total ports to prevent abuse
        port_count = 0
        for part in v.split(','):
            if '-' in part:
                try:
                    start, end = map(int, part.strip().split('-'))
                    port_count += (end - start + 1)
                except:
                    pass
            else:
                port_count += 1
        
        # Use imported constant instead of hardcoding 1000
        if port_count > MAX_PORTS_PER_SCAN: 
            raise ValueError(f"Maximum {MAX_PORTS_PER_SCAN} ports per scan")
        
        return v

class FindingModel(BaseModel):
    """Model for a single security finding."""
    
    type: str
    detail: str
    severity: Optional[str] = "info"


class PortResult(BaseModel):
    """Model for a single port scan result."""
    
    host: Optional[str] = None
    port: Optional[int] = None
    state: Optional[str] = None
    service: Optional[str] = None
    banner: Optional[str] = None
    findings: List[FindingModel] = []
    mapping_summary: Optional[str] = None
    remediation: Optional[str] = None
    base_severity: Optional[str] = None
    error: Optional[str] = None


class ScanResponse(BaseModel):
    """Response model for scan initiation."""
    
    scan_id: str
    status: str = "queued"
    message: str = "Scan queued successfully"


class ScanStatus(BaseModel):
    """Model for scan status information."""
    
    scan_id: str
    host: str
    ports: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: Optional[int] = None  # Percentage if available


class ScanResult(BaseModel):
    """Complete scan result model."""
    
    scan_id: str
    host: str
    ports: str
    status: str
    ports_scanned: int
    open_ports: int
    closed_ports: int
    error_count: int
    elapsed: float
    risk_score: int
    risk_level: str
    total_findings: int
    critical_findings: int
    high_findings: int
    results: List[PortResult]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanListItem(BaseModel):
    """Model for scan list item (summary view)."""
    
    scan_id: str
    host: str
    status: str
    risk_level: Optional[str] = None
    open_ports: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ErrorResponse(BaseModel):
    """Model for error responses."""
    
    error: str
    detail: Optional[str] = None