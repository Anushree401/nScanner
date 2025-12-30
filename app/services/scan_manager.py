# app/services/scan_manager.py
"""Service layer for managing and orchestrating scans."""

import uuid
import asyncio
import time
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlmodel import Session, select
from app.core.scanner import scanning
from app.core.risk import summarize_scan
from app.db.models import Scan, init_db
from app.core.config import MAX_CONCURRENT_SCANS
from app.services.gemini_service import summarize_with_gemini

# In-memory store for quick lookups and active scan tracking
ACTIVE_SCANS: Dict[str, Dict[str, Any]] = {}
SCAN_SEMAPHORE: Optional[asyncio.Semaphore] = None

# Initialize database engine
engine = init_db()


def get_semaphore() -> asyncio.Semaphore:
    """Get or create the scan concurrency semaphore."""
    global SCAN_SEMAPHORE
    if SCAN_SEMAPHORE is None:
        SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
    return SCAN_SEMAPHORE


async def start_scan_async(host: str, ports: str = "1-1024") -> str:
    """
    Start an asynchronous port scan.
    
    Args:
        host: Target hostname or IP address
        ports: Port specification string
        
    Returns:
        Unique scan ID for tracking
    """
    scan_id = str(uuid.uuid4())
    
    # Initialize in-memory tracking
    ACTIVE_SCANS[scan_id] = {
        "status": "queued",
        "result": None,
        "host": host,
        "ports": ports
    }
    
    # Create database entry
    scan_row = Scan(
        id=scan_id,
        host=host,
        ports=ports,
        status="queued"
    )
    with Session(engine) as sess:
        sess.add(scan_row)
        sess.commit()
    
    async def _run_scan():
        """Internal async function to execute the scan."""
        semaphore = get_semaphore()
        
        async with semaphore:  # Limit concurrent scans
            ACTIVE_SCANS[scan_id]["status"] = "running"
            started_at = datetime.utcnow()
            
            # Update DB status
            with Session(engine) as sess:
                db_scan = sess.get(Scan, scan_id)
                if db_scan:
                    db_scan.status = "running"
                    db_scan.started_at = started_at
                    sess.add(db_scan)
                    sess.commit()
            
            try:
                # Run the actual scan in a thread pool
                start_time = time.time()
                results = await asyncio.to_thread(scanning, host, ports)
                elapsed = time.time() - start_time
                
                # Compute risk summary
                risk_summary = summarize_scan(results)
                
                # AI-enhanced summary (Gemini)
                # try:
                #     ai_summary = summarize_with_gemini(results, risk_summary)
                # except Exception as ai_err:
                #     ai_summary = None
                ai_summary = summarize_with_gemini(results, risk_summary)
                
                completed_at = datetime.utcnow()
                
                # Update database with results
                with Session(engine) as sess:
                    db_scan = sess.get(Scan, scan_id)
                    if db_scan:
                        db_scan.status = "done"
                        db_scan.completed_at = completed_at
                        db_scan.elapsed_time = elapsed
                        db_scan.risk_score = risk_summary["risk_score"]
                        db_scan.risk_level = risk_summary["risk_level"]
                        db_scan.open_ports = risk_summary["open_ports"]
                        db_scan.closed_ports = risk_summary["closed_ports"]
                        db_scan.error_count = risk_summary["error_count"]
                        db_scan.total_findings = risk_summary["total_findings"]
                        db_scan.critical_findings = risk_summary["critical_findings"]
                        db_scan.high_findings = risk_summary["high_findings"]
                        db_scan.ai_summary = ai_summary
                        db_scan.results = results
                        sess.add(db_scan)
                        sess.commit()
                
                # Update in-memory cache
                ACTIVE_SCANS[scan_id]["status"] = "done"
                ACTIVE_SCANS[scan_id]["result"] = results
                ACTIVE_SCANS[scan_id]["risk_summary"] = risk_summary
                ACTIVE_SCANS[scan_id]["ai_summary"] = ai_summary
                
            except Exception as e:
                error_msg = str(e)
                
                # Update database with error
                with Session(engine) as sess:
                    db_scan = sess.get(Scan, scan_id)
                    if db_scan:
                        db_scan.status = "error"
                        db_scan.completed_at = datetime.utcnow()
                        db_scan.error_message = error_msg
                        sess.add(db_scan)
                        sess.commit()
                
                # Update in-memory cache
                ACTIVE_SCANS[scan_id]["status"] = "error"
                ACTIVE_SCANS[scan_id]["error"] = error_msg
    
    # Create the scan task
    asyncio.create_task(_run_scan())
    
    return scan_id


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve scan information by ID.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Dictionary containing scan information, or None if not found
    """
    # First check database (authoritative source)
    with Session(engine) as sess:
        db_scan = sess.get(Scan, scan_id)
        if db_scan:
            result = {
                "scan_id": db_scan.id,
                "host": db_scan.host,
                "ports": db_scan.ports,
                "status": db_scan.status,
                "started_at": db_scan.started_at,
                "completed_at": db_scan.completed_at,
                "elapsed": db_scan.elapsed_time,
                "risk_score": db_scan.risk_score,
                "risk_level": db_scan.risk_level,
                "open_ports": db_scan.open_ports,
                "closed_ports": db_scan.closed_ports,
                "error_count": db_scan.error_count,
                "total_findings": db_scan.total_findings,
                "critical_findings": db_scan.critical_findings,
                "high_findings": db_scan.high_findings,
                "ports_scanned": (db_scan.open_ports or 0) + (db_scan.closed_ports or 0),
                "results": db_scan.results or [],
                "ai_summary": db_scan.ai_summary,
                "error_message": db_scan.error_message
            }
            return result
    
    # Fallback to in-memory cache (for very recent scans)
    return ACTIVE_SCANS.get(scan_id)


def list_scans(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """
    List all scans with pagination.
    
    Args:
        limit: Maximum number of scans to return
        offset: Number of scans to skip
        
    Returns:
        List of scan summary dictionaries
    """
    with Session(engine) as sess:
        statement = (
            select(Scan)
            .order_by(Scan.started_at.desc())
            .offset(offset)
            .limit(limit)
        )
        scans = sess.exec(statement).all()
        
        return [
            {
                "scan_id": s.id,
                "host": s.host,
                "ports": s.ports,
                "status": s.status,
                "risk_level": s.risk_level,
                "open_ports": s.open_ports,
                "started_at": s.started_at,
                "completed_at": s.completed_at
            }
            for s in scans
        ]


def delete_scan(scan_id: str) -> bool:
    """
    Delete a scan from the database.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        True if deleted, False if not found
    """
    with Session(engine) as sess:
        db_scan = sess.get(Scan, scan_id)
        if db_scan:
            sess.delete(db_scan)
            sess.commit()
            
            # Also remove from in-memory cache
            ACTIVE_SCANS.pop(scan_id, None)
            return True
    return False


def cleanup_old_scans(days: int = 30) -> int:
    """
    Delete scans older than specified days.
    
    Args:
        days: Age threshold in days
        
    Returns:
        Number of scans deleted
    """
    from datetime import timedelta
    
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    with Session(engine) as sess:
        statement = select(Scan).where(Scan.completed_at < cutoff_date)
        old_scans = sess.exec(statement).all()
        
        count = len(old_scans)
        for scan in old_scans:
            sess.delete(scan)
        sess.commit()
        
    return count