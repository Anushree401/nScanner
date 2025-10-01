# app/api/routes.py
"""FastAPI route definitions for the scanner API."""

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os
from typing import Optional

from app.services.scan_manager import (
    start_scan_async,
    get_scan,
    list_scans,
    delete_scan
)
from app.api.schemas import (
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanListItem,
    ErrorResponse
)

# Initialize FastAPI app
app = FastAPI(
    title="nScanner",
    description="Safe, non-intrusive network port scanner with security checks",
    version="1.0.0"
)

# Setup templates
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Mount static files if directory exists
static_dir = os.path.join(BASE_DIR, "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.post(
    "/api/scan",
    response_model=ScanResponse,
    responses={400: {"model": ErrorResponse}}
)
async def api_start_scan(scan_request: ScanRequest):
    """
    Initiate a new port scan.
    
    **Parameters:**
    - host: Target hostname or IP address
    - ports: Port specification (e.g., "22,80,443" or "1-1024")
    
    **Returns:**
    - scan_id: Unique identifier for tracking this scan
    - status: Current scan status
    - message: Human-readable status message
    """
    try:
        scan_id = await start_scan_async(scan_request.host, scan_request.ports)
        return ScanResponse(
            scan_id=scan_id,
            status="queued",
            message=f"Scan initiated for {scan_request.host}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@app.get(
    "/api/scan/{scan_id}",
    response_model=ScanResult,
    responses={404: {"model": ErrorResponse}}
)
async def api_get_scan(scan_id: str):
    """
    Retrieve scan results by scan ID.
    
    **Parameters:**
    - scan_id: Unique scan identifier
    
    **Returns:**
    Complete scan results including all findings and risk assessment
    """
    scan_data = get_scan(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_data


@app.get(
    "/api/scans",
    response_model=list[ScanListItem]
)
async def api_list_scans(
    limit: int = Query(50, ge=1, le=100, description="Maximum scans to return"),
    offset: int = Query(0, ge=0, description="Number of scans to skip")
):
    """
    List all scans with pagination.
    
    **Parameters:**
    - limit: Maximum number of scans to return (1-100)
    - offset: Number of scans to skip for pagination
    
    **Returns:**
    List of scan summaries
    """
    return list_scans(limit=limit, offset=offset)


@app.delete(
    "/api/scan/{scan_id}",
    responses={404: {"model": ErrorResponse}}
)
async def api_delete_scan(scan_id: str):
    """
    Delete a scan from the database.
    
    **Parameters:**
    - scan_id: Unique scan identifier
    
    **Returns:**
    Success message
    """
    if delete_scan(scan_id):
        return {"message": f"Scan {scan_id} deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Serve the main web interface.
    """
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring.
    """
    return {
        "status": "healthy",
        "service": "nscanner"
    }


# Error handlers - FIXED
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handle validation errors."""
    raise HTTPException(status_code=400, detail=str(exc))


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors."""
    raise HTTPException(status_code=500, detail="Internal server error")