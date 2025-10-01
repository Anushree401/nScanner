# app/core/risk.py
"""Risk scoring and scan summarization logic."""

from typing import List, Dict, Any
from .config import RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD


def severity_weight(severity: str) -> int:
    """
    Convert severity level to numeric weight.
    
    Args:
        severity: Severity level string (critical, high, medium, low, info)
        
    Returns:
        Numeric weight for the severity level
    """
    severity = (severity or "medium").lower()
    weights = {
        "critical": 50,
        "high": 30,
        "medium": 15,
        "low": 5,
        "info": 0
    }
    return weights.get(severity, 10)


def compute_port_score(port_entry: Dict[str, Any]) -> int:
    """
    Calculate risk score for a single port scan result.
    
    Args:
        port_entry: Dictionary containing port scan results
        
    Returns:
        Risk score (0-100) for this port
    """
    if port_entry.get("state") != "open":
        return 0
    
    # Base score for an open port
    score = 10
    
    # Add scores for each finding based on severity
    for finding in port_entry.get("findings", []):
        if isinstance(finding, dict):
            sev = finding.get("severity", finding.get("sev", "medium"))
            score += severity_weight(sev)
        else:
            # Unknown structure - small bump
            score += 5
    
    # Additional risk for inherently risky ports
    risky_ports = {
        23: 20,    # Telnet - unencrypted
        3389: 15,  # RDP - often targeted
        3306: 10,  # MySQL - database exposure
        5432: 10,  # PostgreSQL - database exposure
        5900: 15,  # VNC - remote access
        1433: 10,  # MSSQL - database exposure
        27017: 10  # MongoDB - database exposure
    }
    
    port = port_entry.get("port")
    if port in risky_ports:
        score += risky_ports[port]
    
    # Add score based on base severity from mapping
    base_severity = port_entry.get("base_severity", "low")
    score += severity_weight(base_severity)
    
    # Cap at 100
    return min(100, score)


def summarize_scan(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate summary statistics and risk assessment for scan results.
    
    Args:
        results: List of port scan result dictionaries
        
    Returns:
        Dictionary containing:
        - risk_score: Overall risk score (0-100)
        - risk_level: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        - open_ports: Count of open ports
        - closed_ports: Count of closed ports
        - error_count: Count of errors encountered
        - total_findings: Total number of findings across all ports
        - critical_findings: Count of critical severity findings
        - high_findings: Count of high severity findings
    """
    open_ports = 0
    closed_ports = 0
    error_count = 0
    total_findings = 0
    critical_findings = 0
    high_findings = 0
    per_port_scores = []
    
    for entry in results:
        if entry.get("error"):
            error_count += 1
            continue
        
        state = entry.get("state")
        if state == "open":
            open_ports += 1
            
            # Count findings by severity
            for finding in entry.get("findings", []):
                total_findings += 1
                if isinstance(finding, dict):
                    sev = finding.get("severity", "").lower()
                    if sev == "critical":
                        critical_findings += 1
                    elif sev == "high":
                        high_findings += 1
            
            # Calculate port score
            port_score = compute_port_score(entry)
            per_port_scores.append(port_score)
            
        elif state == "closed":
            closed_ports += 1
    
    # Calculate average risk score
    if per_port_scores:
        avg_score = sum(per_port_scores) // len(per_port_scores)
        max_score = max(per_port_scores)
        
        # Weight average toward max if there are critical findings
        if critical_findings > 0:
            avg_score = int(avg_score * 0.5 + max_score * 0.5)
    else:
        avg_score = 0
    
    # Determine risk level
    if avg_score >= RISK_HIGH_THRESHOLD or critical_findings > 0:
        level = "HIGH"
    elif avg_score >= RISK_MEDIUM_THRESHOLD or high_findings > 2:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    # Special case: if many risky ports are open, escalate
    if open_ports > 10:
        if level == "LOW":
            level = "MEDIUM"
        elif level == "MEDIUM" and open_ports > 20:
            level = "HIGH"
    
    return {
        "risk_score": avg_score,
        "risk_level": level,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "error_count": error_count,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "ports_scanned": open_ports + closed_ports
    }