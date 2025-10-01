# app/core/scanner.py
"""Core port scanning functionality."""

import socket
from typing import List, Dict, Any
# ADD concurrent.futures for thread pooling
import concurrent.futures
from .safe_checks import safe_banner_grab, safe_http_checks, safe_tls_checks, safe_smtp_checks
from .rules import mapping_port_for_vulnerability
# Import MAX_CONCURRENT_SCANS
from .config import SOCKET_CONNECT_TIMEOUT, MIN_PORT, MAX_PORT, MAX_CONCURRENT_SCANS 


def validate_port(port: int) -> bool:
    """
    Validate that a port number is within valid range.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        port = int(port)
        return MIN_PORT <= port <= MAX_PORT
    except (ValueError, TypeError):
        return False


def process_port_socket(host_id: str, port: int, result_list: List[Dict[str, Any]]) -> None:
    """
    Scan a single port and gather information about the service.
    
    Performs TCP connection test and runs protocol-specific checks
    for common services (HTTP, HTTPS, SMTP, SSH).
    
    Args:
        host_id: Target hostname or IP address
        port: Port number to scan
        result_list: List to append results to (modified in place)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_CONNECT_TIMEOUT)
            conn_result = sock.connect_ex((host_id, port))
            
            if conn_result == 0:
                # Port is open
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                
                entry = {
                    "host": host_id,
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": "",
                    "findings": []
                }
                
                # Attempt banner grab
                banner = safe_banner_grab(host_id, port)
                if banner:
                    entry["banner"] = banner
                    entry["findings"].append({
                        "type": "banner",
                        "detail": banner,
                        "severity": "info"
                    })
                
                # Port-specific safe checks
                if port in (80, 8080, 8000):
                    entry["findings"].extend(safe_http_checks(host_id, port, use_https=False))
                
                if port in (443, 8443):
                    entry["findings"].extend(safe_http_checks(host_id, port, use_https=True))
                    entry["findings"].extend(safe_tls_checks(host_id, port))
                
                if port in (465, 587, 25):
                    entry["findings"].extend(safe_smtp_checks(host_id, port))
                
                if port == 22:
                    # SSH: banner is often sent on connect
                    if not entry["banner"]:
                        b = safe_banner_grab(host_id, port)
                        if b:
                            entry["banner"] = b
                            entry["findings"].append({
                                "type": "banner",
                                "detail": b,
                                "severity": "info"
                            })
                
                # Attach vulnerability mapping and remediation
                mapping = mapping_port_for_vulnerability(port)
                entry["mapping_summary"] = mapping["summary"]
                entry["remediation"] = mapping["remediation"]
                entry["base_severity"] = mapping["severity"]
                
                # Use a thread-safe append (the List is managed by the calling thread)
                result_list.append(entry)
            else:
                # Port is closed
                # Use a thread-safe append (the List is managed by the calling thread)
                result_list.append({
                    "host": host_id,
                    "port": port,
                    "state": "closed"
                })
                
    except socket.gaierror:
        result_list.append({
            "error": f"Hostname could not be resolved: {host_id}",
            "port": port
        })
    except socket.timeout:
        result_list.append({
            "error": f"Connection timeout to {host_id}:{port}",
            "port": port
        })
    except socket.error as e:
        result_list.append({
            "error": f"Socket error connecting to {host_id}:{port} - {str(e)}",
            "port": port
        })
    except Exception as e:
        result_list.append({
            "error": f"Unexpected error on port {port}: {str(e)}",
            "port": port
        })


def parse_port_spec(port_spec: str) -> List[int]:
    """
    Parse a port specification string into a list of port numbers.
    ... (omitted for brevity)
    """
    ports = []
    port_spec_cleaned = port_spec.replace(" ", "")
    
    if not port_spec_cleaned:
        raise ValueError("No valid ports specified")
    
    for port_entry in port_spec_cleaned.split(","):
        port_entry = port_entry.strip()
        
        if '-' in port_entry:
            # Handle port range
            try:
                start, end = map(int, port_entry.split('-'))
                if start > end:
                    raise ValueError(f"Invalid range: {start}-{end} (start > end)")
                if not (validate_port(start) and validate_port(end)):
                    raise ValueError(f"Invalid port range: {port_entry}")
                ports.extend(range(start, end + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range format: {port_entry} - {str(e)}")
        
        elif port_entry.isdigit():
            # Handle single port
            port = int(port_entry)
            if not validate_port(port):
                raise ValueError(f"Invalid port: {port_entry}")
            ports.append(port)
        
        else:
            raise ValueError(f"Invalid port format: {port_entry}")
    
    return sorted(list(set(ports)))  # Remove duplicates and sort


def scanning(host_id: str, port_num: str) -> List[Dict[str, Any]]:
    """
    Scan specified ports on a target host concurrently using a thread pool.
    
    Args:
        host_id: Target hostname or IP address
        port_num: Port specification (e.g., "22,80,443" or "1-1024")
        
    Returns:
        List of dictionaries containing scan results for each port
    """
    result = []
    
    try:
        ports = parse_port_spec(port_num)
    except ValueError as e:
        return [{"error": str(e)}]
    
    # Use ThreadPoolExecutor for concurrent scanning, using the configured limit
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS) as executor:
        # Submit all process_port_socket tasks
        futures = [
            executor.submit(process_port_socket, host_id, port, result) 
            for port in ports
        ]
        
        # Wait for all futures to complete
        concurrent.futures.wait(futures)
    
    # The 'result' list is modified in place by the worker threads
    return result