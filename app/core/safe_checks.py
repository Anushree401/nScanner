# app/core/safe_checks.py
"""Non-intrusive security checks for various services."""

import socket
import requests
import ssl
from datetime import datetime
from typing import List, Dict
import urllib3
from app.core.config import (
    SOCKET_CONNECT_TIMEOUT, SOCKET_RECV_TIMEOUT,
    HTTP_REQUEST_TIMEOUT, TLS_HANDSHAKE_TIMEOUT,
    SMTP_TIMEOUT, HTTP_CHECK_RETRIES
)

# Disable only the specific warning about unverified HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def safe_banner_grab(host: str, port: int) -> str:
    """
    Attempt to grab a service banner via TCP connection.
    
    Args:
        host: Target hostname or IP
        port: Target port number
        
    Returns:
        Banner string if received, empty string otherwise
    """
    try:
        with socket.create_connection((host, port), timeout=SOCKET_CONNECT_TIMEOUT) as sock:
            sock.settimeout(SOCKET_RECV_TIMEOUT)
            try:
                data = sock.recv(2048)
                if data:
                    return data.decode(errors="ignore").strip()
            except socket.timeout:
                return ""
            except Exception:
                return ""
    except Exception:
        return ""
    return ""


def safe_http_checks(host: str, port: int, use_https: bool = False) -> List[Dict[str, str]]:
    """
    Perform safe HTTP/HTTPS checks including headers and methods.
    
    Note: SSL verification is disabled to allow checking of misconfigured
    servers. In production, consider making this configurable.
    
    Args:
        host: Target hostname or IP
        port: Target port number
        use_https: Whether to use HTTPS
        
    Returns:
        List of findings dictionaries
    """
    findings = []
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"
    
    resp = None
    for attempt in range(HTTP_CHECK_RETRIES):
        try:
            # Try HEAD first (lighter)
            resp = requests.head(
                url,
                timeout=HTTP_REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False  # Intentionally disabled for security testing
            )
            break
        except requests.RequestException:
            if attempt < HTTP_CHECK_RETRIES - 1:
                continue
            # Last attempt - try GET
            try:
                resp = requests.get(
                    url,
                    timeout=HTTP_REQUEST_TIMEOUT,
                    allow_redirects=True,
                    verify=False
                )
                break
            except requests.RequestException as e:
                findings.append({
                    "type": "http_unreachable",
                    "detail": str(e),
                    "severity": "info"
                })
                return findings
    
    if not resp:
        return findings
    
    # Check Server header
    server = resp.headers.get("Server")
    if server:
        findings.append({
            "type": "server_header",
            "detail": f"Server header: {server}",
            "severity": "info"
        })
    
    # Security headers check
    sec_headers = {
        "Strict-Transport-Security": ("HSTS (recommended for HTTPS)", "medium"),
        "Content-Security-Policy": ("CSP (helps mitigate XSS)", "medium"),
        "X-Frame-Options": ("X-Frame-Options (clickjacking mitigation)", "low"),
        "X-Content-Type-Options": ("X-Content-Type-Options (nosniff)", "low"),
        "Referrer-Policy": ("Referrer-Policy (privacy)", "low")
    }
    
    for header, (description, severity) in sec_headers.items():
        if header not in resp.headers:
            findings.append({
                "type": "missing_header",
                "detail": f"Missing header: {header} - {description}",
                "severity": severity
            })
    
    # Check allowed methods via OPTIONS
    try:
        opt = requests.options(url, timeout=HTTP_REQUEST_TIMEOUT - 1, verify=False)
        allow = opt.headers.get("Allow") or opt.headers.get("allow")
        if allow:
            findings.append({
                "type": "allowed_methods",
                "detail": f"Allowed methods: {allow}",
                "severity": "info"
            })
            if any(m in allow.upper() for m in ["PUT", "DELETE"]):
                findings.append({
                    "type": "potential_risk_methods",
                    "detail": "Server advertises PUT/DELETE - review if these require auth.",
                    "severity": "medium"
                })
    except requests.RequestException:
        pass
    
    return findings


def safe_tls_checks(host: str, port: int) -> List[Dict[str, str]]:
    """
    Collect TLS certificate information non-invasively.
    
    Args:
        host: Target hostname or IP
        port: Target port number
        
    Returns:
        List of findings dictionaries
    """
    findings = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(TLS_HANDSHAKE_TIMEOUT)
            s.connect((host, port))
            cert = s.getpeercert()
            
            # Check certificate expiry
            notAfter = cert.get("notAfter")
            if notAfter:
                try:
                    exp_dt = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_dt - datetime.utcnow()).days
                    findings.append({
                        "type": "cert_expiry",
                        "detail": f"Cert expires in {days_left} days ({notAfter})",
                        "severity": "info"
                    })
                    if days_left < 30:
                        severity = "high" if days_left < 7 else "medium"
                        findings.append({
                            "type": "cert_soon_expire",
                            "detail": f"Certificate expires in {days_left} days.",
                            "severity": severity
                        })
                    elif days_left < 0:
                        findings.append({
                            "type": "cert_expired",
                            "detail": "Certificate has expired!",
                            "severity": "critical"
                        })
                except ValueError as e:
                    findings.append({
                        "type": "cert_parse_error",
                        "detail": f"Could not parse certificate date: {e}",
                        "severity": "low"
                    })
            
            # Check issuer
            issuer = cert.get("issuer")
            if issuer:
                issuer_str = ", ".join([f"{k}={v}" for tuples in issuer for k, v in tuples])
                findings.append({
                    "type": "cert_issuer",
                    "detail": f"Issuer: {issuer_str}",
                    "severity": "info"
                })
            
            # Check subject
            subject = cert.get("subject")
            if subject:
                subject_str = ", ".join([f"{k}={v}" for tuples in subject for k, v in tuples])
                findings.append({
                    "type": "cert_subject",
                    "detail": f"Subject: {subject_str}",
                    "severity": "info"
                })
                
    except ssl.SSLError as e:
        findings.append({
            "type": "tls_error",
            "detail": f"SSL/TLS error: {str(e)}",
            "severity": "high"
        })
    except socket.timeout:
        findings.append({
            "type": "tls_timeout",
            "detail": "TLS handshake timeout",
            "severity": "medium"
        })
    except Exception as e:
        findings.append({
            "type": "tls_error",
            "detail": str(e),
            "severity": "medium"
        })
    
    return findings


def safe_smtp_checks(host: str, port: int) -> List[Dict[str, str]]:
    """
    Check SMTP banner and STARTTLS support.
    
    Args:
        host: Target hostname or IP
        port: Target port number
        
    Returns:
        List of findings dictionaries
    """
    findings = []
    try:
        with socket.create_connection((host, port), timeout=SMTP_TIMEOUT) as s:
            s.settimeout(SMTP_TIMEOUT - 2)
            
            # Read banner
            banner = s.recv(1024).decode(errors="ignore")
            if banner:
                findings.append({
                    "type": "smtp_banner",
                    "detail": banner.strip(),
                    "severity": "info"
                })
            
            # Send EHLO to check capabilities
            try:
                s.sendall(b"EHLO scanner.local\r\n")
                caps = s.recv(4096).decode(errors="ignore")
                
                if "STARTTLS" in caps.upper():
                    findings.append({
                        "type": "smtp_starttls",
                        "detail": "Server advertises STARTTLS",
                        "severity": "info"
                    })
                else:
                    findings.append({
                        "type": "smtp_no_starttls",
                        "detail": "Server does not advertise STARTTLS - unencrypted communication",
                        "severity": "high" if port == 25 else "medium"
                    })
                
                # Check for AUTH
                if "AUTH" in caps.upper():
                    findings.append({
                        "type": "smtp_auth",
                        "detail": "Server supports authentication",
                        "severity": "info"
                    })
                    
            except socket.timeout:
                findings.append({
                    "type": "smtp_timeout",
                    "detail": "Timeout waiting for EHLO response",
                    "severity": "low"
                })
            except Exception as e:
                findings.append({
                    "type": "smtp_ehlo_error",
                    "detail": f"Error during EHLO: {str(e)}",
                    "severity": "low"
                })
                
    except socket.timeout:
        findings.append({
            "type": "smtp_conn_timeout",
            "detail": "Connection timeout",
            "severity": "medium"
        })
    except Exception as e:
        findings.append({
            "type": "smtp_conn_error",
            "detail": str(e),
            "severity": "medium"
        })
    
    return findings