# app/core/rules.py
"""Port to vulnerability mapping with remediation guidance."""

from typing import Dict, TypedDict


class VulnerabilityInfo(TypedDict):
    summary: str
    remediation: str
    severity: str


def mapping_port_for_vulnerability(port: int) -> VulnerabilityInfo:
    """
    Map a port number to potential vulnerabilities and remediation advice.
    
    Args:
        port: The port number to check
        
    Returns:
        Dictionary containing summary, remediation, and severity information
    """
    mapping: Dict[int, VulnerabilityInfo] = {
        21: {
            "summary": "FTP - Check for anonymous login and known vulnerabilities.",
            "remediation": "Disable anonymous FTP, require auth or use SFTP/FTPS.",
            "severity": "medium"
        },
        22: {
            "summary": "SSH - Check for weak credentials and outdated versions.",
            "remediation": "Enforce strong ciphers, disable password auth, use key auth, keep OpenSSH updated.",
            "severity": "low"
        },
        23: {
            "summary": "Telnet - Check for weak credentials and unencrypted communication.",
            "remediation": "Disable Telnet; use SSH instead.",
            "severity": "high"
        },
        25: {
            "summary": "SMTP - Check for open relay and email spoofing vulnerabilities.",
            "remediation": "Ensure STARTTLS is configured, disable open relay, and validate auth policies.",
            "severity": "medium"
        },
        53: {
            "summary": "DNS - Check for DNS cache poisoning and zone transfer vulnerabilities.",
            "remediation": "Restrict AXFR to authorized hosts and secure recursive resolvers.",
            "severity": "medium"
        },
        80: {
            "summary": "HTTP - Check for common web vulnerabilities (XSS, SQLi, missing headers).",
            "remediation": "Harden web app, add security headers (CSP, HSTS, X-Frame-Options), patch frameworks.",
            "severity": "medium"
        },
        110: {
            "summary": "POP3 - Check for weak credentials and unencrypted communication.",
            "remediation": "Use POP3S or IMAPS; require TLS.",
            "severity": "medium"
        },
        143: {
            "summary": "IMAP - Check for weak credentials and unencrypted communication.",
            "remediation": "Use IMAPS or require TLS.",
            "severity": "medium"
        },
        443: {
            "summary": "HTTPS - Check for SSL/TLS vulnerabilities and misconfigurations.",
            "remediation": "Enforce strong TLS protocols (1.2+), renew certificates, disable legacy ciphers.",
            "severity": "low"
        },
        465: {
            "summary": "SMTPS - SMTP over SSL/TLS. Check certificate validity.",
            "remediation": "Ensure valid certificates and strong TLS configuration.",
            "severity": "low"
        },
        587: {
            "summary": "SMTP Submission - Check for proper authentication and TLS.",
            "remediation": "Require STARTTLS and authentication for all submissions.",
            "severity": "medium"
        },
        3306: {
            "summary": "MySQL - Check for weak credentials and SQL injection vulnerabilities.",
            "remediation": "Restrict access to DB ports to internal networks only; require auth; use least privilege.",
            "severity": "high"
        },
        3389: {
            "summary": "RDP - Check for weak credentials and unpatched vulnerabilities.",
            "remediation": "Place behind VPN, enforce NLA, limit IP access and patch regularly.",
            "severity": "critical"
        },
        5432: {
            "summary": "PostgreSQL - Check for exposed database and weak credentials.",
            "remediation": "Restrict access to internal networks; require strong authentication.",
            "severity": "high"
        },
        5900: {
            "summary": "VNC - Check for weak credentials and unencrypted communication.",
            "remediation": "Require strong authentication, use secure tunnels (SSH/VPN).",
            "severity": "high"
        },
        8080: {
            "summary": "HTTP Proxy/Alt - Check for open proxy and common web vulnerabilities.",
            "remediation": "Harden proxy, restrict access, implement authentication.",
            "severity": "medium"
        },
        8443: {
            "summary": "HTTPS Alt - Alternative HTTPS port. Check TLS configuration.",
            "remediation": "Same as port 443 - enforce strong TLS and valid certificates.",
            "severity": "low"
        }
    }
    
    return mapping.get(port, {
        "summary": "No specific vulnerability checks mapped for this port.",
        "remediation": "Investigate service and ensure latest patches and network segmentation.",
        "severity": "low"
    })