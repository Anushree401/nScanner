#!/usr/bin/env python3
"""
portscanner_safe.py

- Minimal TCP port scanner (no nmap).
- Banner grabbing and safe automated checks (HTTP headers, TLS cert info,
  SMTP/SSH/FTP banners, OPTIONS methods, STARTTLS support check).
- Maps ports -> potential findings (non-exploitative) and suggested remediation.
- CLI friendly and can be imported by FastAPI app.
"""

import argparse
import sys
import time
from colorama import Fore, Style, init
import socket
import requests
import ssl
from datetime import datetime
from typing import List

init(autoreset=True)

# -------------------------
# helper funcs 
# -------------------------
def validate_port(port):
    """Validate port number (1-65535)."""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except Exception:
        return False

def mapping_port_for_vulnerability(port):
    """High-level mapping: non-exploitative hint text + remediation suggestions."""
    if port == 21:
        return {"summary":"FTP - anonymous or outdated servers may expose files.",
                "remediation":"Disable anonymous FTP, require auth or use SFTP/FTPS."}
    elif port == 22:
        return {"summary":"SSH - check for old ciphers and weak configs.",
                "remediation":"Enforce strong ciphers, disable password auth, use key auth, keep OpenSSH updated."}
    elif port == 23:
        return {"summary":"Telnet - unencrypted comms (legacy).",
                "remediation":"Disable Telnet; use SSH."}
    elif port == 25:
        return {"summary":"SMTP - open relay or missing STARTTLS is a risk.",
                "remediation":"Ensure STARTTLS is configured, disable open relay, and validate auth policies."}
    elif port == 53:
        return {"summary":"DNS - zone transfers or misconfig may leak data.",
                "remediation":"Restrict AXFR to authorized hosts and secure recursive resolvers."}
    elif port == 80:
        return {"summary":"HTTP - missing security headers or old server versions.",
                "remediation":"Add security headers (CSP, HSTS, X-Frame-Options), patch web server."}
    elif port == 110:
        return {"summary":"POP3 - unencrypted credentials risk.",
                "remediation":"Use POP3S or IMAPS, require encryption."}
    elif port == 143:
        return {"summary":"IMAP - unencrypted credentials risk.",
                "remediation":"Use IMAPS or require TLS."}
    elif port == 443:
        return {"summary":"HTTPS - TLS config issues possible (expired certs, weak protocols).",
                "remediation":"Enforce strong TLS protocols, renew certs, disable legacy ciphers."}
    elif port == 3306:
        return {"summary":"MySQL - exposed DB may allow data access.",
                "remediation":"Restrict access to DB ports to internal networks and require auth."}
    elif port == 3389:
        return {"summary":"RDP - exposed RDP can be brute-forced or exploited when unpatched.",
                "remediation":"Place behind VPN, enforce NLA, limit IP access and patch regularly."}
    elif port == 5900:
        return {"summary":"VNC - often unencrypted and allows remote control.",
                "remediation":"Require authentication, use secure tunnels."}
    elif port == 8080:
        return {"summary":"HTTP Proxy / Alternative HTTP - same web risks apply.",
                "remediation":"Harden web service, restrict proxying and open access."}
    else:
        return {"summary":"Generic service - no specific checks mapped.", "remediation":"Investigate service and ensure latest patches and network segmentation."}

# -------------------------
# Safe automated checks (non-exploitative)
# -------------------------
def safe_http_checks(host, port, use_https=False):
    """Perform safe, read-only HTTP checks: GET/HEAD, security headers, allowed methods."""
    findings = []
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        # Prefer HEAD first (lighter)
        resp = requests.head(url, timeout=5, allow_redirects=True, verify=False)
    except requests.RequestException:
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True, verify=False)
        except requests.RequestException as e:
            findings.append({"type":"http_unreachable", "detail":str(e)})
            return findings

    # status ok or redirect are fine — record server header
    server = resp.headers.get("Server")
    if server:
        findings.append({"type":"server_header", "detail":f"Server header: {server}"})

    # Security headers to check
    sec_headers = {
        "Strict-Transport-Security":"HSTS (recommended for HTTPS)",
        "Content-Security-Policy":"CSP (helps mitigate XSS)",
        "X-Frame-Options":"X-Frame-Options (clickjacking mitigation)",
        "X-Content-Type-Options":"X-Content-Type-Options (nosniff)",
        "Referrer-Policy":"Referrer-Policy (privacy)"
    }
    for h,k in sec_headers.items():
        if h not in resp.headers:
            findings.append({"type":"missing_header", "detail":f"Missing header: {h} - {k}"})

    # Check allowed methods via OPTIONS (safe)
    try:
        opt = requests.options(url, timeout=4, verify=False)
        allow = opt.headers.get("Allow") or opt.headers.get("allow") # passes only if present, which is decided by the network on which the script is run 
        if allow:
            findings.append({"type":"allowed_methods", "detail":f"Allowed methods: {allow}"})
            # if methods include PUT/DELETE without auth, we cannot test further (do not attempt)
            if any(m in allow.upper() for m in ["PUT", "DELETE"]):
                findings.append({"type":"potential_risk_methods", "detail":"Server advertises PUT/DELETE - review if these require auth."})
    except requests.RequestException:
        pass

    return findings

def safe_tls_checks(host, port):
    """Collect TLS certificate info (expiry, issuer). Non-invasive.
    Use of this is that it will use SNI to get the correct cert for the host we are connecting to from the Root CA bundle. Hence it verifies the cert chain to ensure it is valid and no common errors like expired certs, self-signed certs, or hostname mismatches that commonly occur in real-world scenarios occur in the cert presented by the server.
    
    Common errors that can occur:
    - Expired Certificate: The certificate's validity period has ended.
    - Self-Signed Certificate: The certificate is signed by the same entity that created it, rather than a trusted Certificate Authority (CA).
    - Untrusted CA: The certificate is signed by a CA that is not in the client's trusted CA list.
    - Hostname Mismatch: The hostname in the URL does not match the Common Name (CN) or Subject Alternative Names (SAN) in the certificate.
    
    CVEs related to TLS/SSL misconfigurations:
    - CVE-2014-3566 (POODLE): A vulnerability in SSL 3.0 that allows an attacker to decrypt secure connections.
    - CVE-2015-0204 (FREAK): A vulnerability that allows attackers to force a downgrade of the encryption used in SSL/TLS connections.
    - CVE-2016-2107: A padding oracle attack against AES-NI based implementations of AES-CBC in TLS.
    - CVE-2018-0732: A vulnerability in OpenSSL that could allow an attacker to cause a denial of service (DoS) or potentially execute arbitrary code.
    - CVE-2020-1967: A vulnerability in OpenSSL's handling of TLS 1.3 that could allow an attacker to crash the server or client.
    - CVE-2021-3449: A NULL pointer dereference in OpenSSL's TLS 1.3 implementation that could lead to a denial of service.
    - CVE-2021-3711 (High): A buffer overflow in OpenSSL's ChaCha20-Poly1305 implementation that could allow an attacker to execute arbitrary code.
    - CVE-2022-0778: A vulnerability in OpenSSL's handling of X.509 certificates that could allow an attacker to cause a denial of service.
    - CVE-2023-0464: A vulnerability in OpenSSL's TLS 1.3 implementation that could allow an attacker to crash the server or client.
    - CVE-2023-23397: A vulnerability in Microsoft Outlook that could allow an attacker to steal NTLM hashes via specially crafted emails.
    
    Most of these were due to improper validation, outdated protocols, or weak cipher suites.
    Cipher suite misconfigurations can lead to vulnerabilities like BEAST, CRIME, and others.
    Cipher suites are those that use RC4, DES, 3DES, or export-grade encryption are considered weak."""
    findings = []
    try:
        ctx = ssl.create_default_context() # uses system CA bundle 
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s: # SNI = means server_hostname is set = means SNI is used 
        # SNI means the client tells the server which hostname it is connecting to at the start of the handshake. This is crucial for servers hosting multiple domains on the same IP address, as it allows them to present the correct SSL/TLS certificate for the requested domain.
        # so here we are using SNI to get the correct cert for the host we are connecting to from the Root CA bundle 
        # if the server does not support SNI, it may return a default certificate or fail the handshake.
            s.settimeout(5)
            s.connect((host, port)) # TCP connect to host:port
            # get cert
            cert = s.getpeercert() # this will return the cert in a dict format that is stored in the variable cert list in the browser
            # cert is a dict; check notAfter
            notAfter = cert.get("notAfter") # this will return the expiry date of the cert
            if notAfter:
                # example format: 'Jun  1 12:00:00 2026 GMT'
                exp_dt = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_dt - datetime.utcnow()).days
                findings.append({"type":"cert_expiry", "detail":f"Cert expires in {days_left} days ({notAfter})"})
                if days_left < 30:
                    findings.append({"type":"cert_soon_expire", "detail":"Certificate expires in less than 30 days."}) # findings of cert expiry
            # issuer of cert 
            issuer = cert.get("issuer")
            if issuer:
                findings.append({"type":"cert_issuer", "detail":f"Issuer: {issuer}"}) # findings of cert issuer
    except Exception as e:
        findings.append({"type":"tls_error", "detail":str(e)})
    return findings

def safe_banner_grab(host, port):
    """Attempt to grab a small banner from a plain TCP connect (non-invasive).
    
    This function will attempt to connect to the specified host and port using a TCP socket. It sets a timeout for the connection and tries to read a small amount of data (up to 2048 bytes) from the socket. If data is received, it decodes the data to a string and returns it. If no data is received or if any exceptions occur during the connection or data reading process, it returns an empty string.
    
    Note: This function does not send any data to the server; it only attempts to read any initial banner that the server might send upon connection. This is a common technique used for services like FTP, SMTP, and HTTP, which often send a greeting or banner message when a client connects.
    
    Purpose and Use Cases:
    - Service Identification: Many services send a banner that includes the service name and version, which can be useful for identifying the service running on a particular port.
    - Security Assessments: Understanding the service and version can help in assessing potential vulnerabilities associated with that service.
    - Network Diagnostics: Banner grabbing can be used to verify that the expected service is running on a given port. Hence it can determine if a service is up and responding.
    - Compliance and Auditing: Ensuring that services are properly configured and not exposing unnecessary information via banners.
    - Compliance Checks: Ensuring that services are properly configured and not exposing unnecessary information.
    Caution:
    - Ethical Considerations: Banner grabbing should be performed in accordance with legal and ethical guidelines, including obtaining permission to scan the target system.
    - Limited Information: Not all services provide useful banners, and some may provide misleading information."""
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            # Try to read banner quickly
            # this will read the inital contents sent by the server, which is usually a banner or greeting message "Hello from xyz service"
            sock.settimeout(2)
            try:
                data = sock.recv(2048) # read up to 2048 bytes
                if data:
                    return data.decode(errors="ignore").strip() # decode bytes to string 
            except Exception:
                return ""
    except Exception:
        return ""
    return ""

def safe_smtp_checks(host, port):
    """Grab SMTP banner and check for STARTTLS support (via EHLO parsing).
    
     This function attempts to connect to an SMTP server on the specified host and port, retrieves the server's banner, and checks if the server supports the STARTTLS command. It performs the following steps:
    1. Establishes a TCP connection to the SMTP server using a socket with a timeout.
    2. Reads the initial banner sent by the server upon connection.
    3. Sends an EHLO command to the server to request its capabilities.
    4. Parses the server's response to the EHLO command to check for the presence of the 'STARTTLS' capability.' This means the server supports upgrading the connection to a secure TLS/SSL connection. Which means the server supports encryption for email transmission, enhancing security and protecting against eavesdropping.
    5. Collects findings in a list of dictionaries, each containing a 'type' and 'detail' key.
    6. Returns the list of findings, which may include the SMTP banner, STARTTLS support status, or any connection errors encountered."""
    findings = []
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.settimeout(3)
            banner = s.recv(1024).decode(errors="ignore") # again, read banner
            if banner:
                findings.append({"type":"smtp_banner", "detail":banner.strip()})
            # send EHLO (non-authenticating) to read capabilities
            try:
                s.sendall(b"EHLO example.com\r\n") # send EHLO command to the server
                caps = s.recv(4096).decode(errors="ignore") # read response, which may include multiple lines; if server supports STARTTLS, it will be listed here, and that will be determined by checking if "STARTTLS" is in the response
                if "STARTTLS" in caps.upper():
                    findings.append({"type":"smtp_starttls", "detail":"Server advertises STARTTLS"}) # if STARTTLS is found in the response, it means the server supports it
                else:
                    findings.append({"type":"smtp_no_starttls", "detail":"Server does not advertise STARTTLS"}) # if not found, it means the server does not support STARTTLS
            except Exception:
                pass
    except Exception as e:
        findings.append({"type":"smtp_conn_error", "detail":str(e)})
    return findings

# -------------------------
# Core scanning functions 
# -------------------------
def process_port_socket(host_id, port, result_list):
    """Existing socket connect logic + attach safe automated checks and mapping.
    
    These automated checks are non-exploitative and safe to run on production systems.
    They do not attempt any authentication or intrusive actions. They only read banners and server responses.
    
    THe purpose of this function is to scan a specific port on a given host using a TCP socket connection. It attempts to connect to the specified port and, if successful, performs a series of safe automated checks to gather information about the service running on that port. The findings from these checks are then compiled into a structured format and appended to the provided result list.
    
    The checks inlude:
    - Basic banner grabbing to identify the service.
    - Port-specific safe checks (e.g., HTTP headers, TLS cert info, SMTP STARTTLS support).
    - Mapping the port to potential findings and remediation suggestions.
    The function handles various exceptions to ensure that any connection issues or unexpected errors are captured and reported in the results.
    
    The significance of this function lies in its ability to provide a comprehensive overview of the services running on a target host without causing disruption or requiring authentication. This makes it suitable for use in production environments where safety and non-intrusiveness are paramount.

    These kinds of checks are useful for:
    - Service Identification: Understanding what services are running on which ports.
    - Security Assessments: Identifying potential vulnerabilities or misconfigurations.
    - Compliance Checks: Ensuring that services are properly configured and not exposing unnecessary information.
    - Network Diagnostics: Verifying that services are up and responding as expected.
    - Ethical Considerations: Performing non-intrusive checks in accordance with legal and ethical guidelines.
    
    It is for light reconnaissance and should not be used for aggressive scanning or exploitation.

    SSL/TLS and SMTP are two different protocols used for secure communication over networks, but they serve different purposes and operate at different layers of the network stack. 
    SSL/TLS (Secure Sockets Layer / Transport Layer Security):
    - Purpose: SSL/TLS is a cryptographic protocol designed to provide secure communication over a network. It is used to encrypt data transmitted between a client and a server, ensuring confidentiality, integrity, and authenticity.
    - Layer: SSL/TLS operates at the transport layer (Layer 4) of the OSI model, sitting between the application layer (Layer 7) and the transport layer (Layer 4).
    - Usage: SSL/TLS is commonly used to secure web traffic (HTTPS), email (SMTPS, IMAPS, POP3S), and other protocols that require secure communication.
    - Functionality: SSL/TLS provides encryption, authentication (via certificates), and data integrity checks.

    SMTP (Simple Mail Transfer Protocol):
    - Purpose: SMTP is a protocol used for sending and receiving email messages between mail servers. It is not inherently secure and does not provide encryption or authentication by itself.
    - Layer: SMTP operates at the application layer (Layer 7) of the OSI model.
    - Usage: SMTP is used for sending email messages from a client to a mail server or between mail servers. It is often used in conjunction with other protocols like IMAP or POP3 for retrieving email.
    - Functionality: SMTP defines how email messages are formatted and transmitted, but it does not include any security features.

    We separated the checks for SSL/TLS and SMTP because they address different aspects of network communication and security. SSL/TLS focuses on securing the communication channel itself, while SMTP is concerned with the transmission of email messages. By performing separate checks for each protocol, we can gather relevant information about both the security of the communication channel (via SSL/TLS) and the configuration and capabilities of the email service (via SMTP). This comprehensive approach helps in identifying potential vulnerabilities and misconfigurations in both areas.

    Potential inclusions of more protocols in the future:
    - FTP (File Transfer Protocol): Check for anonymous login and banner grabbing.
    - SSH (Secure Shell): Banner grabbing and checking for weak configurations (without attempting authentication).
    - Telnet: Banner grabbing (note: Telnet is insecure and should be avoided in favor of SSH).
    - POP3/IMAP: Banner grabbing and checking for STARTTLS support.
    - RDP (Remote Desktop Protocol): Banner grabbing (limited info available).
    - MySQL/PostgreSQL: Banner grabbing and version detection (without attempting authentication).
    - VNC (Virtual Network Computing): Banner grabbing (limited info available).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)  # 3 seconds
            conn_result = sock.connect_ex((host_id, port)) # checks if port is open or closed, returns 0 on success
            if conn_result == 0: 
                # open
                try:
                    service = socket.getservbyport(port) # get common service name for port
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
                # basic banner
                banner = safe_banner_grab(host_id, port) # attempt to grab banner
                if banner:
                    entry["banner"] = banner
                    entry["findings"].append({"type":"banner", "detail":banner})

                # port-specific safe checks
                if port in (80, 8080):
                    entry["findings"] += safe_http_checks(host_id, port, use_https=False)
                if port == 443:
                    entry["findings"] += safe_http_checks(host_id, port, use_https=True)
                    entry["findings"] += safe_tls_checks(host_id, port)
                if port in (465, 587):  # SMTP over TLS or submission
                    entry["findings"] += safe_smtp_checks(host_id, port)
                if port == 25:
                    entry["findings"] += safe_smtp_checks(host_id, port)
                if port == 22:
                    # SSH: banner is often sent on connect
                    if not entry["banner"]:
                        b = safe_banner_grab(host_id, port)
                        if b:
                            entry["banner"] = b
                            entry["findings"].append({"type":"banner", "detail":b})
                    # do not attempt authentication
                # attach mapping summary & remediation
                mapping = mapping_port_for_vulnerability(port)
                entry["mapping_summary"] = mapping["summary"]
                entry["remediation"] = mapping["remediation"]
                result_list.append(entry)
            else:
                result_list.append({
                    "host": host_id,
                    "port": port,
                    "state": "closed"
                })
    except socket.gaierror:
        result_list.append({"error": f"Hostname could not be resolved: {host_id}"})
    except socket.error as e:
        result_list.append({"error": f"Socket error connecting to {host_id}:{port} - {str(e)}"})
    except Exception as e:
        result_list.append({"error": f"Unexpected Error on port {port}: {str(e)}"})

def scanning(host_id, port_num):
    """Parse port spec and scan (supports comma-separated and ranges).
    
    This function scans specified ports on a given host using TCP socket connections. It supports both individual ports and port ranges, allowing for flexible scanning options. The function performs the following steps:
    1. Cleans and validates the input port specification.
    2. Iterates through each port or range of ports, validating each port number.
    3. For each valid port, it calls the `process_port_socket` function to perform the actual scanning and information gathering.
    4. Collects and returns the results of the scans, including open/closed status and any findings from the safe automated checks.

    The significance of this function lies in its ability to efficiently handle various port specifications and ensure that only valid ports are scanned. By leveraging the `process_port_socket` function, it provides a comprehensive overview of the services running on the target host while maintaining safety and non-intrusiveness. This makes it suitable for use in production environments where safety and non-intrusiveness are paramount."""
    
    port_num_cleaned = port_num.replace(" ", "")
    if not port_num_cleaned:
        return [f"\n{Fore.RED}[!] No valid ports specified.{Style.RESET_ALL}"]
    print(f"\n{Fore.GREEN}[*] Scanning {host_id} on port(s): {port_num_cleaned}{Style.RESET_ALL}")
    result = []
    for port_entry in port_num_cleaned.split(","):
        port_entry = port_entry.strip()
        if '-' in port_entry:
            try:
                start, end = map(int, port_entry.split('-'))
                if start > end:
                    result.append({"error": f"Invalid range: {start}-{end} (start > end)"})
                    continue
                for port in range(start, end + 1):
                    if not validate_port(port):
                        result.append({"error": f"Invalid port: {port}"})
                        continue
                    process_port_socket(host_id, port, result)
            except ValueError:
                result.append({"error": f"Invalid port range format: {port_entry}"})
                continue
        elif port_entry.isdigit():
            if not validate_port(port_entry):
                result.append({"error": f"Invalid port: {port_entry}"})
                continue
            process_port_socket(host_id, int(port_entry), result)
        else:
            result.append({"error": f"Invalid port format: {port_entry}"})
    return result

# -------------------------
# CLI printing helpers
# -------------------------
def print_summary(results):
    open_ports = [r for r in results if r.get("state") == "open"]
    print("-" * 80)
    print(f"Open ports found: {len(open_ports)}")
    for item in results:
        if item.get("state") != "open":
            continue
        print(f"{Fore.GREEN}[+] {item['host']}:{item['port']}  service={item.get('service','?')} {Style.RESET_ALL}")
        if item.get("banner"):
            print(f"    banner: {item['banner']}")
        # mapping summary
        print(f"    summary: {item.get('mapping_summary')}")
        print(f"    remediation: {item.get('remediation')}")
        # findings
        if item.get("findings"):
            for f in item["findings"]:
                # avoid repeating banner
                if f.get("type") == "banner":
                    continue
                print(f"    - {f.get('type')}: {f.get('detail')}")
        print()
    print("-" * 80)

# -------------------------
# Main CLI entry
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Safe TCP port scanner with passive checks (non-exploitative).")
    parser.add_argument("-H", "--host", required=True, help="Host IP or name")
    parser.add_argument("-p", "--port", default="1-1024", help="Port spec: '22,80,443' or '1-1024'")
    args = parser.parse_args()

    start = time.time()
    results = scanning(args.host, args.port)
    elapsed = time.time() - start
    print_summary(results)
    print(f"Scan completed in {elapsed:.2f}s")

if __name__ == "__main__":
    main()
