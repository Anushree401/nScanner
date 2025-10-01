#!/usr/bin/env python3
import argparse
import time
import socket
import requests
from colorama import Fore, Style, init

init(autoreset=True)

# ------------------ Argument Parser ------------------ #
def argument_parser():
    parser = argparse.ArgumentParser(
        description="TCP port scanner. Accepts a HostName/IP Address and list of ports to scan. "
                    "Attempts to identify the service running on a port."
    )
    parser.add_argument("-H", "--host", nargs="?", default="127.0.0.1",
                        help="Host IP Address (default: %(default)s)")
    parser.add_argument("-p", "--port", nargs="?", default="80",
                        help="Comma-separated port list, such as '25,80,8000' or ranges like '1-100' (default: %(default)s)")
    return vars(parser.parse_args())

# ------------------ Validation ------------------ #
def validate_port(port):
    """Validate port number (1-65535)."""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False

# ------------------ Scanning ------------------ #
def scanning(host_id, port_num):
    port_num_cleaned = port_num.replace(" ", "")
    if not port_num_cleaned:
        return [f"{Fore.RED}[!] No valid ports specified.{Style.RESET_ALL}"]

    results = []
    print(f"\n{Fore.GREEN}[*] Scanning {host_id} on port(s): {port_num_cleaned}{Style.RESET_ALL}")

    for port_entry in port_num_cleaned.split(","):
        port_entry = port_entry.strip()

        # Handle port ranges
        if '-' in port_entry:
            try:
                start, end = map(int, port_entry.split('-'))
                if start > end:
                    results.append(f"{Fore.RED}[-] Invalid range: {start}-{end} (start > end){Style.RESET_ALL}")
                    continue
                for port in range(start, end + 1):
                    if validate_port(port):
                        process_port_socket(host_id, port, results)
            except ValueError:
                results.append(f"{Fore.RED}[-] Invalid port range format: {port_entry}{Style.RESET_ALL}")
        
        # Handle single port
        elif port_entry.isdigit():
            port = int(port_entry)
            if validate_port(port):
                process_port_socket(host_id, port, results)
            else:
                results.append(f"{Fore.RED}[-] Invalid port: {port_entry}{Style.RESET_ALL}")
        
        else:
            results.append(f"{Fore.RED}[-] Invalid port format: {port_entry}{Style.RESET_ALL}")
    
    return results

# ------------------ Port Processor ------------------ #
def process_port_socket(host_id, port, results):
    """Attempt TCP connect to check open/closed and add vulnerability mapping & safe checks."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            conn_result = sock.connect_ex((host_id, port))
            if conn_result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"

                msg = f"{Fore.GREEN}[+] Host: {host_id} | Port: {port}/tcp | State: open | Service: {service}{Style.RESET_ALL}"
                results.append(msg)

                # Show mapped vulnerabilities
                vuln_info = mapping_port_for_vulnerability(port)
                results.append(f"{Fore.CYAN}[i] Potential Vulnerabilities: {vuln_info}{Style.RESET_ALL}")

                # Run safe automation tests
                test_result = script_automation_test(host_id, port)
                if test_result:
                    results.append(test_result)
            else:
                results.append(f"{Fore.YELLOW}[-] Host: {host_id} | Port: {port}/tcp | State: closed{Style.RESET_ALL}")
    except socket.gaierror:
        results.append(f"{Fore.RED}[!] Hostname could not be resolved: {host_id}{Style.RESET_ALL}")
    except socket.error:
        results.append(f"{Fore.RED}[!] Could not connect to server: {host_id}{Style.RESET_ALL}")
    except Exception as e:
        results.append(f"{Fore.RED}[!] Unexpected Error on port {port}: {str(e)}{Style.RESET_ALL}")

# ------------------ Vulnerability Mapping ------------------ #
def mapping_port_for_vulnerability(port): 
    mapping = {
        21: "FTP - Check for anonymous login and known vulnerabilities.",
        22: "SSH - Check for weak credentials and outdated versions.",
        23: "Telnet - Unencrypted communication, weak credentials possible.",
        25: "SMTP - Check for open relay and spoofing risks.",
        53: "DNS - Cache poisoning / zone transfer risks.",
        80: "HTTP - Web vulns like XSS, SQLi, missing security headers.",
        110:"POP3 - Weak credentials, clear-text comms.",
        143:"IMAP - Weak credentials, clear-text comms.",
        443:"HTTPS - TLS misconfigurations, weak protocols.",
        3306:"MySQL - Weak creds, exposed DB, SQL injection risks.",
        3389:"RDP - Exposed RDP often targeted, weak creds, exploits.",
        5900:"VNC - Unencrypted, weak authentication.",
        8080:"HTTP Proxy/Alt HTTP - Proxy abuse, common web vulns."
    }
    return mapping.get(port, "No specific vulnerability checks mapped for this port.")

# ------------------ Safe Automation Test ------------------ #
def script_automation_test(host_id, port_num):
    """Perform simple safe checks (no exploits)."""
    if port_num == 80:
        try:
            url = f"http://{host_id}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return (f"{Fore.GREEN}[+] HTTP reachable at {url}{Style.RESET_ALL}\n"
                        f"    Suggested: Run web vulnerability tests (headers, XSS, SQLi) manually or via tools.")
            else:
                return f"{Fore.YELLOW}[-] HTTP returned {response.status_code} at {url}{Style.RESET_ALL}"
        except requests.RequestException as e:
            return f"{Fore.RED}[!] HTTP unreachable at {url} - {str(e)}{Style.RESET_ALL}"
    
    if port_num == 443:
        try:
            url = f"https://{host_id}"
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code == 200:
                return (f"{Fore.GREEN}[+] HTTPS reachable at {url}{Style.RESET_ALL}\n"
                        f"    Suggested: Check TLS config (SSL Labs or openssl).")
            else:
                return f"{Fore.YELLOW}[-] HTTPS returned {response.status_code} at {url}{Style.RESET_ALL}"
        except requests.RequestException as e:
            return f"{Fore.RED}[!] HTTPS unreachable at {url} - {str(e)}{Style.RESET_ALL}"

    if port_num == 21:
        return (f"{Fore.CYAN}[i] Suggested: Try FTP client to check for anonymous login "
                f"on {host_id}:{port_num}{Style.RESET_ALL}")

    return ""

# ------------------ Main ------------------ #
def main():
    args = argument_parser()
    host = args["host"]
    ports = args["port"]

    start = time.time()
    results = scanning(host, ports)
    elapsed = time.time() - start

    for line in results:
        print(line)

    print(f"\n{Fore.MAGENTA}[*] Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
