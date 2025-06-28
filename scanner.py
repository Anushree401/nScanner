import requests 
import json 
import nmap
import sys
import requests
import socket
from ipwhois import IPWhois
from colorama import init, Fore, Style
import os

init(autoreset=True)
API_KEY = os.environ.get("API_KEY")  



class PassiveScanner:
    @staticmethod
    def fetch_http(target):
        try:
            req = requests.get(f"https://{target}", timeout=5)
            return dict(req.headers)
        except requests.exceptions.RequestException:
            return {}

    @staticmethod
    def iplookup(domain):
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    @staticmethod
    def ipanalysis(ip):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json?token={API_KEY}", timeout=5)
            return response.json()
        except Exception:
            return {}

    @staticmethod
    def whoislookup(ip):
        try:
            obj = IPWhois(ip)
            return obj.lookup_rdap()
        except Exception:
            return {}

    def full_recon(self, target):
        data = {}
        ip_addr = self.iplookup(target)
        if not ip_addr:
            return data
        data["ip_address"] = ip_addr
        data["http_headers"] = self.fetch_http(target)
        data["ip_analysis"] = self.ipanalysis(ip_addr)
        data["whois_data"] = self.whoislookup(ip_addr)
        return data




import socket
import nmap

class ActiveScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan(self, host_id, port_num, verbose=False):
        result = []
        try:
            try:
                resolved_ip = socket.gethostbyname(host_id)
            except Exception as e:
                return [f"[!] DNS resolution failed for {host_id}: {str(e)}"]
            port_num_cleaned = port_num.replace(" ", "") if port_num else ""
            if not port_num_cleaned:
                return ["[!] No valid ports specified"]
            result.append(f"[*] Scanning {host_id} ({resolved_ip}) on port(s): {port_num_cleaned}")
            self.scanner.scan(resolved_ip, arguments=f"-sT -Pn -p {port_num_cleaned}")
            print(f"CMD: {self.scanner.command_line()}")
            print(f"INFO: {self.scanner.scaninfo()}")
            print(f"HOSTS: {self.scanner.all_hosts()}")
            if resolved_ip not in self.scanner.all_hosts():
                return [f"[!] Host {resolved_ip} | Scan failed or host unreachable"]
            result.append(f"[*] Starting port scan on {resolved_ip}...")
            for port_entry in port_num_cleaned.split(","):
                port_entry = port_entry.strip()
                if '-' in port_entry:
                    try:
                        start, end = map(int, port_entry.split('-'))
                        for port in range(start, end + 1):
                            self.process_port(resolved_ip, port, result, verbose)
                    except ValueError:
                        result.append(f"[-] Invalid port range: {port_entry}")
                elif port_entry.isdigit():
                    self.process_port(resolved_ip, int(port_entry), result, verbose)
                else:
                    result.append(f"[-] Invalid port format: {port_entry}")
            print("[DEBUG] Active Scan Results:")
            for line in result:
                print(line)
            return result
        except nmap.PortScannerError as e:
            return [f"[!] NMAP Error: {str(e)}"]
        except Exception as e:
            return [f"[!] Unexpected Error: {str(e)}"]

    def process_port(self, resolved_ip, port, result, verbose=False):
        try:
            port_info = self.scanner[resolved_ip]["tcp"].get(port, {})
            state = port_info.get("state", "unknown")
            service = port_info.get("name", "unknown")
            if state == "open":
                result.append(f"[+] Host: {resolved_ip} | Port: {port}/tcp | State: {state} | Service: {service}")
            elif verbose:
                result.append(f"[-] Host: {resolved_ip} | Port: {port}/tcp | State: {state}")
        except Exception as e:
            if verbose:
                result.append(f"[?] Error checking port {port}: {str(e)}")
