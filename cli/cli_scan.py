# cli/cli_scan.py
"""Command-line interface for the port scanner."""

import argparse
import time
from colorama import Fore, Style, init

# Initialize colorama first
init(autoreset=True)

from app.core.scanner import scanning
from app.core.risk import summarize_scan


def argument_parser():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Safe TCP port scanner with security checks. "
                    "Performs non-intrusive reconnaissance on target hosts.",
        epilog="Example: python -m cli.cli_scan -H scanme.nmap.org -p 22,80,443"
    )
    parser.add_argument(
        "-H", "--host",
        required=True,
        help="Target hostname or IP address"
    )
    parser.add_argument(
        "-p", "--port",
        default="1-1024",
        help="Port specification: '80' or '22,80,443' or '1-1024' (default: %(default)s)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output including all findings"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    return parser.parse_args()


def format_and_print(results, verbose=False, no_color=False):
    """
    Format and print scan results to console.
    
    Args:
        results: List of scan result dictionaries
        verbose: Whether to show detailed findings
        no_color: Whether to disable colored output
    """
    # Disable colors if requested
    if no_color:
        # Create a simple namespace that returns empty strings
        class NoColor:
            def __getattr__(self, name):
                return ""
        
        Fore_local = NoColor()
        Style_local = NoColor()
    else:
        Fore_local = Fore
        Style_local = Style
    
    for r in results:
        if r.get("error"):
            print(f"{Fore_local.RED}[!] ERROR: {r['error']}{Style_local.RESET_ALL}")
            continue
        
        state = r.get("state")
        if state == "open":
            host = r.get("host")
            port = r.get("port")
            service = r.get("service", "unknown")
            banner = r.get("banner", "")
            
            print(f"\n{Fore_local.GREEN}[+] {host}:{port}/tcp OPEN{Style_local.RESET_ALL}")
            print(f"    Service: {service}")
            
            if banner and verbose:
                print(f"    Banner: {banner[:100]}{'...' if len(banner) > 100 else ''}")
            
            # Show vulnerability summary
            summary = r.get("mapping_summary", "")
            if summary:
                print(f"{Fore_local.CYAN}    Vulnerability Info: {summary}{Style_local.RESET_ALL}")
            
            # Show findings if verbose
            findings = r.get("findings", [])
            if findings and verbose:
                print(f"    {Fore_local.YELLOW}Findings:{Style_local.RESET_ALL}")
                for f in findings:
                    if f.get("type") == "banner":
                        continue  # Already shown above
                    
                    ftype = f.get("type", "unknown")
                    detail = f.get("detail", "")
                    severity = f.get("severity", "info")
                    
                    # Color code by severity
                    if severity == "critical":
                        color = Fore_local.RED
                    elif severity == "high":
                        color = Fore_local.MAGENTA
                    elif severity == "medium":
                        color = Fore_local.YELLOW
                    else:
                        color = Fore_local.CYAN
                    
                    print(f"      {color}[{severity.upper()}] {ftype}: {detail}{Style_local.RESET_ALL}")
            
            # Show remediation
            remediation = r.get("remediation", "")
            if remediation and verbose:
                print(f"    {Fore_local.BLUE}Remediation: {remediation}{Style_local.RESET_ALL}")
        
        elif state == "closed" and verbose:
            host = r.get("host")
            port = r.get("port")
            if host and port:
                print(f"{Fore_local.YELLOW}[-] {host}:{port}/tcp closed{Style_local.RESET_ALL}")


def print_summary(results, elapsed):
    """
    Print scan summary statistics.
    
    Args:
        results: List of scan result dictionaries
        elapsed: Scan duration in seconds
    """
    risk_summary = summarize_scan(results)
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"Ports Scanned: {risk_summary['ports_scanned']}")
    print(f"Open Ports: {risk_summary['open_ports']}")
    print(f"Closed Ports: {risk_summary['closed_ports']}")
    print(f"Errors: {risk_summary['error_count']}")
    print(f"Total Findings: {risk_summary['total_findings']}")
    print(f"Critical Findings: {risk_summary['critical_findings']}")
    print(f"High Findings: {risk_summary['high_findings']}")
    
    # Risk assessment
    risk_level = risk_summary['risk_level']
    risk_score = risk_summary['risk_score']
    
    if risk_level == "HIGH":
        risk_color = Fore.RED
    elif risk_level == "MEDIUM":
        risk_color = Fore.YELLOW
    else:
        risk_color = Fore.GREEN
    
    print(f"\n{risk_color}Risk Level: {risk_level} (Score: {risk_score}/100){Style.RESET_ALL}")
    print(f"Scan Duration: {elapsed:.2f} seconds")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


def main():
    """Main CLI entry point."""
    args = argument_parser()
    
    print(f"{Fore.GREEN}[*] Starting scan of {args.host} on ports: {args.port}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] This may take a while depending on the port range...{Style.RESET_ALL}\n")
    
    start = time.time()
    try:
        results = scanning(args.host, args.port)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"\n{Fore.RED}[!] Scan failed: {str(e)}{Style.RESET_ALL}")
        return 1
    
    elapsed = time.time() - start
    
    # Print results
    format_and_print(results, verbose=args.verbose, no_color=args.no_color)
    
    # Print summary - FIXED: Actually call the function
    print_summary(results, elapsed)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())