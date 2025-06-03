#!/usr/bin/env python

"""
CVE-2018-1207 Scanner - Dell iDRAC7/8 Vulnerability Scanner
This script scans a range of IP addresses for the CVE-2018-1207 vulnerability
affecting Dell iDRAC7 and iDRAC8 devices with firmware versions below 2.52.52.52.

Usage:
    python cve_2018_1207_scanner.py <start_ip> <end_ip> [port] [threads]

Example:
    python cve_2018_1207_scanner.py 192.168.1.1 192.168.1.254 443 10

Author: Manus AI Assistant
Date: June 3, 2025
"""

import sys
import re
import socket
import ipaddress
import requests
import concurrent.futures
import argparse
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def ip_range(start_ip, end_ip):
    """Generate IP addresses from start_ip to end_ip inclusive."""
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    
    if start > end:
        raise ValueError("Start IP must be less than or equal to end IP")
        
    return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]

def check_vulnerability(ip, port=443, timeout=5):
    """Check if the specified IP:port is vulnerable to CVE-2018-1207."""
    url = f"https://{ip}:{port}/cgi-bin/login?LD_DEBUG=files"
    
    try:
        response = requests.get(url, verify=False, timeout=timeout)
        
        # Check for vulnerability indicator
        if re.search(r'calling init: /lib/', response.text):
            return (ip, port, True, "VULNERABLE")
        else:
            return (ip, port, False, "NOT VULNERABLE")
            
    except requests.exceptions.ConnectTimeout:
        return (ip, port, None, "CONNECTION TIMEOUT")
    except requests.exceptions.ReadTimeout:
        return (ip, port, None, "READ TIMEOUT")
    except requests.exceptions.ConnectionError:
        return (ip, port, None, "CONNECTION ERROR")
    except requests.exceptions.RequestException as e:
        return (ip, port, None, f"ERROR: {str(e)}")

def scan_range(start_ip, end_ip, port=443, max_workers=10):
    """Scan a range of IPs for the vulnerability."""
    ips = ip_range(start_ip, end_ip)
    results = []
    
    print(f"[*] Starting scan of {len(ips)} IP addresses on port {port}")
    print(f"[*] Using {max_workers} concurrent threads")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(check_vulnerability, ip, port): ip for ip in ips}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            if completed % 10 == 0 or completed == len(ips):
                print(f"[*] Progress: {completed}/{len(ips)} IPs scanned")
                
            result = future.result()
            results.append(result)
            
            # Print vulnerable hosts immediately
            if result[2]:  # If vulnerable
                print(f"[!] VULNERABLE: {result[0]}:{result[1]}")
    
    return results

def print_results(results):
    """Print scan results in a formatted way."""
    vulnerable = [r for r in results if r[2] is True]
    not_vulnerable = [r for r in results if r[2] is False]
    errors = [r for r in results if r[2] is None]
    
    print("\n--- SCAN RESULTS ---")
    print(f"Total IPs scanned: {len(results)}")
    print(f"Vulnerable: {len(vulnerable)}")
    print(f"Not vulnerable: {len(not_vulnerable)}")
    print(f"Errors/Unreachable: {len(errors)}")
    
    if vulnerable:
        print("\n--- VULNERABLE HOSTS ---")
        for ip, port, _, _ in vulnerable:
            print(f"{ip}:{port}")
    
    if errors:
        print("\n--- ERRORS ---")
        for ip, port, _, error in errors:
            print(f"{ip}:{port} - {error}")

def main():
    parser = argparse.ArgumentParser(description='Scan IP range for CVE-2018-1207 vulnerability')
    parser.add_argument('start_ip', help='Starting IP address')
    parser.add_argument('end_ip', help='Ending IP address')
    parser.add_argument('--port', '-p', type=int, default=443, help='Port to scan (default: 443)')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--output', '-o', help='Output file for results')
    
    args = parser.parse_args()
    
    try:
        results = scan_range(args.start_ip, args.end_ip, args.port, args.threads)
        print_results(results)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write("IP,Port,Vulnerable,Status\n")
                for ip, port, vulnerable, status in results:
                    f.write(f"{ip},{port},{vulnerable},{status}\n")
                print(f"\n[*] Results saved to {args.output}")
                
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
