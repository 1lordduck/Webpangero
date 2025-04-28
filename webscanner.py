#!/usr/bin/env python3

import argparse
import requests
from bs4 import BeautifulSoup
import sys
from tqdm import tqdm
import ssl, socket
from urllib.parse import urlparse, urljoin
import dns.resolver

class Color:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

ASCII_LOGO = r"""
__        __   _     ____                                      
\ \      / /__| |__ |  _ \ __ _ _ __   __ _  ___ _ __ ___       
 \ \ /\ / / _ \ '_ \| |_) / _` | '_ \ / _` |/ _ \ '__/ _ \      
  \ V  V /  __/ |_) |  __/ (_| | | | | (_| |  __/ | | (_) |     
   \_/\_/ \___|_.__/|_|   \__,_|_| |_|\__, |\___|_|  \___/      
                                      |___/                                       
         Simple Web Vulnerability Scanner   
               Author: 1lordduck
"""

print(f"{Color.BLUE}{ASCII_LOGO}{Color.RESET}")

def loadPayloads(file):
    try: 
        with open (file, "r") as file:
            content = file.read()
            return content.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"{Color.RED}[!] Error fetching payloads: {e}{Color.RESET}")
        sys.exit(1)

SQLI_PAYLOADS = loadPayloads("./payloads/sqli.txt")
XSS_PAYLOADS = loadPayloads("./payloads/xss.txt")

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "uncaught mysql",
    "check your manual",
    "mariadb server",
    "query",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error",
    "ora-01756",
    "sqlstate",
    "microsoft ole db provider for odbc drivers",
    "odbc sql server driver",
]

def is_sql_error(response_text):
    lower = response_text.lower()
    return any(error.lower() in lower for error in SQL_ERRORS)

def banner(target):
    try:
        response = requests.get(target)
        xxss = response.headers.get("x-xss-protection", "No x-xss-protection header found")
        X_frame_Options = response.headers.get("X-Frame-Options", "No X-Frame-Options header found")
        server_banner = response.headers.get('Server', 'No server header found')
        x_powered_by = response.headers.get("X-Powered-By", "No X-Powered-By header found")
        print(f"{Color.GREEN}Server:{Color.RESET} {server_banner}")
        print(f"{Color.GREEN}Powered by:{Color.RESET} {x_powered_by}")
        print(f"{Color.GREEN}X-XSS-Protection header:{Color.RESET} {xxss}")
        print(f"{Color.GREEN}X-Frame-Options header:{Color.RESET} {X_frame_Options}")
    except requests.exceptions.RequestException as e:
        print(f"{Color.RED}[!]{Color.RESET} There was an error while banner grabbing: {e}")
        sys.exit(0)

def SSLfetch(target_url):
    try:
        hostname = urlparse(target_url).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()
            if cert:
                wanted_keys = {
                    'emailAddress',
                    'commonName',
                    'organizationName',
                    'countryName',
                    'stateOrProvinceName'
                }
                for item in cert.get('issuer', []):
                    for pair in item:
                        if pair[0] in wanted_keys:
                            print(f"{Color.BLUE}{pair[0]}: {Color.RESET}{pair[1]}")
    except Exception as e:
        print(f"[!] Error fetching SSL Info: {e}")

record_types = ['A', 'CAA']

def fetch_DNSRECORDS(target):
    resolver = dns.resolver.Resolver()
    hostname = urlparse(target).hostname or target
    a_records = []
    caa_records = []
    for record_type in record_types:
        try:
            answers = resolver.resolve(hostname, record_type)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            print(f"No such domain: {hostname}")
            return
        except Exception as e:
            print(f"Error resolving {record_type} record: {e}")
            continue
        if record_type == 'A':
            a_records.extend([rdata.address for rdata in answers])
        elif record_type == 'CAA':
            caa_records.extend([str(rdata) for rdata in answers])
    if a_records:
        print(f"{Color.BLUE}IPs found: {Color.RESET}")
        for ip in a_records:
            print(f"  {ip}")
    if caa_records:
        print(f"{Color.BLUE}CAA domains:{Color.RESET}")
        for caa in caa_records:
            print(f"  {caa}")

def parse_args():
    parser = argparse.ArgumentParser(description='WebScanner - Web Vulnerability Scanner')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Path to HTML file')
    group.add_argument('-u', '--url', help='URL to scan')
    parser.add_argument('-T', '--threshold', type=int, default=1, help='Alert threshold (1-100)')
    return parser.parse_args()

def get_html_from_file(path):
    try:
        with open(path, 'r') as file:
            return file.read()
    except Exception as e:
        print(f"{Color.RED}[!] Error reading file: {e}{Color.RESET}")
        sys.exit(1)

def get_html_from_url(url):
    try:
        return requests.get(url).text
    except Exception as e:
        print(f"{Color.RED}[!] Error fetching URL: {e}{Color.RESET}")
        sys.exit(1)

def find_forms(html):
    return BeautifulSoup(html, "html.parser").find_all("form")

def find_links(html):
    soup = BeautifulSoup(html, "html.parser")
    return [a.get("href") for a in soup.find_all("a") if a.get("href")]

def scan_sql_injection(form, threshold, base_url):
    found = []
    action = form.get("action") or base_url
    full_url = urljoin(base_url, action)
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")
    for payload in tqdm(SQLI_PAYLOADS[:threshold], desc=f"{Color.YELLOW}Scanning SQLi{Color.RESET}", leave=False):
        data = {}
        for idx, inp in enumerate(inputs):
            name = inp.get("name") or f"input{idx}"
            data[name] = payload
        try:
            response = requests.post(full_url, data=data) if method == "post" else requests.get(full_url, params=data)
            if is_sql_error(response.text):
                found.append((payload, response.url))
        except Exception as e:
            print(f"{Color.RED}[!] SQLi scan error: {e}{Color.RESET}")
    return found

def scan_xss(form, threshold, base_url):
    found = []
    action = form.get("action") or base_url
    full_url = urljoin(base_url, action)
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")
    for payload in tqdm(XSS_PAYLOADS[:threshold], desc=f"{Color.YELLOW}Scanning XSS{Color.RESET}", leave=False):
        data = {}
        for idx, inp in enumerate(inputs):
            name = inp.get("name") or f"input{idx}"
            data[name] = payload
        try:
            response = requests.post(full_url, data=data) if method == "post" else requests.get(full_url, params=data)
            if payload in response.text:
                found.append((payload, response.url))
        except Exception as e:
            print(f"{Color.RED}[!] XSS scan error: {e}{Color.RESET}")
    return found

def generate_report(sql_results, xss_results, target, found):
    print("="*40)
    print(f"{Color.BLUE}Target: {Color.RESET}{target}")
    fetch_DNSRECORDS(target)
    SSLfetch(target)
    print('='*40)
    banner(target)
    print(f"{Color.GREEN}Found Vulnerabilities:{Color.RESET} {found if found else 'None'}")
    print("="*40)
    print(f"{Color.GREEN}Security Scan Report{Color.RESET}")
    print("="*40)
    if sql_results:
        print(f"{Color.RED}[!] SQL Injection Vulnerabilities Found:{Color.RESET}")
        for payload, url in sql_results:
            print(f"  - Payload: {payload} | URL: {url}")
    else:
        print(f"{Color.GREEN}[✓] No SQL Injection issues found.{Color.RESET}")
    if xss_results:
        print(f"{Color.RED}[!] XSS Vulnerabilities Found:{Color.RESET}")
        for payload, url in xss_results:
            print(f"  - Payload: {payload} | URL: {url}")
    else:
        print(f"{Color.GREEN}[✓] No XSS issues found.{Color.RESET}")
    print("="*40)

def main():
    try:
        args = parse_args()
        target = args.url if args.url else "http://localhost"
        html = get_html_from_url(target) if args.url else get_html_from_file(args.file)
        forms = find_forms(html)
        print(f"{Color.GREEN}[+] Found {len(forms)} forms to test.{Color.RESET}")
        sql_report = []
        xss_report = []
        for form in forms:
            sql_report.extend(scan_sql_injection(form, args.threshold, target))
            xss_report.extend(scan_xss(form, args.threshold, target))
        found = ""
        if sql_report:
            found += " SQL Injection"
        if xss_report:
            found += " XSS"
        generate_report(sql_report, xss_report, target, found)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    main()
