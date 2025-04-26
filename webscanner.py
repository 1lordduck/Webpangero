#!/usr/bin/env python3

import argparse
from os import wait
import requests
from bs4 import BeautifulSoup
import sys
from tqdm import tqdm

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
def loadPayloads(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  
        payloads = response.text.splitlines()  # Split by newlines
        return [payload.strip() for payload in payloads if payload.strip()]  
    except requests.exceptions.RequestException as e:
        print(f"{Color.RED}[!] Error fetching payloads: {e}{Color.RESET}")
        sys.exit(1)

SQLI_PAYLOADS = loadPayloads("https://raw.githubusercontent.com/1lordduck/Webpangero/main/payloads/sqli.txt")
XSS_PAYLOADS = loadPayloads("https://raw.githubusercontent.com/1lordduck/Webpangero/main/payloads/xss.txt")

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error",
    "ORA-01756",  
    "SQLSTATE",
    "Microsoft OLE DB Provider for ODBC Drivers",
    "ODBC SQL Server Driver",
]

def is_sql_error(response_text):
    lower = response_text.lower()
    return any(error.lower() in lower for error in SQL_ERRORS)

def banner(target):
    try:
        response = requests.get(target)

        xxss = response.headers.get("x-xss-protection", "No x-xss-protection header found")

        server_banner = response.headers.get('Server', 'No server header found')
        x_powered_by = response.headers.get("X-Powered-By", "No X-Powered-By header found")

        print(f"{Color.GREEN}Server:{Color.RESET} {server_banner}")
        print(f"{Color.GREEN}Powered by:{Color.RESET} {x_powered_by}")
        print(f"{Color.GREEN}X-XSS-Protection header:{Color.RESET} {xxss}")
        

    except requests.exceptions.RequestException as e:
        print(f"{Color.RED}[!]{Color.RESET} There was an error while banner grabbing: {e}")
        sys.exit(0)

def parse_args():
    parser = argparse.ArgumentParser(description='WebScanner - Web Vulnerability Scanner')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Path to HTML file')
    group.add_argument('-u', '--url', help='URL to scan')
    parser.add_argument('-T', '--threshold', type=int, default=1, help='Alert threshold (1-10)')
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

def scan_sql_injection(form, threshold):
    found = []
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")

    for payload in tqdm(SQLI_PAYLOADS[:threshold], desc=f"{Color.YELLOW}Scanning SQLi{Color.RESET}", leave=False):
        data = {inp.get("name"): payload for inp in inputs if inp.get("name")}
        try:
            response = requests.post(action, data=data) if method == "post" else requests.get(action, params=data)
            if "sql" in response.text.lower() or "error" in response.text.lower():
                found.append((payload, response.url))
        except:
            continue
    return found

def scan_xss(form, threshold):
    found = []
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")

    for payload in tqdm(XSS_PAYLOADS[:threshold], desc=f"{Color.YELLOW}Scanning XSS{Color.RESET}", leave=False):
        data = {inp.get("name"): payload for inp in inputs if inp.get("name")}
        try:
            response = requests.post(action, data=data) if method == "post" else requests.get(action, params=data)
            if payload in response.text:
                found.append((payload, response.url))
        except:
            continue
    return found

def generate_report(sql_results, xss_results, target, found):
    print("="*40)
    print(f"{Color.BLUE}Target: {Color.RESET}{target}")
    banner(target)
    print(f"{Color.GREEN}Found Vulnerabilities:{Color.RESET} {found}")
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
        target = "None"
        VulnsFound = ""

        if args.file:
            html = get_html_from_file(args.file)
            base_url = "http://localhost"
            target = base_url + html
        else:
            html = get_html_from_url(args.url)
            base_url = args.url
            target = base_url

        forms = find_forms(html)
        print(f"{Color.GREEN}[+] Found {len(forms)} forms to test.{Color.RESET}")

        sql_report = []
        xss_report = []

        for form in forms:
            action = form.get("action")

            if action:
                if not action.startswith("http"):
                    form["action"] = base_url.rstrip("/") + "/" + action.lstrip("/")
            else:
                form["action"] = base_url  

            sql_report.extend(scan_sql_injection(form, args.threshold))
            xss_report.extend(scan_xss(form, args.threshold))

        if len(sql_report) > 0:
            VulnsFound += " SQL Injection "
        if len(xss_report) > 0:
            VulnsFound += " Cross-Site Scripting (XSS) "

        generate_report(sql_report, xss_report, target, VulnsFound)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting cleanly.")
        sys.exit(0)


if __name__ == "__main__":
    main()

