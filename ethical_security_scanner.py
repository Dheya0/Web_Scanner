# ethical-scanner-web.py
import os
import re
import json
import time
import socket
import ssl
import csv
import logging
import asyncio
import threading
import sqlite3
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, quote
from functools import lru_cache

# Third-party Libraries
import requests
import nmap
import aiohttp
import dns.resolver
import whois
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from playwright.sync_api import sync_playwright

# Project-specific Imports
from utils import (load_config, get_page_content, run_parallel_checks, load_cve_data,
                  load_dependencies, load_mapping, load_payloads, get_proxies, ensure_payload_exists)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='security_scan.log'
)
logger = logging.getLogger('EthicalSecurityScanner')

# Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
payloads_dir = os.path.join(current_dir, 'ethical_scanner_web', 'payloads')
password_list_path = r'D:\Testing Tool\ethical_scanner_web\million_password_list.txt'
cve_dir = r"D:\Testing Tool\cvelist"

class EthicalSecurityScanner:
    def __init__(self, target_url, scan_type="full", selected_categories=None, threads=5, timeout=10, user_agent=None,
                 respect_robots=True, scan_depth=2, socketio=None):
        """Initialize the EthicalSecurityScanner with target URL and configurations."""
        if not target_url or not isinstance(target_url, str):
            raise ValueError("Target URL must be a non-empty string")
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.ip_addresses = []
        self.scan_type = scan_type
        self.selected_categories = selected_categories or []
        self.threads = threads
        self.session = requests.Session()
        self.config = load_config(self)
        self.timeout = self.config["timeout"]
        self.respect_robots = respect_robots
        self.scan_depth = scan_depth
        self.user_agent = user_agent or self.config["user_agent"]
        self.session.headers.update({'User-Agent': self.user_agent})
        self.request_semaphore = threading.Semaphore(10)
        self.proxies = get_proxies()
        self.disallowed_paths = []
        self.socketio = socketio  # For real-time updates
        self.results = {
            "target": self.target_url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_type": self.scan_type,
            "findings": {},
            "vulnerabilities": [],
            "risk_score": 0,
            "scan_stats": {
                "start_time": time.time(),
                "end_time": None,
                "duration": None,
                "requests_made": 0,
                "errors_encountered": 0
            }
        }

    # --- Vulnerability Scanning Methods ---
    def sql_injection_test(self, target_url):
        """Synchronous SQL injection test."""
        parsed_url = urlparse(target_url)
        params = parse_qs(parsed_url.query)
        logger.info(f"[SYNC] Starting SQL injection test on {target_url}")
        if not params:
            return [{"status": "Skipped", "details": "No parameters available for testing"}]
        payloads = load_payloads("sql_payloads.txt", payload_type="SQLi")
        if not payloads:
            return [{"status": "Error", "details": "Failed to load payloads"}]
        findings = []
        for param in params:
            for payload in payloads:
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={quote(payload)}"
                try:
                    start = time.time()
                    with self.request_semaphore:
                        response = self.session.get(test_url, proxies=self.proxies, timeout=self.timeout)
                    elapsed = time.time() - start
                    self.results["scan_stats"]["requests_made"] += 1
                    if self.is_sql_vulnerable(response, elapsed):
                        findings.append({
                            "param": param,
                            "payload": payload,
                            "status": "Vulnerable",
                            "response_time": f"{elapsed:.2f}s",
                            "details": f"SQLi detected at {test_url}"
                        })
                        self._add_vulnerability("SQL Injection", "High", f"SQLi at {test_url}", "CWE-89",
                                                "Use parameterized queries.")
                except requests.RequestException as e:
                    logger.error(f"Request failed with payload '{payload}': {e}")
                    findings.append({"payload": payload, "status": "Error", "details": str(e)})
                    self.results["scan_stats"]["errors_encountered"] += 1
        self.results["findings"]["sqli"] = findings if findings else [{"status": "No Vulnerabilities Found"}]
        return findings

    async def check_sqli_async(self, target_url):
        """Asynchronous SQL injection test."""
        payloads = load_payloads("sql_payloads.txt", payload_type="SQLi")
        if not payloads:
            return [{"status": "Error", "details": "Failed to load payloads"}]
        findings = []
        logger.info(f"[ASYNC] Starting SQL injection test on {target_url}")
        async with aiohttp.ClientSession() as session:
            tasks = [self._test_payload_async(session, f"{target_url}?id={quote(payload)}", payload)
                     for payload in payloads]
            results = await asyncio.gather(*tasks)
            findings.extend([r for r in results if r])
        self.results["findings"]["sqli_async"] = findings if findings else [{"status": "No Vulnerabilities Found"}]
        return findings

    async def _test_payload_async(self, session, test_url, payload):
        """Helper for async SQLi testing."""
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                text = await response.text()
                if self.is_async_sql_vulnerable(text):
                    return {"payload": payload, "status": "Vulnerable", "details": f"SQLi at {test_url}"}
        except Exception as e:
            logger.debug(f"Async error with payload '{payload}': {e}")
        return None

    def xss_test(self, xss_type='reflective'):
        """Test for XSS vulnerabilities."""
        logger.info(f"Starting {xss_type} XSS test on {self.target_url}")
        if xss_type == 'reflective':
            result = self._test_reflective_xss()
        elif xss_type == 'stored':
            result = self._test_stored_xss(self.target_url)
        else:
            logger.error(f"Unsupported XSS type: {xss_type}")
            result = {"error": "Invalid XSS type"}
        if "payloads" in result and result["payloads"]:
            self._add_vulnerability(f"{xss_type.capitalize()} XSS", "High", f"{xss_type.capitalize()} XSS detected",
                                    "CWE-79", "Sanitize and escape user inputs.")
        self.results["findings"]["xss"] = result
        return result

    def _test_reflective_xss(self):
        """Test for reflective XSS."""
        payloads = load_payloads("xss_payloads.txt", payload_type="XSS")
        detected_payloads = []
        for payload in payloads:
            test_url = f"{self.target_url}?search={quote(payload)}"
            try:
                response, _ = get_page_content(test_url, self.session, self.timeout)
                self.results["scan_stats"]["requests_made"] += 1
                if payload in response.text:
                    detected_payloads.append(payload)
            except Exception as e:
                logger.error(f"XSS test failed with payload '{payload}': {e}")
                self.results["scan_stats"]["errors_encountered"] += 1
        return {"result": "Reflective XSS detected", "payloads": detected_payloads} if detected_payloads else {
            "result": "No XSS detected"}

    def _test_stored_xss(self, url):
        """Test for stored XSS using Selenium."""
        driver = self.get_webdriver()
        payload = "<script>alert('XSS')</script>"
        try:
            driver.get(url)
            forms = driver.find_elements(By.TAG_NAME, 'form')
            if not forms:
                return {"result": "No form found on the page."}
            for form in forms:
                inputs = form.find_elements(By.TAG_NAME, 'input')
                for input_field in inputs:
                    input_field.send_keys(payload)
                form.submit()
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                    return {"result": "Stored XSS detected", "payloads": [payload]}
                except:
                    continue
            return {"result": "No Stored XSS detected"}
        except Exception as e:
            logger.error(f"Stored XSS test failed: {e}")
            return {"error": str(e)}
        finally:
            driver.quit()

    def check_https(self):
        """Check HTTPS and SSL certificate details."""
        findings = {}
        https_url = self.target_url.replace('http://', 'https://') if 'http://' in self.target_url else self.target_url
        try:
            response, _ = get_page_content(https_url, self.session, self.timeout)
            findings["https_supported"] = True
            hostname = urlparse(https_url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = x509.load_der_x509_certificate(ssock.getpeercert(binary_form=True), default_backend())
                    findings["certificate_expiry"] = cert.not_valid_after.isoformat()
                    now = datetime.utcnow()
                    days_to_expiry = (cert.not_valid_after - now).days
                    if days_to_expiry < 30:
                        self._add_vulnerability("SSL Certificate Nearing Expiry", "Medium",
                                                f"Expires in {days_to_expiry} days", "CWE-324",
                                                "Renew the SSL certificate.")
            self.results["findings"]["https"] = findings
        except Exception as e:
            findings["https_supported"] = False
            self._add_vulnerability("HTTPS Not Supported", "High", str(e), "CWE-319",
                                    "Enable HTTPS with a valid certificate.")
            self.results["findings"]["https"] = findings

    def scan_ports(self, target_ip=None, ports="21,22,80,443"):
        """Scan ports using nmap."""
        if not target_ip and not self.ip_addresses:
            self.ip_addresses = self.resolve_domain()
            target_ip = self.ip_addresses[0] if self.ip_addresses else None
        if not target_ip:
            return {"error": "Failed to resolve domain to IP"}
        try:
            nm = nmap.PortScanner()
            nm.scan(target_ip, ports, arguments='-sS -T4')
            scan_results = {host: {"state": nm[host].state(), "ports": nm[host].tcp()} for host in nm.all_hosts()}
            for host, data in scan_results.items():
                for port, info in data["ports"].items():
                    if info["state"] == "open" and port in [21, 23]:
                        self._add_vulnerability(f"Unencrypted Service on Port {port}", "High",
                                                f"Port {port} ({info['name']}) open", "CWE-319",
                                                "Use encrypted protocols.")
            self.results["findings"]["port_scan"] = scan_results
            return scan_results
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            return {"error": str(e)}

    def check_vulnerabilities(self):
        """Check for vulnerabilities in dependencies using CVE data."""
        dependencies = load_dependencies("deps.csv")
        mapping = load_mapping("cpe_mapping.json")
        cves = load_cve_data(cve_dir, dependencies)
        findings = {}
        for cve in cves:
            cve_id = cve['cve']['CVE_data_meta']['ID']
            for dep in dependencies:
                nodes = cve.get('configurations', {}).get('nodes', [{}])
                if nodes and self.is_version_vulnerable(dep['version'], nodes[0].get('cpe_match', [{}])[0]):
                    findings[cve_id] = {"affected": dep['product']}
                    self._add_vulnerability(f"CVE-{cve_id}", "High", f"Affects {dep['product']}", "CWE-Unknown",
                                            "Update software version.")
        self.results["findings"]["cve"] = findings
        return findings

    def csrf_test(self):
        """Test for CSRF vulnerabilities."""
        logger.info(f"Starting CSRF test on {self.target_url}")
        response, soup = get_page_content(self.target_url, self.session, self.timeout)
        findings = []
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', 'No action')
            if not form.find('input', {'name': re.compile('csrf.*', re.I)}):
                findings.append({"action": action, "csrf_token": "Missing"})
                self._add_vulnerability("CSRF Vulnerability", "Medium", f"Form at {action} lacks CSRF token",
                                        "CWE-352", "Add CSRF tokens to forms.")
            else:
                findings.append({"action": action, "csrf_token": "Present"})
        self.results["findings"]["csrf"] = findings
        return findings

    def check_information_disclosure(self):
        """Check for information disclosure vulnerabilities."""
        info_disclosure = {"server_info": {}, "sensitive_files": []}
        response, soup = get_page_content(self.target_url, self.session, self.timeout)
        headers = response.headers
        if 'Server' in headers:
            info_disclosure["server_info"]["server"] = headers['Server']
            self._add_vulnerability("Server Info Leakage", "Low", f"Server: {headers['Server']}", "CWE-200",
                                    "Hide server info in headers.")
        sensitive_files = ["/.env", "/phpinfo.php", "/admin/"]
        for file_path in sensitive_files:
            file_url = urljoin(self.target_url, file_path)
            if self.is_path_allowed(file_path):
                try:
                    file_response, _ = get_page_content(file_url, self.session, self.timeout)
                    if file_response.status_code == 200:
                        info_disclosure["sensitive_files"].append({"path": file_path})
                        self._add_vulnerability(f"Sensitive File Exposed: {file_path}", "High",
                                                f"File {file_path} accessible", "CWE-538",
                                                "Restrict access to sensitive files.")
                except Exception:
                    continue
        self.results["findings"]["information_disclosure"] = info_disclosure
        return info_disclosure

    def crawl(self, base_url, max_depth=3):
        """Crawl the target site for additional URLs."""
        visited = set()
        to_scan = [(base_url, 0)]
        all_urls = []
        while to_scan:
            url, depth = to_scan.pop(0)
            if url in visited or depth > max_depth or not url.startswith(base_url):
                continue
            try:
                response, soup = get_page_content(url, self.session, self.timeout)
                visited.add(url)
                all_urls.append(url)
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if full_url not in visited:
                        to_scan.append((full_url, depth + 1))
            except Exception as e:
                logger.error(f"Crawl failed for {url}: {e}")
        return all_urls

    def check_broken_access_control(self, url):
        """Check for broken access control vulnerabilities."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        findings = []
        for param, values in params.items():
            if param in ["id", "user_id"]:
                original_value = values[0]
                test_value = str(int(original_value) + 1) if original_value.isdigit() else f"{original_value}_test"
                test_url = url.replace(f"{param}={original_value}", f"{param}={test_value}")
                response, _ = get_page_content(test_url, self.session, self.timeout)
                if response.status_code == 200 and original_value not in response.text:
                    findings.append({"url": test_url, "status": "Vulnerable"})
                    self._add_vulnerability("Broken Access Control", "High", f"Unauthorized access at {test_url}",
                                            "CWE-284", "Validate user permissions.")
        self.results["findings"]["access_control"] = findings
        return findings

    async def brute_force_login(self, login_url, username, max_attempts=100, delay=1.0):
        """Perform a brute-force attack on a login endpoint."""
        logger.info(f"Starting brute-force on {login_url} with username {username}")
        if self.socketio:
            self.socketio.emit('scan_status', {'message': f'Brute-force started on {login_url}', 'progress': 0})
        try:
            with open(password_list_path, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Password list not found: {password_list_path}")
            return {"status": "error", "message": "Password list not found"}

        attempts = 0
        success = False
        found_credentials = None
        async with aiohttp.ClientSession() as session:
            for password in passwords[:max_attempts]:
                attempts += 1
                progress = (attempts / min(len(passwords), max_attempts)) * 100
                payload = {"username": username, "password": password}
                try:
                    async with session.post(login_url, data=payload,
                                            timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                        text = await response.text()
                        if "login failed" not in text.lower() and response.status == 200:
                            success = True
                            found_credentials = {"username": username, "password": password}
                            if self.socketio:
                                self.socketio.emit('scan_status', {
                                    'message': f'Success! Found: {username}:{password}', 'progress': 100})
                            break
                        if self.socketio:
                            self.socketio.emit('scan_status', {
                                'message': f'Attempt {attempts}: {password} failed', 'progress': progress})
                except Exception as e:
                    logger.error(f"Brute-force error: {e}")
                    break
                await asyncio.sleep(delay)
        result = {
            "status": "completed" if success else "failed",
            "attempts": attempts,
            "credentials": found_credentials if success else None
        }
        self.results["findings"]["brute_force"] = result
        if success:
            self._add_vulnerability("Weak Credentials", "High", "Credentials found via brute-force", "CWE-307",
                                    "Enforce strong passwords and rate limiting.")
        return result

    # --- Helper Methods ---
    @staticmethod
    def is_sql_vulnerable(response, elapsed):
        """Check if response indicates SQL injection."""
        error_messages = ["sql syntax", "mysql_fetch", "unclosed quotation", "sqlite3"]
        return any(msg in response.text.lower() for msg in error_messages) or elapsed > 5

    @staticmethod
    def is_async_sql_vulnerable(response_text):
        """Check async response for SQL injection signs."""
        error_signatures = ["sql syntax", "mysql", "unclosed quotation", "sqlite"]
        return any(err in response_text.lower() for err in error_signatures)

    @staticmethod
    def is_version_vulnerable(system_version, cpe_match):
        """Check if a version is vulnerable."""
        from packaging import version
        try:
            system_ver = version.parse(system_version)
        except version.InvalidVersion:
            return False
        cpe_version = cpe_match.get('cpe23Uri', '').split(':')[5] if 'cpe23Uri' in cpe_match else '*'
        return cpe_version == '*' or system_version == cpe_version

    def resolve_domain(self):
        """Resolve domain to IP addresses."""
        try:
            ips = [info[4][0] for info in socket.getaddrinfo(self.domain, None)]
            self.ip_addresses = list(set(ips))
            self.results["findings"]["ip_addresses"] = self.ip_addresses
            return self.ip_addresses
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed: {e}")
            return []

    def parse_robots_txt(self):
        """Parse robots.txt to determine disallowed paths."""
        if not self.respect_robots:
            return []
        robots_url = urljoin(self.target_url, "/robots.txt")
        try:
            response, _ = get_page_content(robots_url, self.session, self.timeout)
            if response.status_code == 200:
                lines = response.text.splitlines()
                user_agent_matches = False
                disallowed = []
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(':', 1)
                    if len(parts) != 2:
                        continue
                    directive, value = parts[0].strip().lower(), parts[1].strip()
                    if directive == 'user-agent':
                        user_agent_matches = (value == '*' or value in self.user_agent)
                    elif directive == 'disallow' and user_agent_matches and value:
                        disallowed.append(value)
                self.disallowed_paths = disallowed
                self.results["findings"]["robots_txt"] = {"found": True, "disallowed_paths": disallowed}
                return disallowed
        except Exception as e:
            logger.error(f"Error parsing robots.txt: {e}")
            self.results["findings"]["robots_txt"] = {"found": False, "error": str(e)}
        return []

    def is_path_allowed(self, path):
        """Check if a path is allowed based on robots.txt."""
        if not self.respect_robots or not self.disallowed_paths:
            return True
        for disallowed in self.disallowed_paths:
            if path.startswith(disallowed):
                return False
        return True

    def get_webdriver(self):
        """Set up WebDriver for browser-based tests."""
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        if self.proxies:
            options.add_argument(f'--proxy-server={self.proxies["http"]}')
        return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    def _add_vulnerability(self, name, severity, description, cwe, remediation):
        """Add a vulnerability to results."""
        self.results["vulnerabilities"].append({
            "name": name, "severity": severity, "description": description, "cwe": cwe, "remediation": remediation
        })
        score_map = {"High": 10, "Medium": 5, "Low": 2}
        self.results["risk_score"] += score_map.get(severity, 0)

    def save_results(self):
        """Save scan results to SQLite database."""
        conn = sqlite3.connect("scan_history.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans 
                     (id INTEGER PRIMARY KEY, target TEXT, timestamp TEXT, risk_score INTEGER, findings TEXT)''')
        c.execute("INSERT INTO scans (target, timestamp, risk_score, findings) VALUES (?, ?, ?, ?)",
                  (self.target_url, self.results["scan_time"], self.results["risk_score"],
                   json.dumps(self.results["findings"])))
        conn.commit()
        conn.close()


