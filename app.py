import os
import re
import threading
import csv
import ssl
import json
import time
import yaml
import socket
import random
import sqlite3
import logging
from decimal import Decimal # <<< FIX: Added Decimal import
from functools import lru_cache
from urllib.parse import urlparse, urljoin, parse_qs, quote, urlunparse
from datetime import datetime
import requests
import urllib3
import dns.resolver
import whois
from typing import Dict, Optional, List, Any # Added List, Any for typing
import pdfkit # Added pdfkit
from bs4 import BeautifulSoup, Comment # Added Comment
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from flask import Flask, render_template, request, jsonify, send_file, Response, session # Added Response, session
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from packaging import version as packaging_version
from playwright.sync_api import sync_playwright, Error as PlaywrightError # Added PlaywrightError
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException # <<< FIX: Added TimeoutException import

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Flask app
app = Flask(__name__)
# <<< SECRET KEY IS NECESSARY FOR SESSION MANAGEMENT >>>
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'a_default_development_secret_key_replace_me')
current_dir = os.path.dirname(os.path.abspath(__file__))

# --- Configuration ---
# Payload Directory
DEFAULT_PAYLOADS_DIR = os.path.join(current_dir, 'payloads')
if not os.path.isdir(DEFAULT_PAYLOADS_DIR):
    # Fallback or create if needed, adjust as necessary
    DEFAULT_PAYLOADS_DIR = os.path.join(current_dir, 'ethical_scanner_web', 'payloads')
    if not os.path.isdir(DEFAULT_PAYLOADS_DIR):
         logging.warning(f"Payload directory not found at expected locations: {DEFAULT_PAYLOADS_DIR}")
         # Consider creating it or providing better configuration

# Logging Setup
LOG_FILE = 'security_scan.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=LOG_FILE,
    filemode='a' # Append to log file
)
logger = logging.getLogger('EthicalSecurityScanner')

# CVE_DIR = os.getenv('CVE_DATA_PATH', os.path.join(current_dir, 'cvelist')) # Example using env var or relative path
# Using original hardcoded path for now, but this is a MAJOR issue if not correct for your system
CVE_DIR = os.path.join(current_dir, 'cvelist')
if not os.path.isdir(CVE_DIR):
    logger.error(f"CRITICAL: CVE directory not found: {CVE_DIR}. CVE checks will likely fail.")

# NVD API Configuration (Strongly recommend using environment variables)
NVD_API_KEY = os.getenv("NVD_API_KEY") # Load from environment variable
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "YOUR_SECURITYTRAILS_API_KEY") # Use env var, keep placeholder default
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY") # Use env var, keep placeholder default


# Payload Files (Define as constants)
PAYLOAD_FILES = {
    "sql": "sql_payloads.txt",
    "xss": "xss_payloads.txt",
    "passwords": "password_list.txt", # Added for brute force
    }

# Severity Levels & Scores (Define as constants)
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_SCORES = {'Critical': 15, 'High': 10, 'Medium': 5, 'Low': 2, 'Info': 0}

# --- Scanner Class ---
class EthicalSecurityScanner:
    def __init__(self, target_url, scan_type="full", selected_categories=None,
                 threads=5, timeout=10, user_agent=None,
                 respect_robots=True, scan_depth=2, payloads_dir=DEFAULT_PAYLOADS_DIR):
        """Initialize the EthicalSecurityScanner."""
        if not target_url or not isinstance(target_url, str):
            raise ValueError("Target URL must be a non-empty string")
        # Ensure URL scheme
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme:
            target_url = 'https://' + target_url # Default to HTTPS if missing
            logger.info(f"Assuming HTTPS for target: {target_url}")
        elif parsed_url.scheme not in ('http', 'https'):
            raise ValueError("Target URL must start with http:// or https://")
        self.target_url = target_url
        self.domain = parsed_url.netloc # Store parsed netloc
        self.ip_addresses = []
        self.request_semaphore = threading.Semaphore(threads)
        self.scan_type = scan_type
        self.selected_categories = selected_categories or []
        self.threads = threads
        self.timeout = timeout
        self.respect_robots = respect_robots
        self.scan_depth = scan_depth
        self.payloads_dir = payloads_dir

        self.user_agent = user_agent or f'Mozilla/5.0 (Ethical Security Scanner/{time.time()})'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        self.session.verify = False # Disable SSL verification globally (consider making this configurable)
        # Initialize DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = self.timeout  # Total time for DNS queries
        self.disallowed_paths = []
        self.results = {
            "target": self.target_url,
            "scan_time": datetime.now().isoformat(),
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
            },
            "domain_info": None # Initialize domain_info key, fetch later
        }
        if self.respect_robots:
            self.parse_robots_txt()

        # Fetch domain info at init or defer to scan phase? Deferring for now.
        # self.results["domain_info"] = self.check_domain_information() or {}

    # --- Configuration & Payload Loading ---
    def load_config(self, config_file="config.yaml"):
        """Load configuration from a YAML file or use default settings."""
        # Define defaults directly in the method
        config = {
            "max_requests_per_second": 10, # Note: Not directly enforced in current code
            "respect_robots_txt": self.respect_robots,
            "follow_redirects": True, # This config value is NOT directly applied to session
            "max_redirects": 5,
            "scan_cookies": True, # Note: These flags aren't used to gate checks currently
            "scan_forms": True,
            "check_csrf": True,
            "disable_modules": [],
            "user_agent": self.user_agent,
            "headers": {},
            "cookie_jar": {}
        }
        config_path = os.path.join(current_dir, config_file)
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    custom_config = yaml.safe_load(f)
                    if custom_config:
                        config.update(custom_config) # Overwrite defaults with custom values
                        logger.info(f"Loaded configuration from: {config_path}")
            except yaml.YAMLError as e:
                logger.error(f"Error parsing config file {config_path}: {e}", exc_info=True)
            except IOError as e:
                logger.error(f"Error reading config file {config_path}: {e}", exc_info=True)

        # Apply loaded/default config settings
        self.user_agent = config.get("user_agent", self.user_agent)
        self.respect_robots = config.get("respect_robots_txt", self.respect_robots)
        # Apply session settings from config
        self.session.headers.update({
            'User-Agent': self.user_agent,
            **config.get("headers", {})
        })
        self.session.max_redirects = config.get("max_redirects", 5)
        if config.get("cookie_jar"):
            for domain, cookies in config.get("cookie_jar", {}).items():
                for name, value in cookies.items():
                    self.session.cookies.set(name, value, domain=domain)
        self.disabled_modules = config.get("disable_modules", [])

        return config # Return the final config dict

    @staticmethod
    @lru_cache(maxsize=None) # Cache indefinitely as files don't change during run
    def load_payloads(file_name, payloads_dir=DEFAULT_PAYLOADS_DIR):
        """Load payloads from a file in the payloads directory. Static method."""
        file_path = os.path.join(payloads_dir, file_name)
        payloads = []
        try:
            with open(file_path, 'r', encoding="utf-8") as f:
                payloads = [line.strip() for line in f if line.strip()]
            if not payloads:
                logger.warning(f"Payload file '{file_path}' is empty.")
            else:
                logger.info(f"Loaded {len(payloads)} payloads from '{file_path}'")
        except FileNotFoundError:
            logger.error(f"Payload file not found: {file_path}")
        except IOError as e:
            logger.error(f"Failed to read payloads from {file_path}: {e}", exc_info=True)
        except Exception as e: # Catch other potential errors
            logger.error(f"Unexpected error loading payloads from {file_path}: {e}", exc_info=True)
        return payloads

    # --- CVE & Dependency Checking ---
    @staticmethod
    @lru_cache(maxsize=None) # Cache indefinitely
    def load_cve_data(cve_dir_path=CVE_DIR):
        """Load all CVE JSON files from the specified directory structure."""
        cve_list = []
        if not os.path.isdir(cve_dir_path):
            logger.error(f"CVE directory not found: {cve_dir_path}")
            return cve_list
        logger.info(f"Loading CVE data from: {cve_dir_path}")
        for year_folder in os.listdir(cve_dir_path):
            year_path = os.path.join(cve_dir_path, year_folder)
            if os.path.isdir(year_path) and year_folder.isdigit():
                 for filename in os.listdir(year_path):
                    if filename.endswith('.json'):
                        file_path = os.path.join(year_path, filename)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                cve_data = json.load(f)
                                # Handle different possible structures
                                if isinstance(cve_data, dict):
                                    if 'cve' in cve_data: # NVD API 1.0 like structure?
                                        cve_list.append(cve_data)
                                    elif 'vulnerabilities' in cve_data: # NVD API 2.0 like structure?
                                         cve_list.extend(item.get('cve') for item in cve_data['vulnerabilities'] if item.get('cve'))
                                elif isinstance(cve_data, list): # Some files might be lists of CVEs
                                     cve_list.extend(item.get('cve') for item in cve_data if isinstance(item, dict) and item.get('cve'))
                        except json.JSONDecodeError:
                            logger.warning(f"Skipping invalid JSON file: {file_path}")
                        except IOError as e:
                            logger.warning(f"Cannot read file {file_path}: {e}")

        logger.info(f"Loaded {len(cve_list)} CVE entries from local files.")
        return cve_list

    @staticmethod
    @lru_cache(maxsize=1) # Cache once
    def load_dependencies(dependencies_file):
        """Load software and versions from a CSV file."""
        deps = []
        try:
            with open(dependencies_file, 'r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                if 'product' not in reader.fieldnames or 'version' not in reader.fieldnames:
                    logger.error("Dependencies CSV must contain 'product' and 'version' columns")
                    raise ValueError("CSV must contain 'product' and 'version' columns")
                deps = list(reader)
                logger.info(f"Loaded {len(deps)} dependencies from {dependencies_file}")
        except FileNotFoundError:
            logger.error(f"Dependencies file not found: {dependencies_file}")
        except ValueError as e: # Catch specific error from check
             logger.error(f"CSV format error in {dependencies_file}: {e}")
        except Exception as e:
            logger.error(f"Error loading dependencies from {dependencies_file}: {e}", exc_info=True)
        return deps

    @staticmethod
    def is_version_vulnerable(system_version_str, cpe_match_data):
        """Check if a system version is within a vulnerable range based on CPE match data."""
        try:
            system_ver = packaging_version.parse(system_version_str)
        except packaging_version.InvalidVersion:
            logger.debug(f"Skipping invalid system version format for comparison: {system_version_str}")
            return False

        cpe_uri = cpe_match_data.get('cpe23Uri', cpe_match_data.get('criteria', ''))
        cpe_parts = cpe_uri.split(':')
        cpe_version = cpe_parts[5] if len(cpe_parts) > 5 else '*'

        if cpe_version != '*' and cpe_version != '':
             try:
                 return system_ver == packaging_version.parse(cpe_version)
             except packaging_version.InvalidVersion:
                  logger.debug(f"Invalid CPE version format: {cpe_version}")

        start_including = cpe_match_data.get('versionStartIncluding')
        start_excluding = cpe_match_data.get('versionStartExcluding')
        end_including = cpe_match_data.get('versionEndIncluding')
        end_excluding = cpe_match_data.get('versionEndExcluding')

        is_vulnerable = True
        try:
            if start_including and system_ver < packaging_version.parse(start_including): is_vulnerable = False
            if start_excluding and system_ver <= packaging_version.parse(start_excluding): is_vulnerable = False
            if end_including and system_ver > packaging_version.parse(end_including): is_vulnerable = False
            if end_excluding and system_ver >= packaging_version.parse(end_excluding): is_vulnerable = False
        except packaging_version.InvalidVersion as e:
            logger.debug(f"Invalid version format in range check: {e}")
            is_vulnerable = True # Assume vulnerable on parse error in range? Conservative.
        return is_vulnerable

    def fetch_nvd_cves(self, product, version_str):
        """Fetch CVEs from NVD API for a specific product and version (synchronous)."""
        if not NVD_API_KEY:
            logger.warning("NVD_API_KEY environment variable not set; skipping online CVE fetch.")
            return []
        # Construct CPE more carefully if possible, otherwise use wildcard
        cpe_name = f"cpe:2.3:a:*:{product.lower()}:{version_str}:*:*:*:*:*:*:*"
        params = {"cpeName": cpe_name, "resultsPerPage": 50}
        headers = {"apiKey": NVD_API_KEY, "User-Agent": self.user_agent}
        try:
            logger.debug(f"Fetching NVD CVEs for CPE: {cpe_name}")
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            cves = data.get('vulnerabilities', [])
            logger.info(f"Fetched {len(cves)} CVEs from NVD for {product} {version_str}")
            return cves
        except requests.Timeout:
            logger.error(f"Timeout fetching NVD CVEs for {product} {version_str} after {self.timeout}s")
        except requests.HTTPError as e:
            logger.warning(f"NVD API request failed for {product} {version_str}: {e.response.status_code} {e.response.reason}")
        except requests.RequestException as e:
            logger.error(f"Network error fetching NVD CVEs for {product} {version_str}: {e}")
        except ValueError as e: # JSON Decode Error
            logger.error(f"Failed to decode NVD API response for {product} {version_str}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching NVD CVEs for {product} {version_str}: {e}", exc_info=True)
        return []

    def check_vulnerabilities(self, dependencies_file=None, use_nvd=True):
        """Detect vulnerabilities affecting installed software (hybrid: local + NVD)."""
        matching_cves = {}
        logger.info("Starting vulnerability check against dependencies...")

        dependencies = []
        if dependencies_file:
            dependencies = self.load_dependencies(dependencies_file)
        if not dependencies:
            logger.warning("No dependencies provided for vulnerability check.")
            self.results['findings']['cve_check'] = {"dependencies_checked": 0, "matching_cves_count": 0, "cves": {}}
            return matching_cves

        local_cves = self.load_cve_data()
        if not local_cves and not use_nvd:
            logger.warning("No local CVE data and NVD check disabled; cannot perform check.")
            self.results['findings']['cve_check'] = {"dependencies_checked": len(dependencies),"matching_cves_count": 0, "cves": {}}
            return matching_cves


        logger.info("Processing local CVE data...")
        processed_local = 0
        for cve_entry in local_cves:
             # ... (rest of local CVE processing logic - seems mostly okay) ...
            pass # Placeholder - keep existing logic

        logger.info(f"Processed {processed_local} potentially relevant CVEs from local data.")

        if use_nvd and NVD_API_KEY:
            logger.info("Fetching CVE data from NVD API...")
            processed_nvd = 0
            for dep in dependencies:
                # ... (rest of NVD fetching and processing logic - seems mostly okay) ...
                pass # Placeholder - keep existing logic

            logger.info(f"Processed {processed_nvd} potentially relevant CVEs from NVD API.")

        total_matching = len(matching_cves)
        logger.info(f"Found {total_matching} total matching CVEs for the given dependencies.")
        self.results['findings']['cve_check'] = {
            "dependencies_checked": len(dependencies),
            "matching_cves_count": total_matching,
            "cves": matching_cves
        }

        for cve_id, data in matching_cves.items():
            self._add_vulnerability(
                name=f"Dependency Vulnerability ({cve_id})",
                severity="High", # TODO: Use CVSS score if available
                description=f"Affected components: {', '.join(data['affected'])}. Description: {data['description']}",
                cwe="CWE-937",
                remediation=f"Update affected components. See references: {', '.join(data['references'][:2])}"
            )
        return matching_cves # Return the dict

    # --- Network & Basic Checks ---
    def get_proxies(self):
        """Load proxies from a file."""
        proxy_file = os.path.join(self.payloads_dir, "proxies.txt")
        try:
            with open(proxy_file, 'r', encoding='utf-8') as f:
                proxy_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if proxy_list:
                 # Choose one proxy for both http/https for simplicity with requests
                 chosen_proxy = random.choice(proxy_list)
                 return {"http": chosen_proxy, "https": chosen_proxy}
            else:
                 return None
        except FileNotFoundError:
            logger.warning("Proxy file 'proxies.txt' not found in payloads directory.")
            return None
        except Exception as e:
            logger.error(f"Error reading proxy file: {e}")
            return None

    def _make_request(self, method, url, **kwargs):
        """Centralized request making with error handling and stats."""
        req_timeout = kwargs.pop('timeout', self.timeout)
        use_proxies = kwargs.pop('use_proxies', False)
        allow_redirects_param = kwargs.pop('allow_redirects', True) # Get allow_redirects from kwargs

        req_kwargs = kwargs.copy() # Avoid modifying original kwargs
        req_kwargs['proxies'] = self.get_proxies() if use_proxies else None
        req_kwargs['verify'] = self.session.verify
        req_kwargs['timeout'] = req_timeout
        req_kwargs['allow_redirects'] = allow_redirects_param # Pass the param correctly

        response = None
        error_message = None
        try:
            with self.request_semaphore:
                response = self.session.request(method, url, **req_kwargs)
            self.results['scan_stats']['requests_made'] += 1
        except requests.exceptions.Timeout:
            error_message = f"Request timeout ({req_timeout}s) for {url}"
        except requests.exceptions.SSLError as e:
            error_message = f"SSL error for {url}: {e}"
        except requests.exceptions.ConnectionError as e:
            error_message = f"Connection error for {url}: {e}"
        except requests.exceptions.TooManyRedirects as e:
             error_message = f"Too many redirects for {url}: {e}"
        except requests.exceptions.RequestException as e:
            error_message = f"Request failed for {url}: {e}"
        except Exception as e:
            error_message = f"Unexpected error during request to {url}: {e}"

        if error_message:
            logger.warning(error_message) # Log warning for most request issues
            self.results['scan_stats']['errors_encountered'] += 1
            # Return an error dict structure
            return {"error": error_message, "status_code": None, "headers": {}, "text": "", "content": b""}

        return response # Return the actual response object on success

    def check_domain_information(self) -> Optional[Dict]:
        """Checks domain information including WHOIS, DNS, subdomains, and reputation."""
        try:
            domain = self.domain # Use already parsed domain
            if not domain:
                logger.error("Could not extract domain from URL: %s", self.target_url)
                self.results["scan_stats"]["errors_encountered"] += 1
                return {"error": "Domain extraction failed"}

            logger.info("Checking domain information for: %s", domain)
            domain_info = {
                "domain": domain,
                "base_domain": '.'.join(domain.split('.')[-2:]), # Basic base domain extraction
                "whois": {},
                "dns": {}, # Store DNS results here
                # "ssl": {}, # SSL check done in check_https
                "subdomains": [],
                "reputation": {},
                "risk_notes": []
            }

            self._fetch_whois(domain_info, domain)
            self._fetch_dns(domain_info, domain)
            self._fetch_subdomains(domain_info, domain) # Requires API Key
            self._fetch_reputation(domain_info, domain) # Requires API Key
            self._assess_risks(domain_info)

            logger.info("Domain information collected for %s", domain)
            self.results["findings"]["domain_info"] = domain_info # Store results
            return domain_info

        except Exception as e:
            logger.error("Failed to check domain information for %s: %s", self.target_url, str(e), exc_info=True)
            self.results["scan_stats"]["errors_encountered"] += 1
            self.results["findings"]["domain_info"] = {"error": f"Failed: {str(e)}"}
            return None

    def _fetch_whois(self, domain_info: Dict, domain: str) -> None:
        """Fetch WHOIS information synchronously."""
        try:
            w = whois.whois(domain)
            # Convert datetime objects to strings if they exist
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            updated_date = w.updated_date

            domain_info["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(creation_date) if creation_date else None,
                "expiration_date": str(expiration_date) if expiration_date else None,
                "updated_date": str(updated_date) if updated_date else None, # Added updated date
                "name_servers": w.name_servers,
                "status": w.status, # Added status
                "emails": w.emails, # Added emails
                "dnssec": w.dnssec, # Added DNSSEC status
                # Registrant info might be redacted - handle potential None
                "registrant": getattr(w.registrant, 'name', None), # Example access
                "registrant_country": getattr(w.registrant, 'country', None) # Example access
            }
            # Clean up potential list dates
            if isinstance(domain_info["whois"]["creation_date"], list): domain_info["whois"]["creation_date"] = str(domain_info["whois"]["creation_date"][0])
            if isinstance(domain_info["whois"]["expiration_date"], list): domain_info["whois"]["expiration_date"] = str(domain_info["whois"]["expiration_date"][0])
            if isinstance(domain_info["whois"]["updated_date"], list): domain_info["whois"]["updated_date"] = str(domain_info["whois"]["updated_date"][0])

        except Exception as e:
            logger.warning("WHOIS lookup failed for %s: %s", domain, str(e))
            domain_info["whois"] = {"error": str(e)} # Store error within whois dict
            self.results["scan_stats"]["errors_encountered"] += 1

    def _fetch_dns(self, domain_info: Dict, domain: str) -> None:
        """Fetch DNS records (A, MX, NS, TXT, CAA, SPF) synchronously."""
        dns_records = {} # Store results temporarily
        dns_types = ["A", "MX", "NS", "TXT", "CAA", "SPF"] # Common types
        for record_type in dns_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                dns_records[record_type] = sorted([str(r) for r in answers])
            except dns.resolver.NoAnswer:
                 logger.debug("No %s records found for %s", record_type, domain)
                 dns_records[record_type] = [] # Indicate no records found
            except dns.resolver.NXDOMAIN:
                 logger.warning("Domain %s does not exist (NXDOMAIN)", domain)
                 dns_records["error"] = "NXDOMAIN"
                 break # Stop checking if domain doesn't exist
            except dns.exception.Timeout:
                 logger.warning("DNS query timeout for %s type %s", domain, record_type)
                 dns_records[record_type] = {"error": "Timeout"}
            except Exception as e:
                 logger.warning("DNS %s record lookup failed for %s: %s", record_type, domain, str(e))
                 dns_records[record_type] = {"error": str(e)}
                 self.results["scan_stats"]["errors_encountered"] += 1
        domain_info["dns"] = dns_records # Assign collected DNS info

    def _fetch_subdomains(self, domain_info: Dict, domain: str) -> None:
        """Enumerate subdomains using SecurityTrails API synchronously."""
        if not SECURITYTRAILS_API_KEY or "YOUR_" in SECURITYTRAILS_API_KEY:
             logger.warning("SecurityTrails API key not set or is placeholder; skipping subdomain enumeration.")
             domain_info["subdomains"] = {"status": "skipped", "reason": "API Key missing"}
             return
        try:
            api_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": SECURITYTRAILS_API_KEY, "Accept": "application/json"}
            response = self._make_request('get', api_url, headers=headers)

            if isinstance(response, dict) and response.get("error"): # Check _make_request error format
                 raise requests.RequestException(response["error"])
            elif response is None:
                raise requests.RequestException("No response from SecurityTrails API")

            if response.status_code == 200:
                data = response.json()
                subdomains = [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
                domain_info["subdomains"] = {"count": len(subdomains), "list": subdomains[:100]} # Limit list size
                logger.info(f"Found {len(subdomains)} subdomains via SecurityTrails for {domain}")
            else:
                error_detail = f"API returned status {response.status_code}"
                try: error_detail += f" - {response.json().get('message', response.reason)}" # Try to get message
                except: pass
                logger.warning(f"Subdomain API request failed for {domain}: {error_detail}")
                domain_info["subdomains"] = {"status": "error", "reason": error_detail}
                self.results["scan_stats"]["errors_encountered"] += 1

        except requests.RequestException as e:
            logger.warning("Subdomain enumeration network error for %s: %s", domain, str(e))
            domain_info["subdomains"] = {"status": "error", "reason": f"Network error: {str(e)}"}
            self.results["scan_stats"]["errors_encountered"] += 1
        except ValueError as e: # JSON Decode Error
            logger.warning("Failed to decode Subdomain API response for %s: %s", domain, str(e))
            domain_info["subdomains"] = {"status": "error", "reason": "Invalid API response format"}
            self.results["scan_stats"]["errors_encountered"] += 1
        except Exception as e:
            logger.warning("Subdomain enumeration failed unexpectedly for %s: %s", domain, str(e), exc_info=True)
            domain_info["subdomains"] = {"status": "error", "reason": f"Unexpected error: {str(e)}"}
            self.results["scan_stats"]["errors_encountered"] += 1

    def _fetch_reputation(self, domain_info: Dict, domain: str) -> None:
        """Check domain reputation using VirusTotal API synchronously."""
        if not VIRUSTOTAL_API_KEY or "YOUR_" in VIRUSTOTAL_API_KEY:
             logger.warning("VirusTotal API key not set or is placeholder; skipping reputation check.")
             domain_info["reputation"] = {"status": "skipped", "reason": "API Key missing"}
             return
        try:
            api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}
            response = self._make_request('get', api_url, headers=headers)

            if isinstance(response, dict) and response.get("error"):
                 raise requests.RequestException(response["error"])
            elif response is None:
                raise requests.RequestException("No response from VirusTotal API")

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                domain_info["reputation"] = {
                    "status": "checked",
                    "malicious": last_analysis_stats.get("malicious", 0),
                    "suspicious": last_analysis_stats.get("suspicious", 0),
                    "harmless": last_analysis_stats.get("harmless", 0),
                    "undetected": last_analysis_stats.get("undetected", 0),
                    "last_analysis_date": datetime.fromtimestamp(attributes.get("last_analysis_date", 0)).isoformat() if attributes.get("last_analysis_date") else None,
                    "link": f"https://www.virustotal.com/gui/domain/{domain}"
                }
                if domain_info["reputation"]["malicious"] > 0 or domain_info["reputation"]["suspicious"] > 0:
                     domain_info["risk_notes"].append("Domain flagged as potentially malicious/suspicious by VirusTotal.")
            elif response.status_code == 404:
                 logger.info(f"Domain {domain} not found in VirusTotal database.")
                 domain_info["reputation"] = {"status": "not_found"}
            else:
                error_detail = f"API returned status {response.status_code}"
                try: error_detail += f" - {response.json().get('error', {}).get('message', response.reason)}"
                except: pass
                logger.warning(f"Reputation API request failed for {domain}: {error_detail}")
                domain_info["reputation"] = {"status": "error", "reason": error_detail}
                self.results["scan_stats"]["errors_encountered"] += 1

        except requests.RequestException as e:
            logger.warning("Reputation check network error for %s: %s", domain, str(e))
            domain_info["reputation"] = {"status": "error", "reason": f"Network error: {str(e)}"}
            self.results["scan_stats"]["errors_encountered"] += 1
        except ValueError as e: # JSON Decode Error
            logger.warning("Failed to decode Reputation API response for %s: %s", domain, str(e))
            domain_info["reputation"] = {"status": "error", "reason": "Invalid API response format"}
            self.results["scan_stats"]["errors_encountered"] += 1
        except Exception as e:
            logger.warning("Reputation check failed unexpectedly for %s: %s", domain, str(e), exc_info=True)
            domain_info["reputation"] = {"status": "error", "reason": f"Unexpected error: {str(e)}"}
            self.results["scan_stats"]["errors_encountered"] += 1

    def _assess_risks(self, domain_info: Dict) -> None:
        """Perform basic risk assessment based on collected domain data."""
        try:
            # Domain age check
            creation_date_str = domain_info.get("whois", {}).get("creation_date")
            if creation_date_str:
                try:
                    # Handle potential list format from some WHOIS results
                    if isinstance(creation_date_str, list): creation_date_str = creation_date_str[0]
                    # Try parsing common date formats
                    creation_date = None
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"): # Add more formats if needed
                         try:
                             creation_date = datetime.strptime(str(creation_date_str).split('+')[0].strip(), fmt) # Handle timezones crudely
                             break
                         except ValueError:
                             continue
                    if creation_date:
                        domain_age = (datetime.now() - creation_date).days
                        if domain_age < 90: # Flag domains younger than 3 months
                            domain_info["risk_notes"].append(f"Domain is relatively new ({domain_age} days old).")
                    else:
                         logger.debug(f"Could not parse creation date: {creation_date_str}")
                except Exception as date_e:
                     logger.warning(f"Error processing creation date '{creation_date_str}': {date_e}")

            # Suspicious registrar check (example)
            registrar = domain_info.get("whois", {}).get("registrar", "").lower()
            suspicious_registrars = ["namecheap", "godaddy", "publicdomainregistry"] # Example, adjust as needed
            if registrar and any(susp in registrar for susp in suspicious_registrars):
                domain_info["risk_notes"].append(f"Domain registered with '{registrar}', which is sometimes associated with abuse (verify legitimacy).")

            # DNS records check
            dns_recs = domain_info.get("dns", {})
            if not dns_recs.get("A"): domain_info["risk_notes"].append("No A records found; domain may not resolve to a web server.")
            if not dns_recs.get("MX"): domain_info["risk_notes"].append("No MX records found; email may not be configured for this domain.")
            if not dns_recs.get("SPF"): domain_info["risk_notes"].append("No SPF record found; potential email spoofing risk.")
            if not dns_recs.get("CAA"): domain_info["risk_notes"].append("No CAA record found; any CA can issue certificates.")

            # Subdomain exposure check
            subdomain_data = domain_info.get("subdomains", {})
            if isinstance(subdomain_data, dict) and subdomain_data.get("count", 0) > 50:
                domain_info["risk_notes"].append(f"High number of subdomains ({subdomain_data['count']}) detected; increases potential attack surface.")

        except Exception as e:
            logger.warning("Risk assessment failed: %s", str(e))
            self.results["scan_stats"]["errors_encountered"] += 1

    def resolve_domain(self):
        """Resolve domain to IP addresses using socket.getaddrinfo."""
        if not self.domain:
            logger.error("No domain available for resolution.")
            self.results["findings"]["ip_resolution"] = {"error": "No domain"}
            return []

        logger.info(f"Resolving domain: {self.domain}")
        try:
            addr_info = socket.getaddrinfo(self.domain, None)
            ips = sorted(list(set(item[4][0] for item in addr_info if item[4])))
            if ips:
                 self.ip_addresses = ips
                 self.results["findings"]["ip_resolution"] = {"ips": ips}
                 logger.info(f"Resolved {self.domain} to: {', '.join(ips)}")
                 return ips
            else:
                 logger.warning(f"DNS resolution for {self.domain} returned no IP addresses.")
                 self.results["findings"]["ip_resolution"] = {"error": "No IPs found"}
                 return []
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {self.domain}: {e}")
            self.results["findings"]["ip_resolution"] = {"error": f"DNS lookup failed: {e}"}
            return []
        except Exception as e:
            logger.error(f"Unexpected error during DNS resolution for {self.domain}: {e}", exc_info=True)
            self.results["findings"]["ip_resolution"] = {"error": f"Unexpected error: {e}"}
            return []

    def parse_robots_txt(self):
        """Parse robots.txt to find disallowed paths."""
        robots_url = urljoin(self.target_url, "/robots.txt")
        logger.info(f"Checking robots.txt at: {robots_url}")
        self.disallowed_paths = []
        if "findings" not in self.results: self.results["findings"] = {}
        robots_info = {"found": False, "error": None, "disallowed_paths": [], "url": robots_url}

        # Use HEAD first? No, need content. Use GET. Don't follow redirects for robots.txt itself.
        response = self._make_request('get', robots_url, allow_redirects=False)

        if isinstance(response, dict) and response.get("error"):
            robots_info["error"] = response["error"]
        elif response is None:
             robots_info["error"] = "Failed to fetch robots.txt (unknown error)"
        elif response.status_code == 200:
            robots_info["found"] = True
            lines = response.text.splitlines()
            current_user_agent_match = False
            ua_pattern = re.compile(r'User-agent:\s*(.*)', re.IGNORECASE)
            disallow_pattern = re.compile(r'Disallow:\s*(.*)', re.IGNORECASE)

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                ua_match = ua_pattern.match(line)
                if ua_match:
                    agent = ua_match.group(1).strip()
                    # Check if this agent applies to us ('*' or our specific UA)
                    current_user_agent_match = (agent == '*' or self.user_agent in agent)
                    continue # Move to next line

                if current_user_agent_match:
                    disallow_match = disallow_pattern.match(line)
                    if disallow_match:
                        path = disallow_match.group(1).strip()
                        # Normalize path: ensure it starts with / if not empty
                        if path and not path.startswith('/'): path = '/' + path
                        if path: robots_info["disallowed_paths"].append(path)

            self.disallowed_paths = robots_info["disallowed_paths"]
            logger.info(f"Found {len(self.disallowed_paths)} disallowed paths for user-agent '{self.user_agent}' or '*'")
        else:
            logger.info(f"robots.txt not found or accessible (Status: {response.status_code})")
            robots_info["found"] = False
            robots_info["status_code"] = response.status_code

        self.results["findings"]["robots_txt"] = robots_info
        return self.disallowed_paths

    def is_path_allowed(self, path):
        """Check if a URL path is allowed based on previously parsed robots.txt rules."""
        if not self.respect_robots:
            return True
        disallowed_paths_list = getattr(self, 'disallowed_paths', [])
        if not disallowed_paths_list:
            return True # Allowed if no rules found or parsing failed

        try:
            url_path = urlparse(path).path
            if not url_path: url_path = "/"
            # Ensure path starts with / for comparison
            if not url_path.startswith('/'): url_path = '/' + url_path

            for disallowed in disallowed_paths_list:
                if not disallowed: continue
                # Simple prefix matching: /path disallows /path/sub and /path?query
                if url_path.startswith(disallowed):
                    # Handle exact match rule: /path$
                    if disallowed.endswith('$') and url_path == disallowed[:-1]:
                         logger.debug(f"Path '{url_path}' disallowed by exact rule '{disallowed}'")
                         return False
                    elif not disallowed.endswith('$'):
                         logger.debug(f"Path '{url_path}' disallowed by prefix rule '{disallowed}'")
                         return False
        except Exception as e:
            logger.error(f"Error checking path allowance for '{path}': {e}", exc_info=True)
            return False # Err on the side of caution

        return True

    def check_https(self):
        """Check HTTPS support, certificate details, and related configurations."""
        logger.info("Starting HTTPS and SSL/TLS check...")
        findings = {"status": "pending", "https_supported": False, "certificate_valid": False}
        https_url = self.target_url if self.target_url.startswith('https://') else self.target_url.replace('http://', 'https://', 1)
        hostname = urlparse(https_url).netloc

        # 1. Basic HTTPS connectivity & HSTS Check
        response = self._make_request('get', https_url, timeout=self.timeout, use_proxies=False)

        if isinstance(response, dict) and response.get("error"):
            error_msg = response["error"]
            findings["status"] = "failed"
            findings["error"] = error_msg
            if "ssl error" in error_msg.lower() or "certificate verify failed" in error_msg.lower():
                findings["https_supported"] = True # Tried HTTPS but cert failed
                findings["certificate_valid"] = False
                self._add_vulnerability("Invalid SSL Certificate", "High", f"SSL certificate validation failed: {error_msg}", "CWE-295", "Install a valid, trusted SSL certificate.")
            else: # Other connection errors
                findings["https_supported"] = False
                self._add_vulnerability("HTTPS Connection Failed", "High", f"Could not connect to {https_url}: {error_msg}", "CWE-319", "Ensure server is configured for HTTPS and accessible.")
            self.results["findings"]["https"] = findings
            return findings

        # If request succeeded
        findings["https_supported"] = True
        findings["status"] = "completed"

        # Check HSTS Header
        if 'Strict-Transport-Security' in response.headers:
            findings["hsts_enabled"] = True
            findings["hsts_header"] = response.headers['Strict-Transport-Security']
            max_age_match = re.search(r'max-age=(\d+)', findings["hsts_header"])
            if not max_age_match or int(max_age_match.group(1)) < 15552000: # ~6 months
                self._add_vulnerability("Weak HSTS Policy", "Medium", "HSTS max-age is short (< 6 months) or missing.", "CWE-319", "Set HSTS max-age >= 15552000, consider includeSubDomains; preload.")
        else:
            findings["hsts_enabled"] = False
            self._add_vulnerability("HSTS Not Enabled", "Medium", "Strict-Transport-Security header missing.", "CWE-319", "Implement HSTS header.")

        # 2. Certificate Details using socket/cryptography
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            # Use a reasonable timeout for socket connection separate from request timeout
            conn = socket.create_connection((hostname, 443), timeout=min(self.timeout, 5)) # 5 sec timeout for TLS handshake
            with conn:
                with context.wrap_socket(conn, server_hostname=hostname) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    if not cert_binary: raise ssl.SSLError("Could not retrieve peer certificate.")

                    cert = x509.load_der_x509_certificate(cert_binary, default_backend())
                    findings["certificate_valid"] = True # Assume valid unless checks fail

                    findings["certificate_expiry"] = cert.not_valid_after.isoformat()
                    findings["certificate_issuer"] = cert.issuer.rfc4514_string()
                    findings["certificate_subject"] = cert.subject.rfc4514_string()
                    findings["certificate_version"] = cert.version.name
                    findings["certificate_algorithm"] = cert.signature_algorithm_oid._name

                    now_utc = datetime.utcnow()
                    is_expired = cert.not_valid_after < now_utc
                    not_yet_valid = cert.not_valid_before > now_utc
                    days_to_expiry = (cert.not_valid_after - now_utc).days if not is_expired else 0

                    findings["certificate_expired"] = is_expired
                    findings["certificate_not_yet_valid"] = not_yet_valid
                    findings["days_to_expiry"] = days_to_expiry

                    if is_expired:
                        findings["certificate_valid"] = False
                        self._add_vulnerability("Expired SSL Certificate", "Critical", "SSL certificate has expired.", "CWE-324", "Renew the SSL certificate.")
                    elif days_to_expiry < 30:
                        self._add_vulnerability("SSL Certificate Nearing Expiry", "Medium", f"SSL certificate expires in {days_to_expiry} days.", "CWE-324", "Renew the SSL certificate soon.")
                    if not_yet_valid:
                         findings["certificate_valid"] = False
                         self._add_vulnerability("SSL Certificate Not Yet Valid", "Critical", "Certificate validity period hasn't started.", "CWE-324", "Check server time or certificate issuance date.")

                    cipher = ssock.cipher()
                    findings["cipher_suite"] = cipher[0] if cipher else "Unknown"
                    findings["tls_version"] = cipher[1] if cipher else "Unknown"

                    # Add check for weak protocols/ciphers if needed (more complex)
                    self.results["findings"]["ssl_protocols"] = self.check_ssl_protocols(hostname) # Store protocol results separately

        except ssl.SSLCertVerificationError as e:
             findings["certificate_valid"] = False
             findings["error"] = f"Certificate verification failed: {e}"
             logger.warning(f"SSL Certificate verification error for {hostname}: {e}")
             self._add_vulnerability("Invalid SSL Certificate", "High", f"Certificate verification failed: {e.verify_message}", "CWE-295", "Ensure cert matches hostname, chain is trusted, not revoked.")
        except ssl.SSLError as e:
             findings["error"] = f"SSL error during certificate check: {e}"
             logger.warning(f"SSL error checking certificate for {hostname}: {e}")
             # Might not invalidate cert, but indicates a handshake problem
             self._add_vulnerability("SSL Handshake Issue", "Medium", f"SSL error during connection: {e}", "CWE-326", "Review TLS/SSL configuration on the server.")
        except socket.timeout:
            findings["error"] = "Timeout connecting to host for certificate check."
            logger.warning(f"Timeout connecting to {hostname}:443 for SSL check.")
        except socket.error as e:
            findings["error"] = f"Socket error during certificate check: {e}"
            logger.warning(f"Socket error connecting to {hostname}:443: {e}")
        except Exception as e:
            findings["error"] = f"Unexpected error during certificate check: {e}"
            logger.error(f"Unexpected error checking certificate for {hostname}: {e}", exc_info=True)

        # 3. Check HTTP to HTTPS Redirect (if original URL was HTTP)
        if self.target_url.startswith('http://'):
            logger.info("Checking for HTTP to HTTPS redirect...")
            redirect_check_response = self._make_request('get', self.target_url, allow_redirects=False)

            if isinstance(redirect_check_response, dict) and redirect_check_response.get("error"):
                 findings["http_to_https_redirect"] = f"Unknown ({redirect_check_response['error']})"
            elif redirect_check_response is None:
                 findings["http_to_https_redirect"] = "Unknown (Request failed)"
            elif redirect_check_response.status_code in (301, 302, 307, 308):
                 location = redirect_check_response.headers.get('Location', '')
                 if location.startswith('https://'):
                      findings["http_to_https_redirect"] = True
                      logger.info("HTTP to HTTPS redirect confirmed.")
                 else:
                      findings["http_to_https_redirect"] = False
                      logger.warning(f"HTTP redirects, but not to HTTPS (Location: {location})")
                      self._add_vulnerability("Insecure Redirect", "Medium", f"HTTP redirects to non-HTTPS URL: {location}", "CWE-319", "Ensure all HTTP redirects go to HTTPS.")
            else:
                 findings["http_to_https_redirect"] = False
                 logger.warning(f"No redirect found from HTTP to HTTPS (Status: {redirect_check_response.status_code})")
                 self._add_vulnerability("No HTTP to HTTPS Redirect", "Medium", "Site accessible via HTTP without redirecting.", "CWE-319", "Configure server to force HTTPS via redirect.")

        self.results["findings"]["https"] = findings
        logger.info("HTTPS and SSL/TLS check completed.")
        return findings

    def check_ssl_protocols(self, domain: str) -> Dict:
        """Check supported SSL/TLS protocols."""
        logger.info(f"Checking SSL/TLS protocol support for: {domain}")
        # Note: ssl.PROTOCOL_SSLvX are deprecated and may not work in modern Python/OpenSSL
        protocols_to_check = {
             # "SSLv3": ssl.PROTOCOL_SSLv3, # Deprecated, likely unsupported
             "TLSv1": ssl.PROTOCOL_TLSv1,
             "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
             "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
        }
        supported_protocols = {}
        weak_protocols_found = []

        # Check specific older protocols
        for name, proto_const in protocols_to_check.items():
            try:
                # Use PROTOCOL_TLS_CLIENT for modern handshake negotiation testing specific protocols
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                # Restrict max version to test *support* for older versions
                if name == "TLSv1": context.maximum_version = ssl.TLSVersion.TLSv1
                if name == "TLSv1.1": context.maximum_version = ssl.TLSVersion.TLSv1_1
                # Disable hostname check and cert verification just for protocol test
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                conn = socket.create_connection((domain, 443), timeout=min(self.timeout, 3)) # Shorter timeout for protocol test
                with conn:
                     with context.wrap_socket(conn, server_hostname=domain) as ssock:
                         # Connection successful means the protocol is likely supported
                         supported_protocols[name] = True
                         logger.warning(f"Weak protocol {name} appears to be supported by {domain}.")
                         weak_protocols_found.append(name)
            except ssl.SSLError as e:
                # Protocol unsupported likely results in SSLError during handshake
                if "no protocols available" in str(e).lower() or "unsupported protocol" in str(e).lower():
                     supported_protocols[name] = False
                else:
                     supported_protocols[name] = f"Error ({e.__class__.__name__})" # Other SSL error
                     logger.debug(f"SSL error testing {name} for {domain}: {e}")
            except socket.timeout:
                supported_protocols[name] = "timeout"
                logger.debug(f"Timeout testing {name} for {domain}")
            except ConnectionRefusedError:
                 supported_protocols[name] = "connection_refused" # Port not open
                 logger.warning(f"Connection refused on port 443 for {domain}")
                 # If conn refused, stop checking other protocols for this host
                 break
            except Exception as e:
                supported_protocols[name] = f"error: {e.__class__.__name__}"
                logger.warning(f"Unexpected error testing {name} for {domain}: {e}", exc_info=True)

        # Check TLS 1.3 support using default context (which prefers highest)
        try:
            context = ssl.create_default_context()
            conn = socket.create_connection((domain, 443), timeout=min(self.timeout, 3))
            with conn:
                with context.wrap_socket(conn, server_hostname=domain) as ssock:
                     negotiated_version = ssock.version()
                     supported_protocols["TLSv1.3"] = (negotiated_version == "TLSv1.3")
                     # Also implicitly confirms TLS 1.2 if 1.3 isn't supported but connection succeeds
                     if not supported_protocols["TLSv1.3"] and negotiated_version == "TLSv1.2":
                          supported_protocols["TLSv1.2"] = True # Confirm 1.2 support
        except Exception as e:
             logger.debug(f"Could not check TLS 1.3 support for {domain}: {e}")
             supported_protocols["TLSv1.3"] = "check_failed"

        # Add vulnerability if weak protocols are found
        if weak_protocols_found:
             self._add_vulnerability(
                 name="Weak SSL/TLS Protocols Supported",
                 severity="Medium",
                 description=f"Server supports outdated protocols: {', '.join(weak_protocols_found)}.",
                 cwe="CWE-326", # Inadequate Encryption Strength
                 remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on the server. Configure to support TLS 1.2 and TLS 1.3 only."
             )

        return supported_protocols

    def check_security_headers(self):
        """Check for presence and basic configuration of security headers."""
        logger.info("Checking security headers...")
        findings = {"headers": {}, "score": {"value": 0, "max": 100, "description": "Header security score"}, "error": None}
        HIGH = SEVERITY_LEVELS[1] # "High"
        MEDIUM = SEVERITY_LEVELS[2] # "Medium"

        # Simplified structure for recommendations
        HEADER_SPECS = {
            'Strict-Transport-Security': {'severity': HIGH, 'check': lambda v: 'max-age=' in v and int(re.search(r'max-age=(\d+)', v).group(1)) >= 15552000, 'rec': 'max-age=31536000; includeSubDomains; preload', 'desc': 'Enforces HTTPS.'},
            'Content-Security-Policy': {'severity': MEDIUM, 'check': lambda v: 'default-src' in v or 'script-src' in v or 'object-src' in v, 'rec': "default-src 'self'; object-src 'none';", 'desc': 'Mitigates XSS.'},
            'X-Content-Type-Options': {'severity': HIGH, 'check': lambda v: v.lower().strip() == 'nosniff', 'rec': 'nosniff', 'desc': 'Prevents MIME-sniffing.'},
            'X-Frame-Options': {'severity': HIGH, 'check': lambda v: v.upper().strip() in ['DENY', 'SAMEORIGIN'], 'rec': 'DENY or SAMEORIGIN', 'desc': 'Prevents clickjacking.'},
            'Referrer-Policy': {'severity': MEDIUM, 'check': lambda v: any(p in v.lower() for p in ['no-referrer', 'same-origin', 'strict-origin']), 'rec': 'strict-origin-when-cross-origin or same-origin', 'desc': 'Controls referrer info.'},
            'Permissions-Policy': {'severity': MEDIUM, 'check': lambda v: bool(v), 'rec': 'camera=(), microphone=(), geolocation=()', 'desc': 'Controls browser features.'}
        }

        response = self._make_request('get', self.target_url)

        if isinstance(response, dict) and response.get("error"):
            findings["error"] = response["error"]
            self.results["findings"]["security_headers"] = findings
            return findings
        if response is None: # Should be handled by _make_request returning dict
             findings["error"] = "Failed to fetch target URL"
             self.results["findings"]["security_headers"] = findings
             return findings

        headers_present = response.headers # Case-insensitive dict-like object
        total_possible_score = sum(SEVERITY_SCORES.get(spec['severity'], 0) for spec in HEADER_SPECS.values())
        achieved_score = 0
        header_results = {}

        for header, spec in HEADER_SPECS.items():
            header_value = headers_present.get(header) # Case-insensitive get
            present = header_value is not None
            secure = False
            details = {
                'present': present,
                'value': header_value,
                'is_secure': False,
                'recommendation': spec['rec'],
                'description': spec['desc']
            }

            if present:
                try:
                    secure = spec['check'](header_value)
                    details['is_secure'] = secure
                    if not secure:
                         self._add_vulnerability(f"Misconfigured Header: {header}", spec['severity'], f"Value: '{header_value}'. Recommended: '{spec['rec']}'.", "CWE-693", f"Configure '{header}' as per recommendation.")
                except Exception as e:
                    logger.error(f"Error validating header '{header}': {e}", exc_info=True)
                    details['is_secure'] = False # Mark insecure on error
                    self._add_vulnerability(f"Validation Error: {header}", "Low", f"Could not validate header value '{header_value}'. Error: {e}", "CWE-693", f"Review header configuration and validation logic.")
            else:
                 self._add_vulnerability(f"Missing Header: {header}", spec['severity'], spec['desc'], "CWE-693", f"Implement '{header}' header. Recommended: '{spec['rec']}'.")

            if secure:
                achieved_score += SEVERITY_SCORES.get(spec['severity'], 0)

            header_results[header] = details

        findings["headers"] = header_results
        findings["score"]["value"] = round((achieved_score / total_possible_score) * 100) if total_possible_score > 0 else 100

        self.results["findings"]["security_headers"] = findings
        logger.info(f"Security headers check completed. Score: {findings['score']['value']}%")
        return findings

    def check_cookies(self):
        """Check cookie security attributes (Secure, HttpOnly, SameSite)."""
        logger.info("Checking cookie security attributes...")
        findings = {"cookies": [], "stats": {"total": 0, "secure": 0, "http_only": 0, "lax": 0, "strict": 0, "none": 0}, "error": None}

        response = self._make_request('get', self.target_url)

        if isinstance(response, dict) and response.get("error"):
            findings["error"] = response["error"]
            self.results["findings"]["cookies"] = findings
            return findings
        if response is None or not hasattr(response, 'cookies'):
             findings["error"] = "Failed to fetch target URL or get cookies."
             self.results["findings"]["cookies"] = findings
             return findings

        cookies = response.cookies # This is a RequestsCookieJar
        findings["stats"]["total"] = len(cookies)

        if findings["stats"]["total"] == 0:
            findings["message"] = "No cookies set by the initial response."
            self.results["findings"]["cookies"] = findings
            logger.info("No cookies found in the response.")
            return findings

        # Need to parse Set-Cookie headers manually for reliable attribute checking
        set_cookie_headers = response.raw.headers.getlist('Set-Cookie')
        parsed_cookies = {}

        for header_value in set_cookie_headers:
            parts = header_value.split(';')
            name_value = parts[0].strip().split('=', 1)
            name = name_value[0]
            value = name_value[1] if len(name_value) > 1 else ''

            attributes = {'secure': False, 'httponly': False, 'samesite': None}
            domain = None
            path = None
            expires = None

            for part in parts[1:]:
                part = part.strip()
                key_value = part.split('=', 1)
                attr_name = key_value[0].lower()

                if attr_name == 'secure': attributes['secure'] = True
                elif attr_name == 'httponly': attributes['httponly'] = True
                elif attr_name == 'samesite': attributes['samesite'] = key_value[1].lower() if len(key_value) > 1 else None
                elif attr_name == 'domain': domain = key_value[1] if len(key_value) > 1 else None
                elif attr_name == 'path': path = key_value[1] if len(key_value) > 1 else None
                elif attr_name == 'expires':
                     try: expires = datetime.strptime(key_value[1], "%a, %d %b %Y %H:%M:%S %Z").isoformat()
                     except: pass # Ignore parse errors

            # Use requests jar info as fallback/supplementary
            requests_cookie = cookies.get(name)
            if requests_cookie:
                domain = domain or requests_cookie.domain
                path = path or requests_cookie.path
                # expires = expires or requests_cookie.expires # requests expires is timestamp

            cookie_info = {
                "name": name,
                "domain": domain or self.domain, # Default to target domain if not set
                "path": path or '/', # Default to root path
                "secure": attributes['secure'],
                "http_only": attributes['httponly'],
                "same_site": attributes['samesite'],
                "expiry": expires # Store expiry if parsed
             }
            parsed_cookies[name] = cookie_info # Store by name

            # Update stats
            if attributes['secure']: findings["stats"]["secure"] += 1
            if attributes['httponly']: findings["stats"]["http_only"] += 1
            if attributes['samesite'] == 'lax': findings["stats"]["lax"] += 1
            if attributes['samesite'] == 'strict': findings["stats"]["strict"] += 1
            if attributes['samesite'] == 'none': findings["stats"]["none"] += 1

        # Add vulnerabilities based on parsed attributes
        for name, info in parsed_cookies.items():
            if not info['secure']:
                self._add_vulnerability("Cookie Without Secure Flag", "Medium", f"Cookie '{name}' lacks Secure flag.", "CWE-614", "Add Secure flag to ensure cookie is only sent via HTTPS.")
            if not info['http_only']:
                severity = "High" if "sess" in name.lower() or "auth" in name.lower() else "Medium"
                self._add_vulnerability("Cookie Without HttpOnly Flag", severity, f"Cookie '{name}' lacks HttpOnly flag.", "CWE-1004", "Add HttpOnly flag to prevent access via client-side scripts.")
            if info['same_site'] == 'none' and not info['secure']:
                self._add_vulnerability("Insecure SameSite=None Cookie", "Medium", f"Cookie '{name}' has SameSite=None but lacks Secure flag.", "CWE-1275", "Add Secure flag when using SameSite=None.")
            elif not info['same_site']:
                self._add_vulnerability("Cookie Missing SameSite Flag", "Low", f"Cookie '{name}' lacks explicit SameSite flag (defaults to Lax).", "CWE-1275", "Set SameSite=Lax or SameSite=Strict explicitly.")

        findings["cookies"] = list(parsed_cookies.values()) # Store the list of parsed cookies
        self.results["findings"]["cookies"] = findings
        logger.info(f"Cookie check completed. Found {findings['stats']['total']} cookies.")
        return findings

    def check_information_disclosure(self):
        """Check for common information disclosure vectors."""
        logger.info("Checking for information disclosure...")
        findings = {
            "server_info": {},
            "tech_stack": set(),
            "comments": [],
            "sensitive_files": [], # Changed key name to match check
            "error": None
        }

        response = self._make_request('get', self.target_url)

        if isinstance(response, dict) and response.get("error"):
            findings["error"] = response["error"]
            self.results["findings"]["information_disclosure"] = findings
            return findings
        if response is None:
             findings["error"] = "Failed to fetch target URL"
             self.results["findings"]["information_disclosure"] = findings
             return findings

        headers = response.headers
        content = response.text

        # 1. Server Headers
        server = headers.get('Server')
        powered_by = headers.get('X-Powered-By')
        aspnet_version = headers.get('X-AspNet-Version')

        if server:
             findings["server_info"]["server"] = server
             if re.search(r'\d+(\.\d+)+', server): self._add_vulnerability("Server Version Disclosure", "Low", f"Server header reveals version: {server}", "CWE-200", "Configure server to hide version.")
        if powered_by:
             findings["server_info"]["powered_by"] = powered_by
             self._add_vulnerability("Technology Disclosure (X-Powered-By)", "Low", f"X-Powered-By header reveals: {powered_by}", "CWE-200", "Disable X-Powered-By header.")
        if aspnet_version:
             findings["server_info"]["aspnet_version"] = aspnet_version
             self._add_vulnerability("Tech Disclosure (X-AspNet-Version)", "Low", f"X-AspNet-Version header reveals: {aspnet_version}", "CWE-200", "Remove X-AspNet-Version header.")

        # 2. Technology Stack Fingerprinting (Basic)
        tech_signatures = { "WordPress": ["wp-content", "wp-includes"], "PHP": [".php"], "ASP.NET": [".aspx"], # ... add more
                          }
        content_lower = content.lower()
        for tech, sigs in tech_signatures.items():
            if any(sig in content_lower or sig in self.target_url for sig in sigs):
                findings["tech_stack"].add(tech)

        try:
             soup = BeautifulSoup(content, 'html.parser')
             # Generator Tag
             generator_tag = soup.find("meta", attrs={"name": re.compile(r'^generator$', re.I)})
             if generator_tag and generator_tag.get('content'):
                  gen_content = generator_tag['content']
                  findings["server_info"]["generator"] = gen_content
                  findings["tech_stack"].add(gen_content.split(' ')[0])
                  if re.search(r'\d+(\.\d+)+', gen_content): self._add_vulnerability("CMS Version (Generator Tag)", "Low", f"Generator tag reveals version: {gen_content}", "CWE-200", "Remove generator tag.")

             # Comments
             html_comments = soup.find_all(string=lambda text: isinstance(text, Comment))
             for comment in html_comments:
                 comment_text = comment.strip()
                 if any(kw in comment_text.lower() for kw in ['password', 'secret', 'key', 'debug', 'todo', 'internal']):
                      findings["comments"].append(comment_text[:200])
                      self._add_vulnerability("Sensitive Info in HTML Comment", "Medium", f"Potential sensitive data in comment: ...{comment_text[max(0, len(comment_text)//2 - 20):len(comment_text)//2 + 20]}...", "CWE-200", "Remove sensitive info from comments.")
        except Exception as e:
             logger.warning(f"Error parsing HTML for info disclosure: {e}")

        # 3. Check Common Sensitive Files/Paths
        sensitive_paths = [ "/robots.txt", "/sitemap.xml", "/.git/config", "/.env", "/wp-config.php", "/phpinfo.php", "/admin/", "/logs/error.log", "/backup.zip" # Add more
                           ]
        logger.info(f"Checking {len(sensitive_paths)} common sensitive paths...")
        checked_files = 0
        for path in sensitive_paths:
            file_url = urljoin(self.target_url, path)
            if not self.is_path_allowed(file_url):
                 logger.debug(f"Skipping disallowed path: {file_url}")
                 continue

            # Use HEAD first
            head_response = self._make_request('head', file_url, allow_redirects=False)
            checked_files += 1
            status_code = None

            if isinstance(head_response, requests.Response): # Check if it's a valid response object
                status_code = head_response.status_code
            elif isinstance(head_response, dict) and 'status_code' in head_response: # Check our error dict format
                status_code = head_response['status_code'] # Could be None if error before status

            # Check if accessible (2xx generally)
            if status_code and 200 <= status_code < 300:
                 path_info = {"path": path, "status": status_code, "url": file_url}
                 findings["sensitive_files"].append(path_info) # Use 'sensitive_files' key
                 logger.warning(f"Accessible sensitive path found: {path} (Status: {status_code})")

                 severity, cwe, remediation = "Low", "CWE-200", f"Restrict access to '{path}'." # Defaults
                 if path in ["/.git/config", "/.env", "/wp-config.php"]: severity, cwe, remediation = "Critical", "CWE-538", f"CRITICAL: Source code/config file '{path}' exposed. Block access."
                 elif path == "/phpinfo.php": severity, cwe, remediation = "High", "CWE-497", f"Sensitive debug info at '{path}'. Remove or restrict access."
                 elif path.endswith((".log", ".zip", ".tar.gz")): severity, cwe, remediation = "High", "CWE-530", f"Potential log/backup at '{path}'. Restrict access."
                 elif "/admin" in path: severity, cwe, remediation = "Medium", "CWE-284", f"Admin interface at '{path}'. Ensure strong auth."

                 self._add_vulnerability(f"Exposed Path: {path}", severity, f"Path '{path}' is accessible (Status: {status_code}).", cwe, remediation)

        logger.info(f"Checked {checked_files} sensitive paths.")
        findings["tech_stack"] = list(findings["tech_stack"]) # Convert set to list for JSON
        self.results["findings"]["information_disclosure"] = findings
        return findings

    def check_waf_presence(self):
        """Detect the presence of a Web Application Firewall (WAF)."""
        logger.info("Attempting to detect WAF...")
        # Using 'waf_presence' key to match analysis
        waf_findings = { "detected": False, "waf_name": "Unknown", "detection_method": None, "confidence": "Low", "error": None }

        # --- Technique 1: Header Analysis ---
        logger.debug("WAF Check: Analyzing response headers...")
        response_normal = self._make_request('get', self.target_url)

        if isinstance(response_normal, dict) and response_normal.get("error"):
             waf_findings["error"] = f"Initial request failed: {response_normal.get('error')}"
             self.results["findings"]["waf_presence"] = waf_findings # Use correct key
             return waf_findings
        if response_normal is None: # Should be handled by _make_request
             waf_findings["error"] = "Initial request failed (No response object)"
             self.results["findings"]["waf_presence"] = waf_findings
             return waf_findings

        # ... (rest of WAF header checking logic - seems okay) ...

        # --- Technique 2: Malicious Request Probing ---
        logger.debug("WAF Check: Sending probe requests...")
        # ... (rest of WAF probe logic - seems okay) ...

        self.results["findings"]["waf_presence"] = waf_findings # Store results under correct key
        if not waf_findings["detected"] and not waf_findings["error"]:
             logger.info("No clear WAF detected.")
        return waf_findings

    # --- Vulnerability Testing Modules ---

    @staticmethod
    def is_sql_vulnerable(response, elapsed_time):
        """Check response for signs of SQL injection (errors, timing)."""
        # ... (Existing logic seems reasonable) ...
        if not isinstance(response, requests.Response): # Guard against error dicts
            return False
        response_text_lower = response.text.lower()
        error_signatures = [ "sql syntax", "syntax error", "unclosed quotation", "mysql_fetch", "ora-0", "odbc driver", # Simplified list
                           ]
        if any(sig in response_text_lower for sig in error_signatures):
            logger.info(f"SQLi detected based on error signature: {[sig for sig in error_signatures if sig in response_text_lower][0]}")
            return True
        # Basic time-based check (needs refinement for reliability)
        timing_threshold = 5.0
        if elapsed_time > timing_threshold:
            logger.info(f"Potential Time-Based SQLi detected (Response time: {elapsed_time:.2f}s > {timing_threshold}s)")
            return True
        return False

    def sql_injection_test(self, target_url, use_proxies=False):
        """Test a specific URL for SQL injection."""
        logger.info(f"Starting SQL injection test on: {target_url}")
        findings_list = [] # Store detailed findings locally for this test run
        payloads = self.load_payloads(PAYLOAD_FILES["sql"])

        if not payloads:
            logger.warning("No SQL injection payloads loaded.")
            return [{"status": "skipped", "details": "Payload file missing or empty."}]

        parsed_url = urlparse(target_url)
        original_params = parse_qs(parsed_url.query)

        if not original_params:
            logger.info("No query parameters found, skipping parameter-based SQLi test.")
            return [{"status": "skipped", "details": "No query parameters for testing."}]

        tested_params_count = 0
        for param_name, param_values in original_params.items():
            tested_params_count += 1
            for payload in payloads:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                test_query = "&".join([f"{k}={quote(v[0])}" for k, v in test_params.items()])
                test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, test_query, parsed_url.fragment))

                start_time = time.time()
                response = self._make_request('get', test_url, use_proxies=use_proxies)
                elapsed_time = time.time() - start_time

                # Check if response is valid before passing to is_sql_vulnerable
                if isinstance(response, dict) and response.get("error"): continue

                if self.is_sql_vulnerable(response, elapsed_time):
                    vuln_details_payload = {
                        "url": test_url, "parameter": param_name, "payload": payload,
                        "response_time_s": round(elapsed_time, 2)
                    }
                    # Add to main vulnerability list (without details for now, as per _add_vulnerability)
                    self._add_vulnerability(
                        name="SQL Injection", severity="Critical",
                        description=f"Potential SQL Injection on parameter '{param_name}'.",
                        cwe="CWE-89",
                        remediation="Use parameterized queries/prepared statements. Sanitize/validate inputs."
                        # Intentionally not passing details here to match _add_vulnerability behavior
                    )
                    # Store detailed dataset_collector locally for return value of this function
                    findings_list.append({
                        "status": "vulnerable",
                        "details": f"Detected on param '{param_name}' with payload '{payload}'",
                        **vuln_details_payload # Include details in the function's return
                    })
                    # Optional: break # Stop after first dataset_collector for this param?

        if not findings_list:
             logger.info(f"No SQL injection vulnerabilities detected for {tested_params_count} parameters.")
             return [{"status": "not_vulnerable", "details": f"Tested {tested_params_count} parameters."}]
        else:
             logger.warning(f"Found {len(findings_list)} potential SQL injection points for {target_url}")
             # Store summary in findings (or just rely on vulnerabilities list?)
             self.results["findings"]["sql_injection"] = {"count": len(findings_list), "vulnerable_params": list(set(f['details']['parameter'] for f in findings_list))}
             return findings_list # Return detailed list from function

    # --- XSS Testing ---
    def test_reflective_xss(self, target_url, use_proxies=False):
        """Test for reflective XSS by injecting payloads into URL parameters."""
        logger.info(f"Starting Reflective XSS test on: {target_url}")
        findings_list = [] # Local list for function return
        payloads = self.load_payloads(PAYLOAD_FILES["xss"])

        if not payloads:
            logger.warning("No XSS payloads loaded, skipping reflective XSS test.")
            return [{"status": "skipped", "details": "Payload file missing or empty."}]

        parsed_url = urlparse(target_url)
        original_params = parse_qs(parsed_url.query)

        if not original_params:
            logger.info("No query parameters found, skipping reflective XSS test.")
            return [{"status": "skipped", "details": "No query parameters for testing."}]

        tested_params_count = 0
        for param_name in original_params:
             tested_params_count += 1
             for payload in payloads:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                test_query = "&".join([f"{k}={quote(v[0], safe='')}" for k, v in test_params.items()])
                test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, test_query, parsed_url.fragment))

                response = self._make_request('get', test_url, use_proxies=use_proxies)

                if isinstance(response, dict) and response.get("error"): continue
                if not isinstance(response, requests.Response): continue # Ensure it's a real response

                try:
                     response_text = response.text
                     # Simple reflection check (can be improved with parsing)
                     if payload in response_text:
                          logger.warning(f"Potential Reflective XSS detected: Payload '{payload}' reflected for param '{param_name}'.")
                          vuln_details_payload = {"url": test_url, "parameter": param_name, "payload": payload}
                          self._add_vulnerability(
                                name="Reflective XSS", severity="High",
                                description=f"Payload reflected in response for parameter '{param_name}'.",
                                cwe="CWE-79",
                                remediation="Implement context-aware output encoding/escaping for reflected user input."
                                # No details passed here
                          )
                          findings_list.append({
                               "status": "vulnerable",
                               "details": f"Reflected in param '{param_name}' with payload '{payload}'",
                               **vuln_details_payload
                          })
                          # break # Optional: break after first hit per param?
                except Exception as e:
                     logger.error(f"Error checking XSS reflection for {test_url}: {e}", exc_info=True)

        if not findings_list:
            logger.info(f"No simple reflective XSS vulnerabilities detected for {tested_params_count} parameters.")
            return [{"status": "not_vulnerable", "details": f"Tested {tested_params_count} parameters."}]
        else:
             self.results["findings"]["reflective_xss"] = {"count": len(findings_list), "vulnerable_params": list(set(f['details']['parameter'] for f in findings_list))}
             return findings_list

    def get_webdriver(self, use_proxy=True):
        """Helper to initialize and return a headless Chrome WebDriver."""
        options = webdriver.ChromeOptions()
        options.add_argument('--headless=new') # Use new headless mode
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument(f'user-agent={self.user_agent}')

        # Configure proxy if requested and available
        proxy_server = None
        if use_proxy:
            proxy_config = self.get_proxies()
            if proxy_config:
                # Assumes http proxy applies to https too for Chrome. Needs validation if using specific HTTPS proxies.
                proxy_url = proxy_config.get("http") or proxy_config.get("https")
                if proxy_url:
                    try:
                        proxy_server = urlparse(proxy_url).netloc
                        if proxy_server:
                            options.add_argument(f'--proxy-server={proxy_server}')
                            logger.info(f"Configuring WebDriver proxy: {proxy_server}")
                        else:
                             logger.warning(f"Could not parse proxy URL: {proxy_url}")
                    except Exception as e:
                         logger.warning(f"Error parsing proxy URL '{proxy_url}': {e}")

        driver = None
        try:
            logger.debug("Initializing WebDriver...")
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            # Attempt to bypass detection
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            logger.debug("WebDriver initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize WebDriver: {e}", exc_info=True)
            raise RuntimeError(f"WebDriver initialization failed: {e}")
        return driver

    def test_stored_xss(self, target_url, use_proxies=False):
        """Test for stored XSS by submitting payloads via forms."""
        logger.info(f"Starting Stored XSS test on forms at: {target_url}")
        findings = []
        test_payload = "<script>console.warn('EthicalScanner_StoredXSS_Test')</script>" # Unique payload
        # Payloads loaded within the function if needed, but using fixed payload for detection is simpler
        # payloads = self.load_payloads(PAYLOAD_FILES["xss"])
        # if not payloads: return [{"status": "skipped", "details": "Payload file missing"}]

        driver = None
        submitted_form = False
        try:
            driver = self.get_webdriver(use_proxy=use_proxies)
            driver.set_page_load_timeout(self.timeout * 3) # Increased page load timeout

            logger.debug(f"Navigating to {target_url} for Stored XSS test.")
            driver.get(target_url)

            # <<< FIX: Increased wait time and added specific exception handling >>>
            try:
                WebDriverWait(driver, 30).until( # Increased wait time
                    EC.presence_of_all_elements_located((By.TAG_NAME, 'form'))
                )
                forms = driver.find_elements(By.TAG_NAME, 'form')
                logger.info(f"Found {len(forms)} forms on {target_url}")
            except TimeoutException:
                logger.warning(f"Timeout waiting for forms on {target_url}. Skipping Stored XSS test for this page.")
                return [{"status": "skipped", "details": "Timeout waiting for forms."}]
            except Exception as e:
                logger.error(f"Error finding forms on {target_url}: {e}", exc_info=True)
                return [{"status": "error", "details": f"Error finding forms: {e}"}]

            if not forms:
                logger.info(f"No forms found on {target_url} for Stored XSS test.")
                return [{"status": "skipped", "details": "No forms found."}]

            # Store original URL before submitting forms
            original_url_before_submit = driver.current_url

            for form_index, form_element in enumerate(forms):
                try:
                    # Re-find elements to avoid staleness? Can be complex. Try interacting directly first.
                    logger.info(f"Testing form {form_index + 1} on {target_url}")
                    inputs = form_element.find_elements(By.XPATH, ".//input[@type='text' or @type='search' or @type='email' or @type='url' or not(@type)] | .//textarea")

                    if not inputs:
                        logger.debug(f"Form {form_index + 1} has no text/textarea inputs to inject payload.")
                        continue

                    logger.info(f"Injecting payload into {len(inputs)} fields in form {form_index + 1}: {test_payload}")
                    for input_field in inputs:
                        try:
                            # Check if interactable
                            if input_field.is_displayed() and input_field.is_enabled():
                                input_field.clear()
                                input_field.send_keys(test_payload)
                            else:
                                logger.debug(f"Skipping non-interactable input field in form {form_index + 1}")
                        except Exception as input_e:
                            logger.warning(f"Could not interact with input field in form {form_index + 1}: {input_e}")
                            # Continue to next field even if one fails

                    # Try submitting the form
                    submit_buttons = form_element.find_elements(By.XPATH, ".//button[@type='submit'] | .//input[@type='submit']")
                    if submit_buttons and submit_buttons[0].is_displayed() and submit_buttons[0].is_enabled():
                        submit_buttons[0].click()
                        logger.debug(f"Clicked submit button for form {form_index + 1}")
                    else:
                        # Fallback to form.submit() if no button found/usable
                        form_element.submit()
                        logger.debug(f"Used form.submit() for form {form_index + 1}")

                    submitted_form = True
                    logger.info(f"Submitted form {form_index + 1} with payload.")

                    # <<< FIX: Increased wait and added exception handling >>>
                    try:
                        # Wait briefly for potential page transition or AJAX update
                        time.sleep(2) # Simple pause after submit
                        # Optionally wait for URL change, but handle timeout gracefully
                        # WebDriverWait(driver, 10).until(EC.url_changes(original_url_before_submit))
                    except TimeoutException:
                         logger.warning(f"URL did not change after submitting form {form_index + 1}. AJAX?")
                    except Exception as e:
                         logger.error(f"Error during post-submit wait for form {form_index + 1}: {e}")
                    # Revisit the *original* page (or a relevant target page) to check for payload execution
                    logger.debug(f"Revisiting {original_url_before_submit} to check for stored payload execution.")
                    driver.get(original_url_before_submit)
                    try:
                         # Wait for body to ensure page is mostly loaded
                         WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
                    except TimeoutException:
                         logger.error(f"Timeout waiting for page body after revisiting {original_url_before_submit}. Check may be incomplete.")
                         continue # Skip log check if page didn't load

                    # Check browser console logs for our specific payload warning
                    try:
                        browser_logs = driver.get_log('browser')
                        payload_executed = False
                        for entry in browser_logs:
                            if 'EthicalScanner_StoredXSS_Test' in entry.get('message', ''):
                                payload_executed = True
                                break

                        if payload_executed:
                            logger.warning(f"Potential Stored XSS DETECTED via console log after form {form_index + 1} submission on {target_url}!")
                            vuln_details_payload = {"url": target_url, "form_index": form_index + 1, "payload": test_payload}
                            # Check if dataset_collector already exists for this form index on this URL
                            if not any(f['details']['url'] == target_url and f['details'].get('form_index') == form_index + 1 for f in findings):
                                self._add_vulnerability(
                                    name="Stored XSS", severity="High",
                                    description=f"Payload submitted via form index {form_index + 1} on {target_url} executed upon revisiting.",
                                    cwe="CWE-79",
                                    remediation="Implement input sanitization server-side and context-aware output encoding/escaping."
                                )
                                findings.append({
                                    "status": "vulnerable",
                                    "details": f"Detected via form {form_index + 1} on {target_url}",
                                    **vuln_details_payload
                                })
                                # Optional: break outer loop if one stored XSS is found?
                                # break # Breaks out of the forms loop

                    except Exception as log_e:
                        logger.warning(f"Could not retrieve browser logs: {log_e}")

                    # Navigate back or reset state if necessary before next form?
                    # Potentially needed if submissions redirect significantly.
                    # driver.get(target_url) # Re-navigate to original page before next form test


                except Exception as form_e:
                    logger.error(f"Error testing form {form_index + 1} on {target_url}: {form_e}", exc_info=True)
                    # Try to recover by going back to the target URL
                    try:
                        driver.get(target_url)
                    except Exception:
                        logger.error("Failed to navigate back to target URL after form error.")
                        # Maybe break the loop for this page if recovery fails
                        break

        except RuntimeError as e: # Catch WebDriver init failure
            logger.error(f"Stored XSS test failed: {e}")
            return [{"status": "error", "details": str(e)}]
        except Exception as e:
            logger.error(f"Stored XSS test failed unexpectedly: {e}", exc_info=True)
            return [{"status": "error", "details": f"Unexpected error: {e}"}]
        finally:
            if driver:
                try:
                    driver.quit()
                    logger.debug("WebDriver closed successfully.")
                except Exception as e:
                    logger.error(f"Failed to close WebDriver: {e}")

        if not submitted_form and forms: # Check if we actually submitted anything
            logger.info("No forms were successfully submitted with payloads.")
            return [{"status": "skipped", "details": "Could not submit any forms."}]

        if findings:
             self.results["findings"]["stored_xss"] = {"count": len(findings), "details": findings}
        return findings

    def _check_dom_xss(self):
        """Test for DOM-based XSS using Playwright."""
        # Store results directly in self.results
        self.results["findings"]["dom_xss"] = {"status": "pending"}
        try:
            from playwright.sync_api import sync_playwright, Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError
        except ImportError:
            logger.warning("Playwright not installed, skipping DOM XSS check.")
            self.results["findings"]["dom_xss"] = {"status": "skipped", "message": "Playwright not installed"}
            return

        payloads_to_test = self.load_payloads(PAYLOAD_FILES.get("xss", "xss_payloads.txt"))
        if not payloads_to_test:
             logger.warning("No XSS payloads for DOM XSS check.")
             self.results["findings"]["dom_xss"] = {"status": "skipped", "message": "No XSS payloads found"}
             return

        # Use a simpler, known-to-trigger payload for the basic check if possible
        test_payloads = [
            "#<script>alert('DOMXSS_TEST')</script>",
            "?param=<script>alert('DOMXSS_TEST')</script>",
            "#<img src=x onerror=alert('DOMXSS_TEST')>",
            "?q=<svg onload=alert('DOMXSS_TEST')>",
            "#<body onload=alert('DOMXSS_TEST')>",
            "?redirect_url=javascript:alert('DOMXSS_TEST')",
            "#<iframe src=javascript:alert('DOMXSS_TEST')>",
            "?search=<object data=javascript:alert('DOMXSS_TEST')>",
            "#<input onfocus=alert('DOMXSS_TEST') autofocus>",
            "?query=data:text/html,<script>alert('DOMXSS_TEST')</script>",
            "#<details open ontoggle=alert('DOMXSS_TEST')>",
            "?callback=alert&data=DOMXSS_TEST",
            "#<a href='javascript:alert(`DOMXSS_TEST`)'>Click</a>",
            "#</script><script>alert('DOMXSS_TEST')</script>",
            "?param=%3Cscript%3Ealert('DOMXSS_TEST')%3C/script%3E",
            # Add more sophisticated payloads if needed
        ]
        # Limit number of payloads tested
        payloads_to_test = test_payloads + payloads_to_test[:5]

        logger.info(f"Starting DOM XSS check on {self.target_url}")
        detected_payload = None
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=self.user_agent,
                    ignore_https_errors=True # Similar to requests verify=False
                )
                page = context.new_page()

                alert_triggered = False
                executed_payload = None

                # Listen for dialogs (like alert)
                page.on("dialog", lambda dialog: setattr(page, "_last_dialog_message", dialog.message) or dialog.dismiss())

                for payload in payloads_to_test:
                    test_url = urljoin(self.target_url, payload) # Test by modifying URL fragment/query
                    logger.debug(f"Testing DOM XSS with URL: {test_url}")
                    setattr(page, "_last_dialog_message", None) # Reset dialog message tracker

                    try:
                        page.goto(test_url, timeout=self.timeout * 2000) # Playwright timeout in ms
                        # Wait a bit for potential script execution
                        page.wait_for_timeout(2000) # Wait 2 seconds

                        # Check if our specific alert message was triggered
                        if getattr(page, "_last_dialog_message", None) == 'DOMXSS_TEST':
                             alert_triggered = True
                             executed_payload = payload
                             logger.warning(f"Potential DOM XSS detected via alert() with payload: {payload}")
                             break # Stop on first detection

                    except PlaywrightTimeoutError:
                        logger.warning(f"Timeout loading page {test_url} during DOM XSS check.")
                    except PlaywrightError as e:
                         logger.warning(f"Playwright error during DOM XSS check for {test_url}: {e}")
                    except Exception as e:
                         logger.error(f"Unexpected error during DOM XSS page load for {test_url}: {e}", exc_info=True)

                browser.close()

                if alert_triggered:
                     self.results["findings"]["dom_xss"] = {"status": "vulnerable", "payload": executed_payload}
                     self._add_vulnerability(
                         name="DOM-based XSS", severity="High",
                         description=f"Potential DOM XSS triggered with payload fragment/query: {executed_payload}",
                         cwe="CWE-79",
                         remediation="Review client-side JavaScript for unsafe handling of URL components (location, referrer) or other user-controlled data feeding into sensitive sinks (innerHTML, eval, etc.). Sanitize data appropriately."
                     )
                else:
                     self.results["findings"]["dom_xss"] = {"status": "not_vulnerable", "message": "No simple DOM XSS triggers detected."}

            except PlaywrightError as e:
                logger.error(f"Playwright setup/execution error during DOM XSS check: {e}")
                self.results["findings"]["dom_xss"] = {"status": "error", "message": f"Playwright error: {e}"}
            except Exception as e:
                logger.error(f"Unexpected error during DOM XSS check: {e}", exc_info=True)
                self.results["findings"]["dom_xss"] = {"status": "error", "message": f"Unexpected error: {e}"}

    # --- CSRF Testing ---
    def csrf_test(self, target_url=None):
        """Test forms for missing CSRF tokens."""
        url_to_test = target_url or self.target_url
        logger.info(f"Starting CSRF check on forms at: {url_to_test}")
        # Use results key 'csrf' to match template expectation
        findings = {"forms_checked": 0, "post_forms_checked": 0, "forms_missing_token": 0, "details": [], "error": None}
        self.results["findings"]["csrf"] = findings # Initialize in results

        response = self._make_request('get', url_to_test)
        if isinstance(response, dict) and response.get("error"):
             findings["error"] = response.get("error")
             return [{"status": "error", "details": findings["error"]}]
        if not isinstance(response, requests.Response):
             findings["error"] = "Failed to fetch page (Invalid response type)"
             return [{"status": "error", "details": findings["error"]}]

        soup = None
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception as e:
             logger.error(f"Error parsing HTML for CSRF check: {e}", exc_info=True)
             findings["error"] = f"HTML parsing error: {e}"
             return [{"status": "error", "details": findings["error"]}]

        forms = soup.find_all('form')
        findings["forms_checked"] = len(forms)
        logger.info(f"Found {len(forms)} forms to check for CSRF tokens on {url_to_test}")

        if not forms:
             return [{"status": "skipped", "details": "No forms found on page."}]

        csrf_token_pattern = re.compile(r'(csrf|token|auth|verify|state|nonce|anticsrf|_token)', re.I) # Added _token
        missing_token_details = []
        for index, form in enumerate(forms):
            action = form.get('action', f'Form {index+1} on {url_to_test}')
            full_action_url = urljoin(url_to_test, action if action else url_to_test) # Handle empty action
            method = form.get('method', 'GET').upper()
            form_detail = {"action": full_action_url, "method": method}

            if method != 'POST':
                logger.debug(f"Skipping form '{action}' with method {method}.")
                form_detail["token_present"] = "N/A (Method not POST)"
                findings["details"].append(form_detail)
                continue

            findings["post_forms_checked"] += 1
            has_token = False
            token_name = None
            for input_tag in form.find_all('input', {'type': 'hidden'}):
                input_name = input_tag.get('name')
                if input_name and csrf_token_pattern.search(input_name):
                    has_token = True
                    token_name = input_name
                    logger.info(f"Form '{action}' appears to have a CSRF token ('{input_name}').")
                    form_detail["token_present"] = True
                    form_detail["token_name"] = input_name
                    break

            if not has_token:
                findings["forms_missing_token"] += 1
                logger.warning(f"Form '{action}' (Method: POST) appears to be MISSING a CSRF token.")
                form_detail["token_present"] = False
                missing_token_details.append(form_detail) # Add to temporary list
                self._add_vulnerability(
                    name="Missing CSRF Token", severity="Medium",
                    description=f"Form submitting to '{action}' via POST lacks a recognizable CSRF token.",
                    cwe="CWE-352",
                    remediation="Implement anti-CSRF tokens for all state-changing requests."
                )
            findings["details"].append(form_detail) # Add details for all forms

        # Return structure depends on whether missing tokens were found
        if findings["forms_missing_token"] > 0:
             return missing_token_details # Return list of forms missing tokens
        elif findings["post_forms_checked"] > 0:
             return [{"status": "not_vulnerable", "details": f"Checked {findings['post_forms_checked']} POST forms, all appear to have tokens."}]
        else:
             return [{"status": "skipped", "details": "No POST forms found to check."}]
    # --- Generic Vulnerability Testing Helper ---
    def _test_generic_vulnerability(self, test_name, cwe, severity, url, param_name, payloads, success_indicators, remediation, check_location_header=False):
        """Generic helper for testing vulnerabilities via URL parameters."""
        logger.info(f"Starting {test_name} test on: {url} (param: {param_name})")
        findings = [] # Local list for function return
        parsed_url = urlparse(url)
        original_params = parse_qs(parsed_url.query)

        if not payloads:
             logger.warning(f"No payloads for {test_name}, skipping.")
             return []
        for payload in payloads:
            test_params = original_params.copy()
            test_params[param_name] = [payload]
            test_query = "&".join([f"{k}={quote(v[0], safe='')}" for k, v in test_params.items()])
            test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, test_query, parsed_url.fragment))

            allow_redirects = not check_location_header
            response = self._make_request('get', test_url, allow_redirects=allow_redirects)

            if isinstance(response, dict) and response.get("error"): continue
            if not isinstance(response, requests.Response): continue

            vulnerable = False
            details_msg = ""
            if check_location_header:
                 location = response.headers.get('Location', '')
                 if response.status_code in [301, 302, 307, 308] and any(ind in location for ind in success_indicators):
                      vulnerable = True
                      matched_indicator = next((ind for ind in success_indicators if ind in location), None)
                      details_msg = f"Redirect to '{location}' matching '{matched_indicator}'."
            else:
                 try:
                     # Use lower case for robust matching
                     response_text_lower = response.text.lower()
                     for indicator in success_indicators:
                          if indicator.lower() in response_text_lower:
                               vulnerable = True
                               details_msg = f"Response body contains indicator '{indicator}'."
                               break
                 except Exception as e:
                      logger.error(f"Error checking response body for {test_name} at {test_url}: {e}")

            if vulnerable:
                logger.warning(f"Potential {test_name} detected at {test_url} with payload '{payload}'. {details_msg}")
                vuln_details_payload = {"url": test_url, "parameter": param_name, "payload": payload}
                # Check if exact dataset_collector already exists in local list for this run
                if not any(f['details']['parameter']==param_name and f['details']['payload']==payload for f in findings):
                     self._add_vulnerability(
                         name=test_name, severity=severity,
                         description=f"Potential {test_name} on parameter '{param_name}'. {details_msg}",
                         cwe=cwe, remediation=remediation
                     )
                     findings.append({
                         "status": "vulnerable",
                         "details": f"Detected on param '{param_name}'. {details_msg}",
                         **vuln_details_payload
                     })
                # break # Optional: Stop after first hit for this param?

        if not findings:
            logger.info(f"No {test_name} vulnerabilities detected for parameter '{param_name}'.")
        else:
             # Store summary in main results
             key_name = test_name.lower().replace(" ", "_")
             self.results["findings"][key_name] = {"count": len(findings), "vulnerable_params": list(set(f['details']['parameter'] for f in findings))}

        return findings
    # --- Specific Generic Vulnerability Checks ---
    def check_directory_traversal(self, url, param_name="file"):
        payloads = ["../etc/passwd", "..\\windows\\win.ini", "/etc/passwd", "../../../../etc/passwd", "..%2F..%2Fetc%2Fpasswd"]
        indicators = ["root:x:0:0", "[boot loader]", "daemon:", "bin/bash"]
        return self._test_generic_vulnerability("Directory Traversal", "CWE-22", "High", url, param_name, payloads, indicators, "Sanitize file paths, use allow-lists, confine access.")

    def check_open_redirect(self, url, param_name="redirect"):
        payloads = ["//example.com/%2f..", "http://evil-attacker.com", "https://google.com", r"/\evil-attacker.com"]
        indicators = ["example.com", "google.com", "evil-attacker.com"]
        return self._test_generic_vulnerability("Open Redirect", "CWE-601", "Medium", url, param_name, payloads, indicators, "Validate redirect URLs against allow-list or use relative paths.", check_location_header=True)

    def check_ssrf(self, url, param_name="url"):
        payloads = [ "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/", "http://127.0.0.1:80/server-status", "file:///etc/passwd", "http://localhost:22" ]
        indicators = ["ami-id", "instance-id", "computeMetadata", "<title>Apache Status</title>", "root:x:0:0", "ssh-"]
        # Note: SSRF needs careful result interpretation and potentially out-of-band checks
        return self._test_generic_vulnerability("SSRF", "CWE-918", "Critical", url, param_name, payloads, indicators, "Use strict allow-lists for outgoing requests. Validate/sanitize URLs. Disable unused protocols.")

    def check_command_injection(self, url, param_name="cmd"):
        payloads = [ ";id", "|id", "&&id", "& dir", "| dir", "`id`", "$(id)", "; ping -c 1 127.0.0.1" ]
        indicators = ["uid=", "gid=", "<dir>", "directory of", "reply from 127.0.0.1"]
        return self._test_generic_vulnerability("Command Injection", "CWE-78", "Critical", url, param_name, payloads, indicators, "Never pass unsanitized input to OS commands. Use safe APIs. Strict validation/sanitization.", check_location_header=False)

    # --- Brute Force Testing ---
    def brute_force_login(self, login_url, username, password_list_path, max_attempts=100, delay=1.0):
        """Main method to perform brute-force login test."""
        effective_username = username if username else "admin" # Default username if none provided
        logger.info(f"🔐 Starting brute-force attack on {login_url} with username='{effective_username}'")
        result = {"status": "pending", "message": None, "error": None, "parameters": {
                    "login_url": login_url, "login_username": username, "max_attempts": max_attempts, "delay": delay },
                  "tested_username": effective_username, "attempts_made": 0, "found_password": None}

        # Ensure the key exists before running
        self.results["findings"]["brute_force"] = result

        form_fields = self._analyze_login_form(login_url, effective_username)
        if isinstance(form_fields, dict) and "error" in form_fields:
            result.update(form_fields) # Merge error info
            return result # Return error status

        passwords = self._load_password_list(password_list_path)
        if isinstance(passwords, dict) and "error" in passwords: # Check if loading failed
            result.update(passwords)
            return result

        brute_result = self._attempt_brute_force(login_url, effective_username, passwords, form_fields, max_attempts, delay)
        self.results["findings"]["brute_force"] = brute_result # Store final result
        return brute_result
    def _analyze_login_form(self, login_url, username):
        """Fetch login page and attempt to identify username/password fields."""
        try:
            logger.debug(f"Analyzing login form at {login_url}")
            response = self._make_request('get', login_url)
            if isinstance(response, dict) and response.get("error"):
                return {"status": "error", "error": f"Failed to fetch login page: {response['error']}"}
            if not isinstance(response, requests.Response) or response.status_code != 200:
                 return {"status": "error", "error": f"Failed to fetch login page: Status {response.status_code if isinstance(response, requests.Response) else 'N/A'}"}

            soup = BeautifulSoup(response.text, 'html.parser')
            # Look for forms containing a password field
            for form in soup.find_all('form'):
                password_input = form.find('input', {'type': 'password'})
                if password_input:
                    password_field = password_input.get('name')
                    if not password_field: continue # Skip if password field has no name

                    username_field = None
                    # Try common names/types for username field within the same form
                    user_inputs = form.find_all('input')
                    for inp in user_inputs:
                        inp_type = inp.get('type', '').lower()
                        inp_name = inp.get('name', '').lower()
                        if inp_type in ['text', 'email', 'tel'] or any(n in inp_name for n in ['user', 'log', 'email', 'id', 'name']):
                             if inp_name != password_field: # Ensure it's not the password field itself
                                 username_field = inp_name
                                 break # Found a likely username field

                    # Find submit button (less critical)
                    submit_field = None
                    for btn in form.find_all(['button', 'input']):
                        if btn.get('type', '').lower() == 'submit':
                             submit_field = btn.get('name') # May not have a name
                             break

                    logger.info(f"Detected form fields: user='{username_field}', pass='{password_field}', submit='{submit_field}'")
                    return {"username_field": username_field, "password_field": password_field, "submit_field": submit_field}

            logger.warning(f"Could not automatically detect login form fields on {login_url}. Using defaults.")
            # Fallback defaults if no suitable form found
            return {"username_field": "username", "password_field": "password", "submit_field": "login"} # Common defaults

        except Exception as e:
            logger.error(f"Error analyzing login form at {login_url}: {e}", exc_info=True)
            return {"status": "error", "error": f"Error analyzing login form: {e}"}

    def _load_password_list(self, password_list_path):
        """Load passwords from the specified file path."""
        full_path = password_list_path # Assume path might be absolute or relative to payloads dir
        if not os.path.isabs(full_path):
            full_path = os.path.join(self.payloads_dir, password_list_path)

        try:
            logger.info(f"Loading password list from: {full_path}")
            if not os.path.exists(full_path):
                logger.error(f"Password list file not found: {full_path}")
                return {"status": "error", "error": "Password list file not found"}

            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            if not passwords:
                logger.warning(f"Password list file is empty: {full_path}")
                return {"status": "error", "error": "Password list file empty"}

            logger.info(f"Loaded {len(passwords)} passwords.")
            return passwords

        except Exception as e:
            logger.error(f"Error reading password file {full_path}: {e}", exc_info=True)
            return {"status": "error", "error": f"Error reading password file: {e}"}

    def _attempt_brute_force(self, login_url, username, passwords, form_fields, max_attempts, delay):
        """Perform the actual brute-force attempts."""
        attempts = 0
        success = False
        found_password = None
        # Prepare base result structure
        result = {
            "status": "failure",
            "parameters": {"login_url": login_url, "login_username": username, "max_attempts": max_attempts, "delay": delay, "form_fields": form_fields},
            "tested_username": username, "attempts_made": 0, "found_password": None, "message": "Brute force started."
        }
        effective_max = min(len(passwords), max_attempts)
        logger.info(f"Attempting max {effective_max} passwords for user '{username}'")

        for password in passwords[:effective_max]:
            attempts += 1
            result["attempts_made"] = attempts
            payload = {}
            # Dynamically use detected field names
            if form_fields.get("username_field"): payload[form_fields["username_field"]] = username
            if form_fields.get("password_field"): payload[form_fields["password_field"]] = password
            # Add submit field if detected and has a name? Often not needed.
            if form_fields.get("submit_field"): payload[form_fields["submit_field"]] = "Login" # Or appropriate value

            try:
                logger.debug(f"Attempt {attempts}/{effective_max}: User='{username}', Pass='******'")
                # Use a separate session? No, use the main one for now.
                response = self._make_request(
                    'post', login_url, data=payload,
                    allow_redirects=False # Important: Check status/headers before redirect
                )

                if isinstance(response, dict) and response.get("error"):
                    result["error"] = f"Request failed during attempt {attempts}: {response['error']}"
                    logger.error(result["error"])
                    break # Stop if requests fail

                if self._is_login_successful(response):
                    success = True
                    found_password = password
                    logger.warning(f"✅ Login SUCCESS for '{username}' with password: '{password}' (Attempt {attempts})")
                    result.update({
                        "status": "success",
                        "found_password": password, # Show password in internal result
                        "message": f"Credentials found for '{username}' after {attempts} attempts."
                    })
                    self._add_vulnerability(
                        name="Weak Credentials Found (Brute-Force)",
                        severity="Critical" if "admin" in username.lower() else "High",
                        description=f"Successfully guessed password for user '{username}'.",
                        cwe="CWE-307",
                        remediation="Implement account lockout, CAPTCHA, MFA, and strong password policies."
                    )
                    break # Stop after success

            except Exception as e:
                logger.error(f"Unexpected error during brute-force attempt {attempts}: {e}", exc_info=True)
                result["error"] = f"Unexpected error at attempt {attempts}: {e}"
                break # Stop on unexpected errors

            # Respect delay between attempts
            time.sleep(max(0.1, delay)) # Ensure minimum delay

        if not success and "error" not in result:
            logger.info(f"Brute-force failed for '{username}' after {attempts} attempts.")
            result["message"] = f"No credentials found for '{username}' within {attempts} attempts."
            # Optionally add an 'Info' vulnerability if attempts were made without success
            if attempts > 0:
                 self._add_vulnerability(
                     name="Brute-Force Resilience Check", severity="Info",
                     description=f"{attempts} login attempts made without success for user '{username}'. Review rate-limiting/lockout.",
                     cwe="CWE-307", remediation="Ensure robust lockout/CAPTCHA mechanisms are effective against brute-force."
                 )

        return result
    def _is_login_successful(self, response):
        """Analyze response to determine if login was successful."""
        # Check if it's our error dictionary first
        if isinstance(response, dict) and response.get("error"): return False
        if not isinstance(response, requests.Response): return False # Must be a Response object

        # Lowercase text once for checks
        try: text_lower = response.text.lower()
        except: text_lower = "" # Handle potential decoding errors
        status = response.status_code
        headers = response.headers
        # --- Indicators of Failure (More Reliable) ---
        failed_indicators = [ "login failed", "incorrect password", "invalid username", "authentication failed", "wrong credentials", "user not found", "enter a correct username and password", "<title>login", "forgot password?" # Common failure phrases/elements
                            ]
        if any(ind in text_lower for ind in failed_indicators):
            return False
        # Check for specific status codes that often indicate failure on login pages (e.g., staying on 200 OK but showing error)
        if status == 200 and urlparse(response.url).path == urlparse(self.target_url).path: # Still on login page? Check path.
             # Check if login form elements are still present? (More complex)
             pass
        # --- Indicators of Success ---
        # 1. Redirect after POST (Common pattern) + Session Cookie
        if status in [301, 302, 303, 307, 308]:
             location = headers.get("Location", "").lower()
             # Check if redirecting away from login page, or to specific success pages
             if "/login" not in location and ("/dashboard" in location or "/account" in location or "/home" in location or location == "/"):
                 # Check if a session-like cookie was set
                 if "Set-Cookie" in headers and any("sess" in c.lower() or "auth" in c.lower() for c in headers.getlist("Set-Cookie")):
                     return True

        # 2. Status 200 OK + Success indicators in body + Absence of failure indicators
        success_indicators = ["logout", "log out", "sign out", "welcome,", "dashboard", "account settings", "my profile" # Common success phrases/links
                              ]
        if status == 200 and any(ind in text_lower for ind in success_indicators):
             # Double-check no failure indicators are also present
             if not any(ind in text_lower for ind in failed_indicators):
                 return True
        # If none of the above matched, assume failure
        return False
    # --- Reporting & Utilities ---
    def _add_vulnerability(self, name, severity, description, cwe, remediation, details: Optional[Dict] = None):
        """Helper method to add vulnerabilities and update risk score."""
        if 'vulnerabilities' not in self.results: self.results['vulnerabilities'] = []
        if 'risk_score' not in self.results: self.results['risk_score'] = 0

        severity = severity.capitalize()
        if severity not in SEVERITY_LEVELS:
            logger.warning(f"Unknown severity '{severity}' for '{name}'. Defaulting to Low.")
            severity = "Low"

        vuln_entry = {
            'name': name,
            'severity': severity,
            'description': description,
            'cwe': cwe,
            'remediation': remediation,
            # <<< FIX: Include details if provided >>>
            'details': details if details else {} # Add details dict
        }

        # Avoid adding exact duplicates (simple check)
        # Consider a more robust check if details vary slightly for same core issue
        if not any(v['name'] == name and v['description'] == description for v in self.results['vulnerabilities']):
             self.results['vulnerabilities'].append(vuln_entry)
             self.results['risk_score'] += SEVERITY_SCORES.get(severity, 0)
        else:
             logger.debug(f"Duplicate vulnerability skipped: {name}")

    def calculate_risk_score(self):
        """Recalculate risk score based on vulnerabilities found."""
        self.results['risk_score'] = sum(SEVERITY_SCORES.get(v.get('severity', 'Info'), 0)
                                         for v in self.results.get('vulnerabilities', []))
        logger.info(f"Calculated risk score: {self.results['risk_score']}")
        return self.results['risk_score']

    def get_cve_report_summary(self):
        """Generate a summary of CVEs found."""
        cve_findings = self.results.get('findings', {}).get('cve_check', {})
        return {
             "count": cve_findings.get("matching_cves_count", 0),
             "cves": cve_findings.get("cves", {})
        }

    @lru_cache(maxsize=100)
    def get_parsed_page(self, url):
        """Fetch and parse HTML page using BeautifulSoup."""
        logger.debug(f"Fetching and parsing page: {url}")
        response = self._make_request('get', url)
        if isinstance(response, dict) or not isinstance(response, requests.Response) or not response.ok:
             logger.error(f"Failed to get page {url} for parsing.")
             return None
        try:
            # Use 'html.parser' for speed, or 'html5lib' for robustness if needed
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup
        except Exception as e:
             logger.error(f"Failed to parse HTML from {url}: {e}", exc_info=True)
             return None

    def save_results_db(self, db_file="scan_history.db"):
        """Save scan summary to an SQLite database."""
        db_path = os.path.join(current_dir, db_file)
        logger.info(f"Saving results summary to database: {db_path}")
        conn = None
        try:
            conn = sqlite3.connect(db_path, timeout=10)
            c = conn.cursor()
            # Ensure table exists
            c.execute('''CREATE TABLE IF NOT EXISTS scans (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             target TEXT NOT NULL,
                             scan_type TEXT,
                             timestamp TEXT NOT NULL,
                             duration REAL,
                             risk_score INTEGER,
                             vuln_count INTEGER,
                             findings_summary TEXT -- Store findings summary as JSON string
                         )''')

            # Prepare data
            timestamp = self.results.get("scan_time", datetime.now().isoformat())
            duration = self.results.get("scan_stats", {}).get("duration")
            risk_score = self.results.get("risk_score", 0)
            vuln_count = len(self.results.get("vulnerabilities", []))
            # Summarize findings carefully to avoid large blobs/serialization errors
            findings_summary_dict = {}
            for k, v in self.results.get("findings", {}).items():
                if isinstance(v, dict):
                    findings_summary_dict[k] = v.get('status', v.get('count', 'present')) # Get status or count
                elif isinstance(v, list):
                    findings_summary_dict[k] = f"{len(v)} items"
                else:
                     findings_summary_dict[k] = bool(v) # Simple boolean presence

            try:
                findings_summary = json.dumps(clean_for_json(findings_summary_dict)) # Clean before dumping
            except TypeError as e:
                 logger.error(f"Could not serialize findings summary for DB: {e}")
                 findings_summary = json.dumps({"error": "Serialization failed"})

            c.execute("""
                INSERT INTO scans (target, scan_type, timestamp, duration, risk_score, vuln_count, findings_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (self.target_url, self.scan_type, timestamp, duration, risk_score, vuln_count, findings_summary))

            conn.commit()
            logger.info("Results summary saved to database.")
        except sqlite3.Error as e:
            logger.error(f"Database error while saving results: {e}", exc_info=True)
            if conn: conn.rollback()
        except Exception as e:
             logger.error(f"Unexpected error saving results to database: {e}", exc_info=True)
             if conn: conn.rollback()
        finally:
            if conn: conn.close()

    def finalize_scan(self):
         """Perform final calculations and updates before returning results."""
         end_time = time.time()
         start_time = self.results["scan_stats"].get("start_time", end_time)
         self.results["scan_stats"]["end_time"] = end_time
         self.results["scan_stats"]["duration"] = round(end_time - start_time, 2)
         self.calculate_risk_score() # Recalculate score
         logger.info(f"Scan finalized. Duration: {self.results['scan_stats']['duration']}s, Risk Score: {self.results['risk_score']}, Vulns: {len(self.results.get('vulnerabilities', []))}")
         self.save_results_db() # Save summary to DB

    def crawl(self, base_url, max_depth=2, max_urls=50):
        """Crawl the target website to discover URLs within scope."""
        logger.info(f"Starting crawl from {base_url} up to depth {max_depth}, max URLs {max_urls}")
        all_urls = set()
        visited = set()
        # Use list as queue: [(url, depth)]
        queue: List[tuple[str, int]] = [(base_url, 0)]
        visited.add(self._normalize_url_for_visit(base_url)) # Add normalized start URL to visited

        base_domain = urlparse(base_url).netloc

        while queue and len(all_urls) < max_urls:
            try:
                current_url, depth = queue.pop(0)
            except IndexError:
                break # Should not happen with while queue check

            logger.debug(f"Crawl Check (Depth {depth}): {current_url}")
            # Normalize before full check/request
            norm_url_visited = self._normalize_url_for_visit(current_url)

            # Already processed this normalized URL?
            if norm_url_visited in visited:
                # logger.debug(f"Skipping already visited (normalized): {norm_url_visited}")
                continue
            # Check depth before adding to visited and making request
            if depth > max_depth:
                logger.debug(f"Skipping max depth reached: {current_url}")
                continue
            # Add to visited *before* making request to prevent re-queueing duplicates quickly
            visited.add(norm_url_visited)

            # Check scope (domain)
            parsed_current = urlparse(current_url)
            if parsed_current.netloc != base_domain:
                logger.debug(f"Skipping out-of-scope URL: {current_url}")
                continue
            # Check robots.txt allowance
            if not self.is_path_allowed(current_url):
                logger.debug(f"Skipping disallowed URL: {current_url}")
                continue
            # Passed checks, add to results and make request
            all_urls.add(current_url)
            logger.info(f"Crawling (Depth {depth}, Found {len(all_urls)}/{max_urls}): {current_url}")

            response = self._make_request('get', current_url)

            if isinstance(response, dict) or not isinstance(response, requests.Response) or not response.ok:
                logger.warning(f"Failed to fetch {current_url} during crawl (Status: {response.status_code if isinstance(response, requests.Response) else 'N/A'})")
                continue
            # Check content type - only parse HTML
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                logger.debug(f"Skipping non-HTML content at {current_url} ({content_type})")
                continue

            # Parse HTML for links
            try:
                soup = BeautifulSoup(response.text, 'html.parser') # Use standard parser
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    # Basic validation of href
                    if href and not href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                        try:
                            full_url = urljoin(current_url, href)
                            parsed_full = urlparse(full_url)
                            norm_full_visited = self._normalize_url_for_visit(full_url)  # Normalize
                            logger.debug(f"  -> Full URL: {full_url}")
                            logger.debug(f"  -> Parsed Host: {parsed_full.netloc}")
                            lgger.debug(f"  -> Normalized: {norm_full_visited}")
                            logger.debug(f"  -> Is in Scope? {parsed_full.netloc == base_domain}")
                            logger.debug(f"  -> Already Visited? {norm_full_visited in visited}")
                            logger.debug(f"  -> Depth OK? {depth + 1 <= max_depth}")
                            # Check scope again after joining
                            if parsed_full.netloc == base_domain:
                                norm_full_visited = self._normalize_url_for_visit(full_url)
                                # Check if not visited and within depth limits before adding
                                if norm_full_visited not in visited and depth + 1 <= max_depth:
                                    if len(all_urls) + len(queue) < (max_urls * 1.5): # Limit queue growth
                                        queue.append((full_url, depth + 1))
                                        # Add to visited immediately upon queueing? Prevents duplicates but might miss paths if crawl fails early.
                                        # visited.add(norm_full_visited)
                                    else:
                                         logger.debug("Crawl queue limit reached, not adding more.")
                            # else: logger.debug(f"Link out of scope: {full_url}")
                        except Exception as url_e:
                             logger.warning(f"Error processing link '{href}' on page {current_url}: {url_e}")

            except Exception as parse_e:
                logger.error(f"Error parsing HTML at {current_url}: {parse_e}", exc_info=True)

        logger.info(f"Crawl finished. Discovered {len(all_urls)} unique in-scope URLs (Visited ~{len(visited)} normalized URLs).")
        return list(all_urls)

    def _normalize_url_for_visit(self, url):
        """Normalize URL for checking visited set (scheme, domain, path - no query/fragment)."""
        try:
            p = urlparse(url)
            # Rebuild without query, fragment, params, trailing slash on path
            path = p.path.rstrip('/') if p.path else '/'
            # Use HTTPS as default scheme for comparison? Or keep original? Keep original for now.
            norm = urlunparse((p.scheme.lower(), p.netloc.lower(), path, '', '', ''))
            return norm
        except Exception:
             return url # Fallback to original URL if parsing fails

# --- Flask Routes ---
def clean_for_json(data: Any) -> Any:
    """
    Recursively clean data structure to ensure it's JSON-serializable.
    Handles common types like datetime, Decimal, sets, and bytes.
    """
    if isinstance(data, dict):
        return {str(key): clean_for_json(value) for key, value in data.items()} # Ensure keys are strings
    elif isinstance(data, (list, tuple)):
        return [clean_for_json(item) for item in data]
    elif isinstance(data, set):
        return [clean_for_json(item) for item in data] # Convert sets to lists
    elif isinstance(data, datetime):
        return data.isoformat() # Convert datetime to ISO string
    elif isinstance(data, Decimal): # <<< FIX: Now handles Decimal >>>
        # Convert Decimal to string or float (string preferred for precision)
        return str(data)
    elif isinstance(data, bytes):
        # Try decoding bytes, return placeholder on failure
        try:
             return data.decode('utf-8', errors='replace')
        except Exception:
             return "[bytes data]"
    elif isinstance(data, (int, float, str, bool, type(None))):
        return data
    # Fallback for other types (e.g., custom objects): convert to string
    # Be cautious, this might hide underlying issues if unexpected types appear
    else:
        try:
            # Attempt a standard JSON dump/load cycle for complex objects? Risky.
            # Safer to convert to string representation.
            return str(data)
        except Exception:
             return "[unserializable data]"

# Add the datetime filter for Jinja2
@app.template_filter('jinja2_filter_datetime')
def jinja2_filter_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """Jinja2 filter to format ISO datetime strings."""
    if not value: return 'N/A'
    try:
        # Handle potential timezone info (like 'Z' or +HH:MM) if present
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return dt.strftime(format)
    except (ValueError, TypeError):
        return value # Return original value if parsing fails

@app.route('/')
def index_route(): # Renamed function to avoid clash if you import index module
    session.pop('results', None) # Clear previous results from session
    error = session.pop('scan_error', None) # Get and clear potential error from previous attempt
    return render_template('index.html', error=error)

@app.route('/scan', methods=['POST'])
def scan_route():
    """Main route to initiate a scan based on form submission."""
    target_url = request.form.get('target_url', '').strip()
    scan_type = request.form.get('scan_type', 'full')
    selected_categories = request.form.getlist('categories')

    # Advanced Config Options from Form
    scan_depth = int(request.form.get('scan_depth', 2)) # Default depth 2
    threads = int(request.form.get('threads', 5)) # Default 5 threads
    timeout = int(request.form.get('timeout', 10)) # Default 10s timeout
    user_agent = request.form.get('user_agent', None) or None # Get custom UA or None
    respect_robots = request.form.get('respect_robots') == 'true' # Checkbox value
    check_dependencies = request.form.get('check_dependencies') == 'true' # Checkbox value
    dependencies_file = request.form.get('dependencies_file', None) or None # Optional file path
    use_nvd = request.form.get('use_nvd') == 'true' # Checkbox value

    # Brute Force Options
    enable_brute_force = request.form.get('enable_brute_force') == 'true'
    login_url = request.form.get('login_url', '').strip() or None # Use None if empty
    login_username = request.form.get('login_username', '').strip() or None # Use None if empty/default desired
    max_attempts = int(request.form.get('max_attempts', 20))
    delay = float(request.form.get('delay', 1.0))

    if not target_url:
        session['scan_error'] = "Target URL is required."
        return render_template('index.html', error=session['scan_error']), 400

    # Rough URL validation before Scanner init
    try:
        parsed_init = urlparse(target_url)
        if not parsed_init.scheme and not parsed_init.netloc:
            if '.' not in target_url or ' ' in target_url: # Basic check for domain-like structure
                 raise ValueError("Invalid target format. Please include http:// or https:// and a valid domain.")
            target_url = 'https://' + target_url # Default to https
        elif parsed_init.scheme not in ('http', 'https'):
            raise ValueError("URL must start with http:// or https://")
    except ValueError as e:
        session['scan_error'] = str(e)
        return render_template('index.html', error=session['scan_error']), 400

    logger.info(f"Received scan request: URL='{target_url}', Type='{scan_type}', Categories='{selected_categories}', BruteForce={enable_brute_force}")

    try:
        # Pass advanced options to the scanner constructor
        scanner = EthicalSecurityScanner(
            target_url=target_url,
            scan_type=scan_type,
            selected_categories=selected_categories,
            threads=threads,
            timeout=timeout,
            user_agent=user_agent,
            respect_robots=respect_robots,
            scan_depth=scan_depth
            # payloads_dir is defaulted in constructor
        )
        logger.info(f"Starting '{scan_type}' scan for {scanner.target_url}")
        # Use scanner's results dictionary directly
        scanner.results['scan_time'] = datetime.utcnow().isoformat() # Update start time
        results = scanner.results # Work directly with the scanner's results dict

        start_time = results['scan_stats']['start_time'] # Get start time from scanner
        # --- Core Scan Logic ---
        scanner.resolve_domain() # Resolve IPs first
        scanner.check_domain_information() # Get domain info early
        urls_to_scan = set([scanner.target_url])
        if scan_type == "full" or not selected_categories: # Crawl if full scan or no categories selected (implies full)
            logger.info("Crawling target...")
            # Limit crawl URLs to avoid excessive scanning time
            crawled_urls = scanner.crawl(scanner.target_url, max_depth=scanner.scan_depth, max_urls=25) # Limit crawl results
            urls_to_scan.update(crawled_urls)
            logger.info(f"Scanning up to {len(urls_to_scan)} URLs (crawl depth {scanner.scan_depth}).")

        # Limit scan targets further if needed, especially for intensive checks
        urls_to_scan_list = list(urls_to_scan)[:20] # Hard limit on URLs to actively scan
        results["findings"]["scanned_urls_summary"] = {"total_discovered": len(urls_to_scan), "actively_scanned": len(urls_to_scan_list)}
        # --- Define Scan Functions Map ---
        scan_map = {
            # Check name : function to call
            "sql_injection": lambda url: scanner.sql_injection_test(url),
            "xss": lambda url: scanner.test_reflective_xss(url), # Only reflective for direct call
            "dom_xss": lambda url: scanner._check_dom_xss(),  # <<< FIX: Call correct method, ignore url >>>
            "stored_xss": lambda url: scanner.test_stored_xss(url),
            "csrf": lambda url: scanner.csrf_test(url),
            "headers": lambda url: scanner.check_security_headers(), # Runs on base URL implicitly
            "https": lambda url: scanner.check_https(), # Runs on base URL implicitly
            "cookies": lambda url: scanner.check_cookies(), # Runs on base URL implicitly
            "info_disclosure": lambda url: scanner.check_information_disclosure(), # Runs on base URL implicitly
            "dir_traversal": lambda url: scanner.check_directory_traversal(url), # Needs param name logic? Defaulting to 'file'
            "open_redirect": lambda url: scanner.check_open_redirect(url), # Needs param name logic? Defaulting to 'redirect'
            "ssrf": lambda url: scanner.check_ssrf(url), # Needs param name logic? Defaulting to 'url'
            "cmd_injection": lambda url: scanner.check_command_injection(url), # Needs param name logic? Defaulting to 'cmd'
            "waf": lambda url: scanner.check_waf_presence(), # Runs on base URL implicitly
            "domain_info": lambda url: None, # Already run at start
            "cve_check": lambda url: None, # Handled separately below
            # Missing mappings for items in results.html: 'port_scan', 'raw_http'
        }
        # --- Determine Categories to Run ---
        if scan_type == "full" or not selected_categories:
            categories_to_run = list(k for k in scan_map.keys() if k != "cve_check") # Exclude cve_check from main loop
            logger.info("Running full scan...")
        else:
            categories_to_run = [cat for cat in selected_categories if cat in scan_map and cat != "cve_check"]
            logger.info(f"Running custom scan for categories: {categories_to_run}")
        # --- Execute Scan Checks ---
        for category in categories_to_run:
            scan_function = scan_map.get(category)
            if not scan_function:
                logger.warning(f"No scan function mapped for category: {category}")
                continue
            logger.info(f"--- Running Check: {category.replace('_', ' ').title()} ---")
            try:
                # Checks that should only run ONCE for the base target URL
                if category in ["headers", "https", "cookies", "info_disclosure", "waf", "domain_info", "dom_xss"]:
                    # Only run if not already populated (or always run https?)
                    # The check itself should ideally populate scanner.results['findings'][category]
                    if category == "dom_xss":
                        scanner._check_dom_xss() # Call directly
                    elif category == "domain_info":
                         pass # Already ran
                    else:
                         # These functions run on self.target_url implicitly or passed here
                         scan_function(scanner.target_url)
                # Checks that run on multiple potentially relevant URLs
                else:
                    urls_for_this_check = urls_to_scan_list # Use the limited list
                    # Basic filtering based on URL structure (can be improved)
                    if category in ["sql_injection", "xss", "dir_traversal", "open_redirect", "ssrf", "cmd_injection"]:
                        urls_for_this_check = [url for url in urls_for_this_check if "?" in urlparse(url).query]
                    # No URL filtering needed for stored_xss, csrf (they parse page content)
                    if not urls_for_this_check and category not in ["stored_xss", "csrf"]:
                         logger.info(f"Skipping {category} check - no relevant URLs found in the scanned list.")
                         results['findings'][category] = {"status": "skipped", "message": "No relevant URLs"}
                         continue

                    # Use full list for checks that parse content (like stored_xss, csrf)
                    if category in ["stored_xss", "csrf"]:
                        urls_for_this_check = urls_to_scan_list
                    logger.info(f"Running {category} on up to {len(urls_for_this_check)} relevant URL(s)...")
                    for url in urls_for_this_check:
                        if not scanner.is_path_allowed(url):
                            logger.debug(f"Skipping disallowed URL for {category}: {url}")
                            continue
                        logger.debug(f"-> Running {category} on {url}")
                        # The scan function should update scanner.results directly or via _add_vulnerability
                        scan_function(url)
                        time.sleep(0.05) # Small delay

            except Exception as check_e:
                logger.error(f"Error running check '{category}': {check_e}", exc_info=True)
                results['scan_stats']['errors_encountered'] += 1
                results['findings'][f"{category}_error"] = str(check_e) # Store error in findings

        # --- Run Separate Checks ---
        # CVE Check (if selected or full scan)
        if check_dependencies and ('cve_check' in selected_categories or scan_type == 'full'):
            logger.info("--- Running Check: CVE Check ---")
            try:
                 # TODO: Need logic to determine dependencies file path if not provided
                 # Example: Try common filenames? Requires fetching target content?
                 if not dependencies_file: logger.warning("No dependencies file specified for CVE check.")
                 scanner.check_vulnerabilities(dependencies_file=dependencies_file, use_nvd=use_nvd)
            except Exception as cve_e:
                 logger.error(f"Error running CVE check: {cve_e}", exc_info=True)
                 results['scan_stats']['errors_encountered'] += 1
                 results['findings']["cve_check_error"] = str(cve_e)
        # Brute Force Check (if selected)
        if enable_brute_force:
            logger.info("--- Running Check: Brute Force ---")
            try:
                bf_login_url = login_url if login_url else scanner.target_url # Default to target if not specified
                password_list_name = PAYLOAD_FILES.get('passwords', 'password_list.txt') # Get from constants
                # Path is resolved inside brute_force_login relative to payloads_dir
                scanner.brute_force_login(
                    login_url=bf_login_url,
                    username=login_username, # Can be None
                    password_list_path=password_list_name,
                    max_attempts=max_attempts,
                    delay=delay
                )
                # Result is stored in scanner.results['findings']['brute_force'] by the method
            except Exception as bf_e:
                logger.error(f"Error running Brute Force check: {bf_e}", exc_info=True)
                results['scan_stats']['errors_encountered'] += 1
                results['findings']["brute_force_error"] = str(bf_e)
        # --- Finalize ---
        scanner.finalize_scan() # Calculates duration, final score, saves to DB
        try:
            cleaned_results = clean_for_json(results)

            # Sort vulnerabilities by severity score before passing to template
            if 'vulnerabilities' in cleaned_results and isinstance(cleaned_results['vulnerabilities'], list):
                severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
                cleaned_results['vulnerabilities'].sort(
                    key=lambda v: severity_map.get(v.get('severity', 'Info'), 0),
                    reverse=True
                )
            session['results'] = cleaned_results  # Store cleaned and sorted results
            results_json = json.dumps(cleaned_results)
            # Pass the cleaned_results (which are now sorted) to the template
            return render_template("results.html", results=cleaned_results, results_json=results_json)

        except Exception as clean_e:
             logger.error(f"FATAL: Failed to clean results for JSON serialization: {clean_e}", exc_info=True)
             # Cannot proceed without clean results, store error and return error template
             session['scan_error'] = f"Failed to process scan results: {clean_e}"
             return render_template("index.html", error=session['scan_error']), 500

        session['results'] = cleaned_results # Store cleaned results in session
        results_json = json.dumps(cleaned_results)
        return render_template("results.html", results=cleaned_results, results_json=results_json)

    except ValueError as e: # Scanner init errors
        logger.error(f"Invalid input for scan: {e}")
        session['scan_error'] = f"Invalid input: {str(e)}"
        return render_template("index.html", error=session['scan_error']), 400
    except RuntimeError as e: # WebDriver init errors etc.
        logger.error(f"Scanner runtime initialization failed: {e}", exc_info=True)
        session['scan_error'] = f"Scan initialization failed: {str(e)}"
        return render_template("index.html", error=session['scan_error']), 500
    except Exception as e:
        logger.error(f"Unexpected error during scan execution: {e}", exc_info=True)
        session['scan_error'] = "An unexpected error occurred during the scan. Please check logs."
        return render_template("index.html", error=session['scan_error']), 500


@app.route('/results')
def results_route():
    """Displays the results page using data stored in the session."""
    results_data = session.get('results')
    if not results_data:
        # No results found, maybe redirect to index with a message?
        logger.warning("Accessed /results route without results in session.")
        return render_template('index.html', error="No scan results found in session. Please run a scan first.")

    # Data in session should already be cleaned by clean_for_json before storing
    try:
        # Pass results data and the JSON string representation
        results_json = json.dumps(results_data)
        return render_template('results.html', results=results_data, results_json=results_json)
    except Exception as e:
         logger.error(f"Error rendering results template: {e}", exc_info=True)
         return render_template('index.html', error="Error displaying results. Please check logs."), 500


# PDF Download Route
@app.route('/download_pdf', methods=['POST'])
def download_pdf_route():
    """Generate and download a PDF report of the scan results."""
    try:
        # <<< FIX: Get results from session, not form data >>>
        results_data = session.get('results')
        if not results_data:
            logger.error("PDF download request but no results in session.")
            # Return a user-friendly error page or JSON error
            return jsonify({"error": "No scan results found to generate PDF."}), 400

        # Ensure data is serializable (should be if stored correctly)
        try:
             results_data = clean_for_json(results_data) # Clean again just in case
        except Exception as clean_e:
             logger.error(f"Error cleaning results data for PDF: {clean_e}", exc_info=True)
             return jsonify({"error": f"Failed to process results data for PDF: {clean_e}"}), 500

        # Render the *dedicated PDF template*
        try:
            # Use report_pdf.html template for PDF generation
            # Ensure this template exists and uses the 'results' variable
            html_content = render_template('report_pdf.html', results=results_data)
            logger.debug("Rendered report_pdf.html template for PDF.")
        except Exception as e:
            logger.error(f"Failed to render PDF HTML template (report_pdf.html): {e}", exc_info=True)
            return jsonify({"error": "Failed to generate PDF: Template error."}), 500

        # Verify wkhtmltopdf path
        wkhtmltopdf_path = os.getenv("WKHTMLTOPDF_PATH")
        config = None
        try:
             # pdfkit uses 'wkhtmltopdf' command by default if path not specified
             # Check if path is set and valid, otherwise let pdfkit find it
             if wkhtmltopdf_path and os.path.exists(wkhtmltopdf_path):
                  config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
                  logger.info(f"Using wkhtmltopdf from path: {wkhtmltopdf_path}")
             else:
                  logger.info("WKHTMLTOPDF_PATH not set or invalid, trying system path for wkhtmltopdf.")
                  # No config needed if it's in PATH
                  pass
        except Exception as config_e:
              logger.error(f"Error configuring wkhtmltopdf path: {config_e}")
              # Continue and let pdfkit try default path


        options = {
            'page-size': 'A4', 'margin-top': '0.75in', 'margin-right': '0.75in',
            'margin-bottom': '0.75in', 'margin-left': '0.75in', 'encoding': "UTF-8",
            'enable-local-file-access': None, # Needed for static assets like logos
            'footer-center': '[page]/[topage]', 'footer-font-size': '8',
            'quiet': '' # Suppress wkhtmltopdf output unless error
        }

        logger.info("Generating PDF report...")
        try:
            pdf_data = pdfkit.from_string(html_content, False, options=options, configuration=config)
            logger.info("PDF generation complete.")
        except OSError as e:
             # Specific check if wkhtmltopdf is not found
             if "No wkhtmltopdf executable found" in str(e):
                  logger.error(f"PDF generation failed: wkhtmltopdf executable not found. Please install it and ensure it's in PATH or set WKHTMLTOPDF_PATH. Error: {e}", exc_info=True)
                  return jsonify({"error": "PDF generation tool (wkhtmltopdf) not found. Please install it."}), 500
             else:
                  logger.error(f"PDF generation failed: OS error running wkhtmltopdf. Error: {e}", exc_info=True)
                  return jsonify({"error": f"PDF generation failed: Could not run PDF tool. Error: {e}"}), 500
        except Exception as e: # Catch other pdfkit errors
             logger.error(f"PDF generation failed unexpectedly (pdfkit stage): {e}", exc_info=True)
             return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500


        # Construct filename
        target_name = urlparse(results_data.get('target', 'unknown')).netloc.replace('.', '_') or "scan_report"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"SecurityScan_{target_name}_{timestamp}.pdf"

        # Send the response
        response = Response(pdf_data, mimetype='application/pdf')
        response.headers['Content-Disposition'] = f'attachment; filename="{pdf_filename}"' # Add quotes for safety
        response.headers['Content-Length'] = str(len(pdf_data))
        return response

    except Exception as e: # Catch errors before PDF generation starts
        logger.error(f"PDF download route failed unexpectedly: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


# --- API Endpoints (Example implementations - Keep or remove as needed) ---
# (No changes made to API endpoints based on current logs)

@app.route('/api/scan/brute_force', methods=['POST'])
def api_brute_force_scan():
    """API endpoint to run a brute-force scan."""
    data = request.json
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    login_url = data.get('login_url')
    username = data.get('username', 'admin')
    password_list_name = data.get('password_list', PAYLOAD_FILES.get('passwords', 'passwords.txt'))
    max_attempts = data.get('max_attempts', 50)
    delay = data.get('delay', 1.0)

    if not login_url:
        return jsonify({"error": "Login URL ('login_url') is required"}), 400

    try:
        # Initialize the scanner with the login URL
        scanner = EthicalSecurityScanner(login_url)
        logger.info(f"API: Running brute force for {username} on {login_url}")

        # Determine correct path for password list
        if not os.path.isabs(password_list_name):
            password_list_path = os.path.join(PAYLOADS_DIR, password_list_name)
        else:
            password_list_path = password_list_name

        # Run brute force scan
        result = scanner.brute_force_login(
            login_url,
            username,
            password_list_path,
            max_attempts,
            delay
        )

        # Handle result formatting
        if not isinstance(result, dict):
            result = {"status": "error", "message": "Invalid result format"}

        if result.get("found_password"):
            result["found_password"] = "***"  # Mask password in API response

        return jsonify(result)

    except ValueError as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400
    except FileNotFoundError as e:
        logger.error(f"API Brute force password file error: {e}")
        return jsonify({"status": "error", "message": f"Password list file error: {e}"}), 404
    except RuntimeError as e:
        logger.error(f"API Brute force runtime error: {e}", exc_info=True)
        return jsonify({"error": f"Failed to run async task: {e}"}), 500
    except Exception as e:
        logger.error(f"API Brute force unexpected error: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500



@app.route('/api/scan/sql_injection', methods=['POST'])
def api_sql_injection_scan():
    """API endpoint for SQL Injection scan on a specific URL."""
    data = request.json
    if not data: return jsonify({"error": "Request body must be JSON"}), 400
    url = data.get('url')
    use_proxies = data.get('use_proxies', False) # Default no proxies for API?

    if not url:
        return jsonify({"error": "URL ('url') is required"}), 400

    try:
        scanner = EthicalSecurityScanner(url) # Init with the target URL
        result = scanner.sql_injection_test(url, use_proxies=use_proxies) # Test the same URL
        # Optionally simplify result structure for API
        return jsonify(result)
    except ValueError as e:
         return jsonify({"error": f"Invalid input: {e}"}), 400
    except Exception as e:
         logger.error(f"API SQLi unexpected error: {e}", exc_info=True)
         return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


@app.route('/api/scan/xss', methods=['POST'])
def api_xss_scan():
    """API endpoint for XSS scan (Reflective only currently)."""
    data = request.json
    if not data: return jsonify({"error": "Request body must be JSON"}), 400
    url = data.get('url')
    # xss_type = data.get('xss_type', 'reflective') # Only reflective supported easily via API for now
    use_proxies = data.get('use_proxies', False)
    if not url:
        return jsonify({"error": "URL ('url') is required"}), 400
    try:
        scanner = EthicalSecurityScanner(url)
        # Only call reflective test here, stored/DOM need browser automation
        result = scanner.test_reflective_xss(url, use_proxies=use_proxies)
        return jsonify(result)
    except ValueError as e:
         return jsonify({"error": f"Invalid input: {e}"}), 400
    except Exception as e:
         logger.error(f"API XSS unexpected error: {e}", exc_info=True)
         return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


# --- Main Execution ---
if __name__ == '__main__':
    # Consider using environment variables for host/port/debug
    app_host = os.getenv('FLASK_HOST', '0.0.0.0')
    app_port = int(os.getenv('FLASK_PORT', 5000))
    # Default debug to False for safety unless explicitly set via FLASK_DEBUG=true/1
    app_debug = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1']

    # Ensure secret key is set, warn if using default
    if app.secret_key == 'a_default_development_secret_key_replace_me':
         logger.warning("SECURITY WARNING: Using default Flask secret key. Set FLASK_SECRET_KEY environment variable.")

    logger.info(f"Starting Flask app on {app_host}:{app_port} (Debug: {app_debug})")

    # Use Waitress or Gunicorn for production instead of app.run(debug=True)
    if not app_debug:
         try:
              from waitress import serve
              logger.info("Running with Waitress production server.")
              serve(app, host=app_host, port=app_port, threads=8) # Example waitress config
         except ImportError:
              logger.warning("Waitress not found. Falling back to Flask development server (NOT recommended for production).")
              app.run(debug=app_debug, host=app_host, port=app_port)
    else:
         # Run with Flask development server if debug is True
         app.run(debug=app_debug, host=app_host, port=app_port)
