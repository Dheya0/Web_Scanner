# utils.py
import os
import csv
import json
import random
import yaml
import logging
import requests
from bs4 import BeautifulSoup
from functools import lru_cache
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor

# Assuming logger is defined elsewhere; otherwise, set it up here
logger = logging.getLogger('EthicalSecurityScanner')

# --- Configuration ---
def load_config(self, config_file=None):
    """Load configuration from a YAML file or use default settings."""
    default_config = {
        "max_requests_per_second": 10,
        "respect_robots_txt": False,
        "follow_redirects": True,
        "max_redirects": 5,
        "scan_cookies": True,
        "scan_forms": True,
        "check_csrf": True,
        "disable_modules": [],
        "user_agent": self.user_agent,
        "headers": {},
        "cookie_jar": {},
        "timeout": 5,  # Reduced default timeout for faster scans
        "max_concurrent": 5  # For async or threaded concurrency
    }
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                custom_config = yaml.safe_load(f)
                config = {**default_config, **custom_config}
                self.user_agent = config.get("user_agent", self.user_agent)
                self.respect_robots = config.get("respect_robots_txt", False)
                self.session.headers.update({
                    'User-Agent': self.user_agent,
                    **config.get("headers", {})
                })
                if config.get("cookie_jar"):
                    for domain, cookies in config.get("cookie_jar").items():
                        for name, value in cookies.items():
                            self.session.cookies.set(name, value, domain=domain)
                self.disabled_modules = config.get("disable_modules", [])
                logger.info(f"Loaded configuration from: {config_file}")
                return config
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
    return default_config

# --- Web Utilities ---
@lru_cache(maxsize=100)
def get_page_content(url, session=None, timeout=5):
    """Fetch and cache a webpage's response and parsed HTML."""
    session = session or requests.Session()
    try:
        response = session.get(url, timeout=timeout)
        soup = BeautifulSoup(response.text, 'html.parser')
        return response, soup
    except requests.RequestException as e:
        logger.error(f"Failed to fetch page {url}: {e}")
        return None, None

def run_parallel_checks(check_func, items, max_workers=5, *args, **kwargs):
    """Run a check function across multiple items in parallel."""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_func, item, *args, **kwargs) for item in items]
        for future in futures:
            result = future.result()
            if result:
                results.extend(result if isinstance(result, list) else [result])
    return results

# --- Data Loading ---
@lru_cache(maxsize=100)
def load_cve_data(cve_dir, dependencies=None):
    """Load CVE data, optionally filtered by dependencies."""
    cve_list = []
    if dependencies:
        products = {dep['product'].lower() for dep in dependencies}
    for year in range(1999, 2025):
        year_folder = os.path.join(cve_dir, str(year))
        if os.path.isdir(year_folder):
            for filename in os.listdir(year_folder):
                if filename.endswith('.json'):
                    file_path = os.path.join(year_folder, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            cve_data = json.load(f)
                            if dependencies:
                                cve_products = get_cve_products(cve_data)
                                if not products.isdisjoint(cve_products):
                                    cve_list.append(cve_data)
                            else:
                                if 'cve' in cve_data:
                                    cve_list.append(cve_data)
                                elif 'vulnerabilities' in cve_data:
                                    cve_list.extend(cve_data['vulnerabilities'])
                    except json.JSONDecodeError:
                        logger.warning(f"Skipping invalid JSON file: {file_path}")
    logger.info(f"Loaded {len(cve_list)} CVEs from local files")
    return cve_list

def get_cve_products(cve_data):
    """Extract product names from CVE data."""
    products = set()
    if 'cve' in cve_data and 'configurations' in cve_data['cve']:
        for node in cve_data['cve']['configurations'].get('nodes', []):
            for cpe in node.get('cpe_match', []):
                if 'cpe23Uri' in cpe:
                    parts = cpe['cpe23Uri'].split(':')
                    if len(parts) > 4:
                        products.add(parts[3].lower())  # Vendor or product
    return products

@lru_cache(maxsize=1)
def load_dependencies(dependencies_file):
    """Load software and versions from a CSV file."""
    try:
        with open(dependencies_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if 'product' not in reader.fieldnames or 'version' not in reader.fieldnames:
                raise ValueError("CSV must contain 'product' and 'version' columns")
            deps = list(reader)
            logger.info(f"Loaded {len(deps)} dependencies from {dependencies_file}")
            return deps
    except FileNotFoundError:
        logger.error(f"Dependencies file not found: {dependencies_file}")
        raise
    except Exception as e:
        logger.error(f"Error loading dependencies: {e}")
        raise

@lru_cache(maxsize=1)
def load_mapping(mapping_file):
    """Load product-to-CPE mapping from JSON."""
    try:
        with open(mapping_file, 'r', encoding='utf-8') as f:
            mapping = json.load(f)
            logger.info(f"Loaded CPE mapping from {mapping_file}")
            return mapping
    except FileNotFoundError:
        logger.error(f"Mapping file not found: {mapping_file}")
        raise
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in mapping file: {mapping_file}")
        raise

# --- Payload Management ---
def ensure_payload_exists(file_path):
    """Check if a payload file exists; raise an error if not."""
    if not os.path.exists(file_path):
        logger.error(f"Payload file not found: {file_path}")
        raise FileNotFoundError(f"Payload file not found: {file_path}")

def load_payloads(file_name, payloads_dir="payloads", payload_type=None):
    """Load payloads from a file with an optional type label."""
    file_path = os.path.join(payloads_dir, file_name)
    try:
        ensure_payload_exists(file_path)
        with open(file_path, 'r', encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
        if not payloads:
            logger.warning(f"File {file_name} is empty.")
        logger.info(f"Loaded {len(payloads)} {payload_type or ''} payloads from {file_name}")
        return payloads
    except Exception as e:
        logger.error(f"Failed to load {payload_type or ''} payloads from {file_path}: {e}")
        return []

# --- Proxy Handling ---
def get_proxies(proxy_list=None, test_url="http://example.com", timeout=5):
    """Return a working proxy from a list after testing availability."""
    default_proxies = [
        "http://username:password@103.152.232.81:3128",
        "http://username:password@194.87.188.114:8000",
        "http://username:password@51.79.50.31:9300",
        "http://username:password@185.199.229.156:7492",
        "http://username:password@38.154.227.37:8888",
    ]
    proxy_list = proxy_list or default_proxies
    if not proxy_list:
        return None
    working_proxies = []
    for proxy in proxy_list:
        try:
            proxies = {"http": proxy, "https": proxy}
            requests.get(test_url, proxies=proxies, timeout=timeout)
            working_proxies.append(proxy)
        except requests.RequestException:
            continue
    return {"http": random.choice(working_proxies), "https": random.choice(working_proxies)} if working_proxies else None