import sys
import random
import json
import argparse
import requests
import urllib3
import threading
import re
import socket
import concurrent.futures
from queue import Queue
from urllib.parse import urlparse
from laya import Router
from Wappalyzer import Wappalyzer, WebPage

# Suppress insecure request warnings from verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === LAYA ENGINE INITIALIZATION ===
print("[*] Initializing Laya Decision Engine...", file=sys.stderr)
router = Router(preload=True)

# === WAPPALYZER INITIALIZATION ===
print("[*] Loading Wappalyzer signatures database...", file=sys.stderr)
wappalyzer_scanner = Wappalyzer.latest()

# === HTTP VALIDATION CONFIGURATIONS ===
MAX_THREADS_RECON = 20  
TIMEOUT_HTTP = 4        

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

print_lock = threading.Lock()
total_processed = 0
total_alive = 0
counter_lock = threading.Lock()

def validate_domain_format(domain):
    """Validate basic domain format"""
    domain = domain.strip().lower()
    if not domain or len(domain) < 3:
        return None
    # Basic domain validation
    pattern = r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$'
    if re.match(pattern, domain):
        return domain
    return None

def is_valid_subdomain(subdomain, domain):
    """Check if subdomain is valid and belongs to domain"""
    subdomain = subdomain.strip().lower()
    domain = domain.lower()
    if not subdomain or '*' in subdomain:
        return False
    if not subdomain.endswith(domain):
        return False
    # Avoid very long or suspicious entries
    if len(subdomain) > 255:
        return False
    return True

def fetch_subdomains_crt(domain):
    print(f"{BLUE}[*]{RESET} Querying CT Logs on crt.sh for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    url = "https://crt.sh/"
    query_params = {'q': f'%.{domain}', 'output': 'json'}
    try:
        response = requests.get(url, params=query_params, timeout=15, headers={'User-Agent': random.choice(USER_AGENTS)})
        if response.status_code != 200:
            return []
        try:
            certs = response.json()
        except:
            return []
        subdomains = set()
        for cert in certs:
            names = cert.get('name_value', '').split('\n')
            for name in names:
                name = name.strip().lower()
                if is_valid_subdomain(name, domain):
                    subdomains.add(name)
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from crt.sh: {e}", file=sys.stderr)
        return []

def fetch_subdomains_rapiddns(domain):
    """Fetch subdomains from RapidDNS"""
    print(f"{BLUE}[*]{RESET} Querying RapidDNS for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        response = requests.get(url, timeout=15, headers={'User-Agent': random.choice(USER_AGENTS)})
        if response.status_code != 200:
            return []
        subdomains = set()
        # Extract subdomains from page (basic regex)
        pattern = r'([a-z0-9][a-z0-9.-]*\.{0})'.format(re.escape(domain))
        matches = re.findall(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain) + ')', response.text, re.IGNORECASE)
        for match in matches:
            match = match.lower().strip()
            if is_valid_subdomain(match, domain):
                subdomains.add(match)
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from RapidDNS: {e}", file=sys.stderr)
        return []

def fetch_subdomains_hackertarget(domain):
    """Fetch subdomains from HackerTarget"""
    print(f"{BLUE}[*]{RESET} Querying HackerTarget for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15, headers={'User-Agent': random.choice(USER_AGENTS)})
        if response.status_code != 200:
            return []
        subdomains = set()
        for line in response.text.splitlines():
            if ',' in line:
                sub = line.split(',')[0].strip().lower()
                if is_valid_subdomain(sub, domain):
                    subdomains.add(sub)
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from HackerTarget: {e}", file=sys.stderr)
        return []

def fetch_subdomains_crt_alt(domain):
    """Alternative crt.sh endpoint via web interface parsing"""
    print(f"{BLUE}[*]{RESET} Querying crt.sh (alternative) for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://crt.sh/?q=%.{domain}"
        response = requests.get(url, timeout=15, headers={'User-Agent': random.choice(USER_AGENTS)})
        if response.status_code != 200:
            return []
        subdomains = set()
        matches = re.findall(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain) + ')', response.text, re.IGNORECASE)
        for match in matches:
            match = match.lower().strip()
            if is_valid_subdomain(match, domain):
                subdomains.add(match)
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from crt.sh (alt): {e}", file=sys.stderr)
        return []

def fetch_subdomains_virustotal(domain):
    """Fetch subdomains from VirusTotal (public endpoint, limited)"""
    print(f"{BLUE}[*]{RESET} Querying VirusTotal for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=50"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        response = requests.get(url, timeout=20, headers=headers)
        if response.status_code != 200:
            return []
        subdomains = set()
        data = response.json()
        for item in data.get('data', []):
            id_name = item.get('id', '')
            if is_valid_subdomain(id_name, domain):
                subdomains.add(id_name)
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from VirusTotal: {e}", file=sys.stderr)
        return []

def fetch_subdomains_certspotter(domain):
    """Fetch subdomains from CertSpotter"""
    print(f"{BLUE}[*]{RESET} Querying CertSpotter for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&match_wildcards=false&max_records=100"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        response = requests.get(url, timeout=20, headers=headers)
        if response.status_code != 200:
            return []
        subdomains = set()
        try:
            data = response.json()
            for cert in data:
                dns_names = cert.get('dns_names', [])
                for name in dns_names:
                    name = name.strip().lower()
                    if is_valid_subdomain(name, domain):
                        subdomains.add(name)
        except:
            pass
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from CertSpotter: {e}", file=sys.stderr)
        return []

def fetch_subdomains_otx(domain):
    """Fetch subdomains from AlienVault OTX"""
    print(f"{BLUE}[*]{RESET} Querying AlienVault OTX for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        response = requests.get(url, timeout=20, headers=headers)
        if response.status_code != 200:
            return []
        subdomains = set()
        try:
            data = response.json()
            for entry in data.get('passive_dns', []):
                hostname = entry.get('hostname', '')
                if is_valid_subdomain(hostname, domain):
                    subdomains.add(hostname)
        except:
            pass
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from OTX: {e}", file=sys.stderr)
        return []

def fetch_subdomains_digitorus(domain):
    """Fetch subdomains from Digitorus"""
    print(f"{BLUE}[*]{RESET} Querying Digitorus for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://dns.digitorus.com/domain/{domain}/subdomains"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        response = requests.get(url, timeout=20, headers=headers)
        if response.status_code != 200:
            return []
        subdomains = set()
        matches = re.findall(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain) + ')', response.text, re.IGNORECASE)
        for match in matches:
            match = match.lower().strip()
            if is_valid_subdomain(match, domain):
                subdomains.add(match)
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from Digitorus: {e}", file=sys.stderr)
        return []

def fetch_subdomains_subdomaincenter(domain):
    """Fetch subdomains from SubdomainCenter"""
    print(f"{BLUE}[*]{RESET} Querying SubdomainCenter for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://api.subdomain.center/?domain={domain}"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        response = requests.get(url, timeout=20, headers=headers)
        if response.status_code != 200:
            return []
        subdomains = set()
        try:
            data = response.json()
            for sub in data:
                sub = sub.strip().lower()
                if is_valid_subdomain(sub, domain):
                    subdomains.add(sub)
        except:
            pass
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from SubdomainCenter: {e}", file=sys.stderr)
        return []

def fetch_subdomains_dnsdumpster(domain):
    """Fetch subdomains from DNSDumpster (web scraping)"""
    print(f"{BLUE}[*]{RESET} Querying DNSDumpster for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = "https://dnsdumpster.com/"
        headers = {'User-Agent': random.choice(USER_AGENTS), 'Referer': 'https://dnsdumpster.com/'}
        session = requests.Session()
        # Get CSRF token
        r = session.get(url, headers=headers, timeout=15)
        csrf_token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
        if not csrf_token:
            return []
        token = csrf_token.group(1)
        data = {'csrfmiddlewaretoken': token, 'targetip': domain}
        headers['Cookie'] = '; '.join([f'{k}={v}' for k, v in r.cookies.items()])
        r = session.post(url, data=data, headers=headers, timeout=30)
        subdomains = set()
        matches = re.findall(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain) + ')', r.text, re.IGNORECASE)
        for match in matches:
            match = match.lower().strip()
            if is_valid_subdomain(match, domain) and not match.startswith(('www.',)):
                subdomains.add(match)
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from DNSDumpster: {e}", file=sys.stderr)
        return []

def fetch_subdomains_anubis(domain):
    """Fetch subdomains from Anubis-DB"""
    print(f"{BLUE}[*]{RESET} Querying Anubis for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        response = requests.get(url, timeout=15, headers={'User-Agent': random.choice(USER_AGENTS)})
        if response.status_code != 200:
            return []
        subdomains = set()
        try:
            data = response.json()
            for sub in data:
                sub = sub.strip().lower()
                if is_valid_subdomain(sub, domain):
                    subdomains.add(sub)
        except:
            matches = re.findall(r'"([^"]+\.{0})"'.format(re.escape(domain)), response.text, re.IGNORECASE)
            for match in matches:
                match = match.lower().strip()
                if is_valid_subdomain(match, domain):
                    subdomains.add(match)
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from Anubis: {e}", file=sys.stderr)
        return []

def fetch_subdomains_bufferover(domain):
    """Fetch subdomains from BufferOver.run"""
    print(f"{BLUE}[*]{RESET} Querying BufferOver.run for: {YELLOW}{domain}{RESET}...", file=sys.stderr)
    try:
        url = f"https://dns.bufferover.run/dns?q={domain}"
        response = requests.get(url, timeout=15, headers={'User-Agent': random.choice(USER_AGENTS)})
        if response.status_code != 200:
            return []
        subdomains = set()
        try:
            data = response.json()
            for entry in data.get('FDNS_A', []) + data.get('RDNS', []):
                if ',' in entry:
                    sub = entry.split(',')[-1].strip().lower()
                    if is_valid_subdomain(sub, domain):
                        subdomains.add(sub)
        except:
            pass
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to fetch data from BufferOver: {e}", file=sys.stderr)
        return []

def fetch_subdomains_osint(domain):
    """Aggregate subdomain enumeration from multiple OSINT sources"""
    all_subdomains = set()
    sources = [
        fetch_subdomains_crt,
        fetch_subdomains_crt_alt,
        fetch_subdomains_certspotter,
        fetch_subdomains_rapiddns,
        fetch_subdomains_hackertarget,
        fetch_subdomains_anubis,
        fetch_subdomains_bufferover,
        fetch_subdomains_dnsdumpster,
        fetch_subdomains_digitorus,
        fetch_subdomains_subdomaincenter,
        fetch_subdomains_otx,
        fetch_subdomains_virustotal,
    ]
    
    # Run sources in parallel for faster collection
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_source = {executor.submit(source_func, domain): source_func.__name__ for source_func in sources}
        for future in concurrent.futures.as_completed(future_to_source):
            source_name = future_to_source[future]
            try:
                results = future.result()
                if results:
                    all_subdomains.update(results)
                    print(f"{GREEN}[+]{RESET} {source_name}: found {len(results)} subdomains", file=sys.stderr)
                else:
                    print(f"{YELLOW}[~]{RESET} {source_name}: no results", file=sys.stderr)
            except Exception:
                print(f"{RED}[-]{RESET} {source_name}: failed", file=sys.stderr)
    
    # Remove duplicates and sort
    final_list = sorted(list(all_subdomains))
    print(f"{BLUE}[*]{RESET} Total unique subdomains collected: {YELLOW}{len(final_list)}{RESET}", file=sys.stderr)
    return final_list

def inspect_waf_fingerprint(headers, cookies):
    headers_str = "".join([f"{k}:{v}".lower() for k, v in headers.items()])
    cookies_str = "".join([c.name.lower() for c in cookies])
    
    if "cloudflare" in headers_str or "cf-ray" in headers_str or "__cf_bm" in cookies_str:
        return "Cloudflare WAF"
    if "akamai" in headers_str or "akamai-extension" in headers_str or "ak_bmsc" in cookies_str:
        return "Akamai Edge"
    if "x-amzn-requestid" in headers_str or "awswaf" in headers_str:
        return "AWS WAF"
    if "imperva" in headers_str or "incap_ses" in cookies_str or "visid_incap" in cookies_str:
        return "Imperva Incapsula"
    if "sucuri" in headers_str or "__sucuri" in cookies_str:
        return "Sucuri WAF"
    if "barracuda" in headers_str:
        return "Barracuda WAF"
    if "f5" in headers_str or "bigip" in headers_str or "tsh" in cookies_str:
        return "F5 BIG-IP"
    if "mod_security" in headers_str:
        return "ModSecurity"
        
    return "None Detected"

def test_host(url, alive_results, total_hosts):
    global total_processed, total_alive
    protocols = [""] if url.startswith(("http://", "https://")) else ["https://", "http://"]
    
    questions = {
        "is_critical_target": {
            "type": "noul",
            "instructions": (
                "Analyze this target for penetration testing criticality and actual security risk. "
                "Score close to 1.0 (True) ONLY if the host displays high-value exploitability markers: "
                "exposed API environments (Swagger/JSON), backend framework footprints, internal setup portals, "
                "sensitive endpoints lacking proper WAF security layers, or debug setups. "
                "Score close to 0.0 (False) if it is an unexploitable static asset, a third-party global CDN, "
                "or a generic corporate landing page with zero actionable attack surface."
            )
        },
        "attack_vector": {
            "type": "choice",
            "instructions": "Determine the highest value technical entry point for this active node.",
            "criteria": {
                "api": "json data, restful endpoints, graphql, routing paths, swagger docs",
                "cms": "wordpress, drupal, joomla, unhardened blogging software",
                "login": "sso screens, admin panels, custom login forms, keycloak, active portals",
                "cloud": "exposed buckets, s3, storage blobs, missing proxy filters",
                "other": "low-risk static resources, empty placeholders, or default server index pages"
            }
        }
    }
    
    for protocol in protocols:
        target = f"{protocol}{url}"
        try:
            current_agent = random.choice(USER_AGENTS)
            headers = {
                "User-Agent": current_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5"
            }
            
            resp = requests.get(target, headers=headers, timeout=TIMEOUT_HTTP, verify=False, allow_redirects=False)
            
            title = "No Title"
            try:
                lower_text = resp.text.lower()
                start_tag = "<title>"
                end_tag = "</title>"
                if start_tag in lower_text and end_tag in lower_text:
                    start_idx = lower_text.find(start_tag) + len(start_tag)
                    end_idx = lower_text.find(end_tag)
                    if start_idx < end_idx:
                        extracted_title = resp.text[start_idx:end_idx].strip()
                        title = " ".join(extracted_title.split())
            except Exception:
                title = "No Title"
            
            detected_techs = []
            try:
                webpage = WebPage(url=target, html=resp.text, headers=resp.headers)
                tech_analysis = wappalyzer_scanner.analyze_with_versions_and_categories(webpage)
                if tech_analysis:
                    for tech_name, tech_data in tech_analysis.items():
                        version = f" {tech_data['version']}" if tech_data.get('version') else ""
                        detected_techs.append(f"{tech_name}{version}")
            except Exception:
                pass
            
            tech_string = ", ".join(detected_techs) if detected_techs else "None Detected"
            server = resp.headers.get("Server", "Unknown")
            content_length = resp.headers.get("Content-Length", len(resp.content))
            
            cookie_issues = []
            for cookie in resp.cookies:
                flags = []
                if not cookie.secure: flags.append("Missing-Secure")
                if hasattr(cookie, 'rest') and 'HttpOnly' not in cookie.rest: flags.append("Missing-HttpOnly")
                if flags: cookie_issues.append(f"{cookie.name}({'/'.join(flags)})")
            cookie_string = ", ".join(cookie_issues) if cookie_issues else "Secure or None"
            
            detected_waf = inspect_waf_fingerprint(resp.headers, resp.cookies)
            
            host_metadata = (
                f"URL: {target} | Status: {resp.status_code} | Server: {server} | "
                f"Title: {title} | Technologies: {tech_string} | "
                f"Size: {content_length} bytes | InsecureCookies: {cookie_string} | "
                f"WAF: {detected_waf}"
            )
            
            prediction = router.predict(host_metadata, questions, model="multilingual")
            priority_score = float(prediction["answers"]["is_critical_target"]["noul"])
            vector_guess = str(prediction["answers"]["attack_vector"]["choice"])
            
            alive_results.append({
                "target": target,
                "status": resp.status_code,
                "server": server,
                "title": title,
                "technologies": tech_string,
                "size_bytes": int(content_length),
                "insecure_cookies": cookie_string,
                "waf": detected_waf,
                "score": priority_score,
                "vector": vector_guess,
                "raw_metadata": host_metadata
            })
            
            with counter_lock:
                total_processed += 1
                total_alive += 1
                progress = f"[{total_processed}/{total_hosts}]"
            
            with print_lock:
                print(f"{GREEN}[ALIVE]{RESET} {progress} {target} (Score: {priority_score:.2f} | WAF: {detected_waf})", file=sys.stderr)
            return

        except requests.RequestException:
            continue
            
    with counter_lock:
        total_processed += 1
        progress = f"[{total_processed}/{total_hosts}]"
    with print_lock:
        print(f"{RED}[DEAD]{RESET} {progress} {url}", file=sys.stderr)

def run_concurrent_validation(subdomains):
    global total_processed, total_alive
    total_processed = 0
    total_alive = 0
    total_hosts = len(subdomains)
    
    print(f"{BLUE}[*]{RESET} Starting active validation for {YELLOW}{total_hosts}{RESET} targets using {MAX_THREADS_RECON} threads...\n", file=sys.stderr)
    alive_results = []
    queue = Queue()
    for sub in subdomains:
        queue.put(sub)
        
    def worker():
        while not queue.empty():
            subdomain = queue.get()
            test_host(subdomain, alive_results, total_hosts)
            queue.task_done()
            
    threads = []
    for _ in range(min(MAX_THREADS_RECON, total_hosts)):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
        
    print(f"\n{BLUE}[*]{RESET} Validation finished. Found {GREEN}{total_alive}{RESET} active hosts.", file=sys.stderr)
    return alive_results

def export_markdown(filename, data):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("# High-Fidelity Tactical Recon Report\n\n")
            f.write(f"Generated via Laya Calibration. Active Footprint: {len(data)}\n\n")
            f.write("| Rank | Target | Score | Vector | WAF Protected | Status | Server | Title |\n")
            f.write("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
            for index, host in enumerate(data, 1):
                f.write(
                    f"| {index} | `{host['target']}` | **{host['score']:.4f}** | {host['vector'].upper()} "
                    f"| __{host['waf']}__ | {host['status']} | {host['server']} | {host['title']} |\n"
                )
        print(f"{GREEN}[+]{RESET} Markdown report saved to: {YELLOW}{filename}{RESET}", file=sys.stderr)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to export Markdown: {e}", file=sys.stderr)

def export_json(filename, data):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({"scan_results": data}, f, indent=4, ensure_ascii=False)
        print(f"{GREEN}[+]{RESET} JSON report saved to: {YELLOW}{filename}{RESET}", file=sys.stderr)
    except Exception as e:
        print(f"{RED}[-]{RESET} Failed to export JSON: {e}", file=sys.stderr)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="High-Fidelity Cognitive Recon Triage with Laya")
    parser.add_argument("-d", "--domain", help="Target domain for passive crt.sh lookup")
    parser.add_argument("-om", "--output-md", help="Path to save the Markdown (.md) report")
    parser.add_argument("-oj", "--output-json", help="Path to save the JSON (.json) report")
    args = parser.parse_args()

    targets = []

    if args.domain:
        domain_clean = validate_domain_format(args.domain)
        if not domain_clean:
            print(f"{RED}[-]{RESET} Invalid domain format: {args.domain}")
            sys.exit(1)
        targets = fetch_subdomains_osint(domain_clean)
    elif not sys.stdin.isatty():
        print(f"{BLUE}[*]{RESET} Ingesting targets from stdin pipeline...", file=sys.stderr)
        for line in sys.stdin:
            cleaned_line = line.strip()
            if cleaned_line:
                targets.append(cleaned_line)
    else:
        parser.print_help()
        sys.exit(1)

    if not targets:
        print(f"{RED}[-]{RESET} No targets discovered.")
        sys.exit(1)
        
    # Normalize, deduplicate and filter
    if args.domain and domain_clean:
        targets = [t.strip().lower() for t in targets if t.strip() and is_valid_subdomain(t, domain_clean)]
        targets = list(set(targets))
    else:
        # For stdin, filter basic validity
        targets = [t.strip().lower() for t in targets if t.strip() and len(t) < 255 and '*' not in t]
        targets = list(set(targets))
    
    # Sort for consistent processing
    targets = sorted(targets)
        
    alive_hosts = run_concurrent_validation(targets)
    if not alive_hosts:
        print(f"{RED}[-]{RESET} No URLs responded to HTTP/HTTPS checks.")
        sys.exit(1)
        
    alive_hosts.sort(key=lambda x: x["score"], reverse=True)
    
    print("\n" + "="*20 + " HIGH-FIDELITY LAYA RANKING " + "="*20)
    for index, host in enumerate(alive_hosts, 1):
        alert_color = RED if host["score"] >= 0.70 else GREEN
        print(f"{index}. {alert_color}[Score: {host['score']:.4f} | {host['vector'].upper()}]{RESET} {host['raw_metadata']}")

    if args.output_md: export_markdown(args.output_md, alive_hosts)
    if args.output_json: export_json(args.output_json, alive_hosts)
