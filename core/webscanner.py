import requests, re, time, json, urllib.parse, socket
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from core.stealth import StealthScraper

# ---------------------------------------------------------------------------
# Constants (unchanged + expanded)
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HIGH",
    "Content-Security-Policy": "HIGH",
    "X-Frame-Options": "MEDIUM",
    "X-Content-Type-Options": "MEDIUM",
    "Cross-Origin-Opener-Policy": "MEDIUM",
    "Cross-Origin-Resource-Policy": "MEDIUM",
    "Referrer-Policy": "LOW",
    "Permissions-Policy": "LOW",
}
TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-json"],
    "Joomla": ["joomla", "com_content"],
    "Django": ["csrftoken", "django"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "ASP.NET": ["ASP.NET_SessionId", "__VIEWSTATE"],
    "React": ["react", "react-dom"],
    "Angular": ["ng-version"],
    "Nginx": ["nginx"],
    "Apache": ["httpd", "Apache"],
    "IIS": ["IIS", "Microsoft-IIS"],
    "Cloudflare": ["cloudflare", "__cfduid"],
    "PHP": ["X-Powered-By: PHP", "PHPSESSID"],
}
SENSITIVE_FILES = [
    "/.env", "/.git/HEAD", "/backup.zip", "/phpinfo.php", "/swagger.json",
    "/wp-config.php", "/docker-compose.yml", "/id_rsa", "/actuator/env",
]
JS_SECRET_PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "JWT": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Password": r"(?i)(?:password|passwd)\s*[:=]\s*['\"]?([^'\"]{6,})",
    "DB URL": r"(?:mysql|postgres|mongodb)://[^\s'\"]+",
}
XSS_PAYLOADS = [
    "<svg onload=alert(1)>", "\"'><img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>", "{{7*7}}", "${7*7}",
]
OPEN_REDIR_PARAMS = ["url","redirect","return","next","goto","target","destination","redir","redirect_uri"]
OPEN_REDIR_PAYLOADS = ["//evil.com", "https://evil.com", "/\\evil.com"]

# ---------------------------------------------------------------------------
# WebScanner with built‑in retry & Cloudflare‑aware timeout
# ---------------------------------------------------------------------------
class WebScanner:
    def __init__(self, base_url, threads=10, verbose=False, output_file=None):
        self.base = base_url.rstrip('/')
        self.threads = threads
        self.verbose = verbose
        self.output = output_file or f"WebScan_{urlparse(base_url).hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.scraper = StealthScraper(verbose=verbose)

        # --- Resilient session for plain requests ---
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _write(self, data):
        with open(self.output, 'a', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
            f.write('\n')

    def _fetch(self, url, timeout=60, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        try:
            resp = self.scraper.stealth_get(url, timeout=timeout, **kwargs)
            if resp is not None and resp.status_code < 500:
                return resp
        except:
            pass
        try:
            return self.session.get(url, timeout=timeout, **kwargs)
        except requests.exceptions.ReadTimeout:
            print(f"  [!] Read timeout for {url}")
            return None
        except Exception as e:
            if self.verbose:
                print(f"  [!] Request failed: {e}")
            return None

    def _fetch_raw(self, url, timeout=60, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        try:
            return self.session.get(url, timeout=timeout, **kwargs)
        except requests.exceptions.ReadTimeout:
            print(f"  [!] Read timeout for {url}")
            return None
        except Exception as e:
            if self.verbose:
                print(f"  [!] Raw request failed: {e}")
            return None

    # -----------------------------------------------------------------------
    # Original scanners
    # -----------------------------------------------------------------------
    def headers_scan(self):
        print(f"\n--- Security Headers ---")
        r = self._fetch_raw(self.base, timeout=60)
        if r is None:
            print("  [✗] Could not connect")
            return
        for h, sev in SECURITY_HEADERS.items():
            if h in r.headers:
                print(f"  [✓] {h}: {r.headers[h]}")
            else:
                print(f"  [✗] Missing {h} ({sev})")
        self._write({"headers": dict(r.headers)})

    def cors_scan(self):
        print(f"\n--- CORS Misconfig ---")
        for origin in ["https://evil.com", "https://attacker.com", "null"]:
            try:
                r = self.session.get(self.base, headers={"Origin": origin}, timeout=30, allow_redirects=True)
                acao = r.headers.get("Access-Control-Allow-Origin","")
                acac = r.headers.get("Access-Control-Allow-Credentials","")
                if acao == "*":
                    print(f"  [🔥] Origin {origin} -> ACAO: *")
                elif acao == origin and acac == "true":
                    print(f"  [🔥] Origin {origin} -> mirrors + ACAC:true")
                elif acao == origin:
                    print(f"  [⚠️] Origin {origin} -> mirrors (no creds)")
            except: pass

    def tech_fingerprint(self):
        print(f"\n--- Tech Fingerprinting ---")
        r = self._fetch(self.base, timeout=60)
        if r is None: return
        headers = str(r.headers).lower()
        html = r.text.lower()
        found = []
        for tech, keywords in TECH_SIGNATURES.items():
            for kw in keywords:
                if kw.lower() in headers or kw.lower() in html:
                    found.append(tech)
                    break
        if found: print(f"  Detected: {', '.join(found)}")
        self._write({"tech": found})

    def sensitive_files(self):
        print(f"\n--- Sensitive Files ---")
        for path in SENSITIVE_FILES:
            url = self.base + path
            try:
                resp = self._fetch(url, timeout=30)
                if resp and resp.status_code == 200:
                    print(f"  [🔥] {url} (200)")
                    self._write({"sensitive_file": url})
            except: pass

    def js_secrets(self):
        print(f"\n--- JS Secrets & Endpoints ---")
        try:
            r = self._fetch(self.base, timeout=60)
            if r is None: return
            soup = BeautifulSoup(r.text, 'html.parser')
            scripts = [urljoin(self.base, s['src']) for s in soup.find_all('script') if s.get('src')]
        except: return
        endpoints = set()
        for js in scripts:
            try:
                content = self._fetch(js, timeout=30)
                if content is None: continue
                content = content.text
                for name, pattern in JS_SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        print(f"  [🔥] {name} in {js}: {matches[0]}")
                        self._write({"secret": {"file":js, "type":name}})
                eps = re.findall(r'["\'](/[a-zA-Z0-9_/.-]+)["\']', content)
                eps += re.findall(r'(?:fetch|axios|get|post)\s*\(\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
                for ep in eps:
                    if ep.startswith('/'): endpoints.add(ep)
            except: pass
        if endpoints:
            print(f"  Endpoints: {len(endpoints)} found.")
            self._write({"endpoints": list(endpoints)})

    def open_redirect(self):
        print(f"\n--- Open Redirect ---")
        parsed = urlparse(self.base)
        for param, _ in parse_qs(parsed.query).items():
            if param.lower() in OPEN_REDIR_PARAMS:
                base_url = f"{parsed.scheme}://{parsed.hostname}{parsed.path}?{param}=PAYLOAD"
                for payload in OPEN_REDIR_PAYLOADS:
                    try:
                        test_url = base_url.replace("PAYLOAD", payload)
                        r = self._fetch(test_url, timeout=30, allow_redirects=False)
                        if r and r.status_code in (301,302,303,307,308) and 'evil.com' in r.headers.get('Location',''):
                            print(f"  [🔥] Vulnerable: {param}={payload}")
                            self._write({"open_redirect": test_url})
                    except: pass

    def dir_bruteforce(self, wordlist=None):
        print(f"\n--- Directory Bruteforce ---")
        dirs = ["admin","login","wp-admin","backup","uploads","api","graphql","swagger","config",".git","test","dev","staging","dashboard","panel"]
        if wordlist:
            with open(wordlist) as f:
                dirs = [l.strip() for l in f if l.strip()]
        def check_dir(d):
            url = f"{self.base}/{d}"
            try:
                r = self._fetch(url, timeout=20, allow_redirects=False)
                if r and r.status_code in (200,301,302,403):
                    print(f"  [{r.status_code}] {url}")
                    self._write({"directory": [url, r.status_code]})
            except: pass
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(check_dir, dirs)

    def xss_scan(self):
        print(f"\n--- XSS Scanner ---")
        try:
            r = self._fetch(self.base, timeout=60)
            if r is None: return
            soup = BeautifulSoup(r.text, 'html.parser')
            forms = soup.find_all('form')
            if not forms: return
            for form in forms:
                action = urljoin(self.base, form.get('action', ''))
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                data = {}
                for inp in inputs:
                    name = inp.get('name')
                    if name: data[name] = "test"
                for param in data:
                    for payload in XSS_PAYLOADS:
                        test_data = data.copy()
                        test_data[param] = payload
                        if method == 'post':
                            resp = self.session.post(action, data=test_data, timeout=30)
                        else:
                            resp = self._fetch(action, params=test_data, timeout=30)
                        if resp and payload in resp.text:
                            print(f"  [🔥] Reflected XSS on {param} with {payload}")
                            self._write({"xss": [action, param, payload]})
                            break
        except: pass

    def host_header_injection(self):
        print(f"\n--- Host Header Injection ---")
        headers = {"Host": "evil.com"}
        try:
            r = self._fetch(self.base, headers=headers, timeout=30, allow_redirects=True)
            if r and ("evil.com" in r.url or "evil.com" in r.text):
                print(f"  [🔥] Host Header Injection possible!")
                self._write({"host_header_injection": True})
        except: pass

    def bypass_403(self):
        print(f"\n--- 403 Bypass Check ---")
        test_paths = ["/admin", "/api", "/.git", "/wp-admin"]
        bypass_headers = {
            "X-Original-URL": "/",
            "X-Rewrite-URL": "/",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Host": "127.0.0.1",
        }
        for path in test_paths:
            url = self.base + path
            try:
                r = self._fetch(url, timeout=30)
                if r and r.status_code == 403:
                    for h, v in bypass_headers.items():
                        try:
                            r2 = self.session.get(self.base, headers={h: v}, timeout=30)
                            if r2.status_code != 403:
                                print(f"  [⚠️] Bypass with {h}: {v} -> {r2.status_code}")
                                self._write({"403bypass": [path, h, v, r2.status_code]})
                        except: pass
            except: pass

    def broken_links(self):
        print(f"\n--- Broken Links (internal) ---")
        try:
            r = self._fetch(self.base, timeout=60)
            if r is None: return
            soup = BeautifulSoup(r.text, 'html.parser')
            links = [urljoin(self.base, a['href']) for a in soup.find_all('a', href=True)]
            for link in set(links):
                if self.base in link:
                    try:
                        resp = self.session.head(link, timeout=15, allow_redirects=True)
                        if resp.status_code >= 400:
                            print(f"  [{resp.status_code}] {link}")
                    except: pass
        except: pass

    # =======================================================================
    # NEW SCANNERS (added)
    # =======================================================================
    def scan_admin_panels(self):
        print(f"\n--- Admin Panel Discovery ---")
        admin_paths = [
            "/admin", "/login", "/cpanel", "/wp-admin", "/administrator",
            "/admin.php", "/admin.aspx", "/admin.asp",
            "/backend", "/manage", "/management",
            "/phpMyAdmin", "/pma", "/mysql", "/sql",
            "/console", "/dashboard", "/panel", "/controlpanel",
            "/admin/login", "/admin/index", "/admin/dashboard",
            "/user/login", "/user/admin",
            "/auth/login", "/signin", "/signup",
        ]
        for path in admin_paths:
            url = self.base + path
            try:
                r = self._fetch(url, timeout=30, allow_redirects=False)
                if r and r.status_code in (200, 301, 302, 403):
                    print(f"  [{r.status_code}] {url}")
                    self._write({"admin_panel": [url, r.status_code]})
            except: pass

    def check_git_exposure(self):
        print(f"\n--- Git Exposure Check ---")
        test_url = self.base + "/.git/HEAD"
        try:
            r = self._fetch(test_url, timeout=30)
            if r and r.status_code == 200 and "ref:" in r.text:
                print(f"  [🔥] Git repository exposed: {test_url}")
                self._write({"git_exposed": test_url})
                # Try to fetch .git/config
                config_url = self.base + "/.git/config"
                r2 = self._fetch(config_url, timeout=30)
                if r2 and r2.status_code == 200:
                    print(f"  [🔥] Git config also accessible: {config_url}")
                    self._write({"git_config": config_url})
            else:
                print(f"  Git HEAD not accessible.")
        except: pass

    def check_http_methods(self):
        print(f"\n--- HTTP Methods Check ---")
        methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"]
        for method in methods:
            try:
                resp = self.session.request(method, self.base, timeout=30)
                if resp.status_code not in (405, 501):
                    print(f"  [⚠️] {method} allowed (status {resp.status_code})")
                    if method == "TRACE":
                        print(f"  [🔥] TRACE enabled – potential XST")
                        self._write({"trace_enabled": True})
            except: pass

    def check_cookie_flags(self):
        print(f"\n--- Cookie Security Flags ---")
        try:
            r = self._fetch_raw(self.base, timeout=60)
            if r is None: return
            for cookie in r.cookies:
                flags = []
                if not cookie.secure:
                    flags.append("Secure missing")
                if not getattr(cookie, 'has_nonstandard_attr', lambda x: False)('HttpOnly'):
                    flags.append("HttpOnly missing")
                if not getattr(cookie, 'has_nonstandard_attr', lambda x: False)('SameSite'):
                    flags.append("SameSite missing")
                if flags:
                    print(f"  [⚠️] {cookie.name}: {', '.join(flags)}")
                    self._write({"cookie_flags": {"name": cookie.name, "missing": flags}})
                else:
                    print(f"  [✓] {cookie.name}: flags ok")
        except: pass

    def check_backup_files(self):
        print(f"\n--- Backup Files Check ---")
        patterns = ["backup", "bak", "old", "copy", "~"]
        extensions = [".zip", ".tar.gz", ".tar", ".rar", ".7z", ".sql", ".txt"]
        for patt in patterns:
            for ext in extensions:
                url = f"{self.base}/{patt}{ext}"
                try:
                    r = self._fetch(url, timeout=30)
                    if r and r.status_code == 200:
                        print(f"  [🔥] Backup found: {url}")
                        self._write({"backup_file": url})
                except: pass

    def check_websocket(self):
        print(f"\n--- WebSocket Check ---")
        ws_url = self.base.replace("http://", "ws://").replace("https://", "wss://")
        try:
            import websocket
            ws = websocket.create_connection(ws_url, timeout=5)
            ws.close()
            print(f"  [✓] WebSocket endpoint alive: {ws_url}")
            self._write({"websocket": ws_url})
        except ImportError:
            print("  [!] websocket-client not installed (pip install websocket-client)")
        except Exception as e:
            print(f"  WebSocket not accessible: {e}")