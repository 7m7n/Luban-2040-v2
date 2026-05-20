"""
Intelligent HTTP fetching engine with anti‑bot bypass.
Supports browser fingerprint impersonation, JavaScript rendering,
session management, Cloudflare bypass, and adaptive element selection.
"""
import requests
import json
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional library for advanced stealth
try:
    from stealth_fetcher import Fetcher, StealthyFetcher, StealthySession, DynamicFetcher, DynamicSession
    HAS_STEALTH_LIB = True
except ImportError:
    HAS_STEALTH_LIB = False


class StealthScraper:
    """
    Intelligent fetching engine that automatically selects the best method:
    - Stealthy browser (bypass Cloudflare/WAF)
    - Dynamic browser (JavaScript‑heavy pages)
    - Fast HTTP (simple pages)
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self._stealth_session = None
        self._dynamic_session = None

    # ── Basic HTTP (fallback) ─────────────────────────
    def get(self, url, timeout=10, **kwargs):
        """Simple GET request with fallback."""
        try:
            return self.session.get(url, timeout=timeout, **kwargs)
        except Exception as e:
            if self.verbose:
                print(f"  [!] HTTP GET failed: {e}")
            return None

    def post(self, url, timeout=10, **kwargs):
        """Simple POST request with fallback."""
        try:
            return self.session.post(url, timeout=timeout, **kwargs)
        except Exception as e:
            if self.verbose:
                print(f"  [!] HTTP POST failed: {e}")
            return None

    # ── Stealthy Fetch (advanced) ─────────────────────
    def stealth_get(self, url, impersonate='chrome', timeout=60, **kwargs):
        if HAS_STEALTH_LIB:
            try:
                if self._stealth_session is None:
                    self._stealth_session = StealthySession(
                        headless=True,
                        solve_cloudflare=True,
                        impersonate=impersonate,
                    )
                page = self._stealth_session.fetch(
                    url,
                    timeout=timeout * 1000,      # ms
                    solve_cloudflare=True,
                    **kwargs,
                )
                return _StealthResponse(page)
            except Exception as e:
                if self.verbose:
                    print(f"  [!] Stealth fetch failed: {e}")
                return self.get(url, timeout=timeout)
        return self.get(url, timeout=timeout)

    # ── Dynamic Fetch (JavaScript rendering) ──────────
    def dynamic_get(self, url, timeout=15, wait_network_idle=True, **kwargs):
        """
        Fetch page with full JavaScript rendering.
        For SPAs and dynamic content that requires JS execution.
        """
        if HAS_STEALTH_LIB:
            try:
                if self._dynamic_session is None:
                    self._dynamic_session = DynamicSession(
                        headless=True,
                        disable_resources=False,
                        network_idle=wait_network_idle
                    )
                page = self._dynamic_session.fetch(url, timeout=timeout, **kwargs)
                return _StealthResponse(page)
            except Exception as e:
                if self.verbose:
                    print(f"  [!] Dynamic fetch failed, falling back: {e}")
                return self.get(url, timeout=timeout)
        return self.get(url, timeout=timeout)

    # ── Cloudflare‑specific bypass ────────────────────
    def cloudflare_bypass(self, url, timeout=30):
        """
        Specifically designed to bypass Cloudflare Turnstile/Interstitial.
        """
        if HAS_STEALTH_LIB:
            try:
                page = StealthyFetcher.fetch(
                    url,
                    headless=True,
                    solve_cloudflare=True,
                    network_idle=True,
                    timeout=timeout
                )
                print(f"  [+] Cloudflare bypassed successfully")
                return _StealthResponse(page)
            except Exception as e:
                if self.verbose:
                    print(f"  [!] Cloudflare bypass failed: {e}")
                return self.get(url, timeout=timeout)
        resp = self.get(url, timeout=timeout)
        if resp and 'cf-browser-verification' in resp.text.lower():
            print(f"  [⚠️] Cloudflare detected (install optional fetcher for bypass)")
        return resp

    # ── WAF Detection ─────────────────────────────────
    def detect_waf(self, url):
        """Detect if target is behind a WAF/CDN."""
        resp = self.get(url)
        if not resp:
            return None

        waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cf-chl-out', 'cf-browser-verification'],
            'Akamai': ['akamai', 'akamai-gtm'],
            'Imperva': ['imperva', 'incapsula'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'AWS WAF': ['x-amzn-requestid', 'aws'],
            'F5': ['f5', 'big-ip'],
            'Barracuda': ['barracuda'],
            'Fortinet': ['fortinet', 'fortiguard'],
        }

        headers_str = str(resp.headers).lower()
        body_str = resp.text[:2000].lower() if hasattr(resp, 'text') else ''

        detected = []
        for waf, sigs in waf_signatures.items():
            for sig in sigs:
                if sig in headers_str or sig in body_str:
                    detected.append(waf)
                    break

        if detected:
            print(f"  [⚠️] WAF detected: {', '.join(detected)}")
        return detected if detected else None

    # ── Multi‑page crawl ──────────────────────────────
    def crawl_page(self, url, max_pages=10, same_domain=True):
        """
        Crawl a page and collect all internal links.
        Returns list of discovered URLs.
        """
        discovered = set()
        domain = urlparse(url).netloc

        def process_page(page_url):
            if len(discovered) >= max_pages:
                return
            resp = self.get(page_url)
            if not resp or not hasattr(resp, 'text'):
                return
            import re
            links = re.findall(r'href=["\'](.*?)["\']', resp.text)
            for link in links:
                full_url = urljoin(page_url, link)
                if same_domain and urlparse(full_url).netloc != domain:
                    continue
                if full_url not in discovered:
                    discovered.add(full_url)

        discovered.add(url)
        process_page(url)

        urls_to_process = list(discovered)[:max_pages]
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = [ex.submit(process_page, u) for u in urls_to_process]
            for _ in as_completed(futures):
                pass

        print(f"  [+] Crawled {len(discovered)} URLs from {domain}")
        return list(discovered)[:max_pages]

    # ── Adaptive text extraction ──────────────────────
    def extract_text(self, url, css_selector=None, regex=None):
        """
        Extract text content from page using CSS selector or regex.
        """
        resp = self.get(url)
        if not resp or not hasattr(resp, 'text'):
            return None

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, 'html.parser')

        if css_selector:
            elements = soup.select(css_selector)
            text = ' '.join([el.get_text(strip=True) for el in elements])
        else:
            text = soup.get_text(separator=' ', strip=True)

        if regex:
            import re
            matches = re.findall(regex, text)
            return matches

        return text

    # ── Page change detection ─────────────────────────
    def detect_page_changes(self, url, original_content, timeout=10):
        """
        Check if page content has changed from original.
        Returns similarity score (0.0 to 1.0).
        """
        resp = self.get(url, timeout=timeout)
        if not resp or not hasattr(resp, 'text'):
            return 0.0

        original_words = set(original_content.lower().split())
        new_words = set(resp.text.lower().split())

        if not original_words or not new_words:
            return 0.0

        intersection = original_words.intersection(new_words)
        union = original_words.union(new_words)
        similarity = len(intersection) / len(union) if union else 0.0
        return round(similarity, 3)

    # ── Session management ────────────────────────────
    def create_persistent_session(self, impersonate='chrome'):
        """
        Create a persistent session with cookie storage.
        """
        if HAS_STEALTH_LIB:
            self._stealth_session = StealthySession(
                headless=True,
                solve_cloudflare=True,
                impersonate=impersonate
            )
            return self._stealth_session
        return self.session

    def close_sessions(self):
        """Close all active sessions."""
        if self._stealth_session and hasattr(self._stealth_session, 'close'):
            try:
                self._stealth_session.close()
            except:
                pass
        if self._dynamic_session and hasattr(self._dynamic_session, 'close'):
            try:
                self._dynamic_session.close()
            except:
                pass

    # ── Fingerprint rotation ──────────────────────────
    def rotate_fingerprint(self):
        """Rotate browser fingerprint for next requests."""
        browser_profiles = [
            {'impersonate': 'chrome', 'platform': 'Windows'},
            {'impersonate': 'chrome', 'platform': 'macOS'},
            {'impersonate': 'firefox', 'platform': 'Windows'},
            {'impersonate': 'edge', 'platform': 'Windows'},
            {'impersonate': 'safari', 'platform': 'macOS'},
        ]
        import random
        profile = random.choice(browser_profiles)

        if HAS_STEALTH_LIB:
            self._stealth_session = StealthySession(
                headless=True,
                solve_cloudflare=True,
                impersonate=profile['impersonate']
            )
            if self.verbose:
                print(f"  [*] Rotated to {profile['impersonate']} / {profile['platform']}")

        ua_map = {
            'chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'firefox': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'edge': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
            'safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
        }
        self.session.headers.update({
            'User-Agent': ua_map.get(profile['impersonate'], ua_map['chrome'])
        })
        return profile


class _StealthResponse:
    """
    Adapter to make fetcher responses compatible with requests.Response.
    """
    def __init__(self, scrapling_page):
        self._page = scrapling_page
        self._text = None
        self._status_code = 200
        self._headers = {}
        self._url = ''
        self._elapsed = type('obj', (object,), {'total_seconds': lambda: 0})()

        try:
            self._text = self._page.text if hasattr(self._page, 'text') else str(self._page)
        except:
            self._text = str(self._page)

        try:
            self._url = self._page.url if hasattr(self._page, 'url') else ''
        except:
            pass

        try:
            self._status_code = self._page.status_code if hasattr(self._page, 'status_code') else 200
        except:
            pass

    @property
    def text(self):
        return self._text or ''

    @property
    def content(self):
        return (self._text or '').encode('utf-8')

    @property
    def status_code(self):
        return self._status_code

    @property
    def headers(self):
        return self._headers

    @property
    def url(self):
        return self._url

    @property
    def elapsed(self):
        return self._elapsed

    def json(self):
        try:
            return json.loads(self._text)
        except:
            return {}