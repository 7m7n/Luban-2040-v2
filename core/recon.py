import requests, socket, dns.resolver, json, time, urllib.parse, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from core.stealth import StealthScraper

# Comprehensive takeover fingerprints (30+ services)
TAKEOVER_SIGNATURES = {
    "github.io": ["There isn't a GitHub Pages site here."],
    "herokuapp.com": ["No such app"],
    "netlify.app": ["Not Found"],
    "shopify.com": ["Sorry, this shop is currently unavailable."],
    "tumblr.com": ["Whatever you were looking for doesn't exist."],
    "wordpress.com": ["Do you want to register"],
    "azurewebsites.net": ["404 Web Site not found."],
    "s3.amazonaws.com": ["The specified bucket does not exist"],
    "cloudfront.net": ["Bad request."],
    "azureedge.net": ["404 - Web site not found"],
    "unbounce.com": ["The requested URL was not found on this server."],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["Repository not found"],
    "pantheonsite.io": ["404 Site not found"],
    "fly.dev": ["404 - Page not found"],
    "vercel.app": ["DEPLOYMENT_NOT_FOUND"],
    "cargo.site": ["404 - Page not found"],
    "crisp.chat": ["We can't find this resource"],
    "ghost.org": ["Domain not found"],
    "helpscoutdocs.com": ["The page you are looking for doesn't exist"],
    "helpjuice.com": ["404 Page not found"],
    "helpscout.net": ["404 - Page not found"],
    "intercom.com": ["Oops. Something went wrong."],
    "launchrock.com": ["It looks like you may have followed a broken link"],
    "readme.io": ["Project not found"],
    "tilda.ws": ["Domain doesn't exist"],
    "uservoice.com": ["Can't find that page"],
    "zendesk.com": ["Help Centre is not available"],
    "zohosites.com": ["404 Not Found"],
    "acquia-sites.com": ["No site found"],
    "customers.makeshop.jp": ["Not Found"],
    "landingi.com": ["404 Not Found"],
    "bigcartel.com": ["Not found"],
    "sendgrid.com": ["Not Found"],
    "activehosted.com": ["Not Found"],
    "campaignmonitor.com": ["No site found"],
    "createsend.com": ["The page you're looking for cannot be found"],
    "statistics.com": ["The page you're looking for does not exist"],
    "feedburner.com": ["The feed does not have subscriptions"],
    "typepad.com": ["Not Found"],
    "hatenablog.com": ["404 Not Found"],
    "freshdesk.com": ["404 Not Found"],
    "canny.io": ["Not Found"],
}

DEFAULT_SUBS = ["www","mail","ftp","dev","api","staging","admin","test","vpn","portal","shop","blog","cdn","ns1","ns2","backup","beta","db"]

class Recon:
    def __init__(self, domain, threads=10, verbose=False, output_file=None):
        self.domain = domain
        self.threads = threads
        self.verbose = verbose
        self.output = output_file or f"Recon_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.scraper = StealthScraper(verbose=verbose)

    def _write(self, data):
        with open(self.output, 'a', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
            f.write('\n')

    def dns_enum(self):
        print(f"\n--- DNS Records for {self.domain} ---")
        records = {}
        for rtype in ['A','AAAA','MX','NS','TXT','CNAME','SOA']:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records[rtype] = [str(r) for r in answers]
                for val in records[rtype]:
                    print(f"  {rtype}: {val}")
            except: pass
        self._write({"dns":{self.domain:records}})
        return records

    def subdomain_enum(self, wordlist=None):
        print(f"\n--- Subdomain Enumeration for {self.domain} ---")
        if wordlist:
            with open(wordlist) as f:
                words = [l.strip() for l in f if l.strip()]
        else:
            words = DEFAULT_SUBS
        subs = []
        def resolve(sub):
            fqdn = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                print(f"  [+] {fqdn} -> {ip}")
                return fqdn, ip
            except: return None
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(resolve, w): w for w in words}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    subs.append(res)
        self._write({"subdomains": subs})
        return subs

    def takeover_check(self, subdomains):
        print(f"\n--- Subdomain Takeover Check ---")
        for sd, _ in subdomains:
            try:
                # Resolve CNAME
                answers = dns.resolver.resolve(sd, 'CNAME')
                cname = str(answers[0].target).rstrip('.')
            except:
                continue

            for service, fingerprints in TAKEOVER_SIGNATURES.items():
                if service not in cname:
                    continue

                # Attempt to contact the subdomain with enhanced checks
                for attempt in range(1, 4):  # up to 3 retries
                    try:
                        # Try HTTPS first, then HTTP
                        for protocol in ['https', 'http']:
                            url = f"{protocol}://{sd}"
                            # Use stealth engine for WAF bypass
                            resp = self.scraper.stealth_get(url, timeout=8, allow_redirects=False)
                            if resp is None:
                                continue

                            # Check status code (must be 4xx)
                            if resp.status_code < 400 or resp.status_code >= 500:
                                continue

                            # Check fingerprints
                            for fp in fingerprints:
                                if fp.lower() in resp.text.lower():
                                    print(f"  [🔥] {sd} -> {cname} VULNERABLE ({service}) [status={resp.status_code}]")
                                    self._write({"takeover":[{"subdomain":sd, "cname":cname, "service":service, "vulnerable":True, "status_code":resp.status_code}]})
                                    return  # found, move to next subdomain
                        break  # if succeeded, exit retry loop
                    except Exception as e:
                        if self.verbose:
                            print(f"  [!] Attempt {attempt} failed for {sd}: {e}")
                        if attempt == 3:
                            continue  # tried all attempts
                        time.sleep(1)  # short delay before retry
            # Subtle: if we reach here, no vulnerability for this subdomain
        # All subdomains checked
        print("  [+] Takeover check complete.")

    def wayback_urls(self):
        print(f"\n--- Wayback URLs from 6 sources ---")
        urls = set()
        onion_links = set()

        def fetch_source(source_name, fetcher):
            try:
                fetcher()
            except Exception as e:
                print(f"  [-] {source_name}: {e}")

        # 1. Wayback Machine (CDX)
        def wayback():
            param = {'url': f"{self.domain}/*", 'output': 'json', 'fl': 'original', 'collapse': 'urlkey', 'limit': '5000'}
            r = requests.get("http://web.archive.org/cdx/search/cdx", params=param, timeout=60)
            for line in r.text.splitlines():
                try:
                    url = json.loads(line)[0]
                    urls.add(url)
                    if '.onion' in url:
                        onion_links.add(url)
                except: pass
        # 2. Wayback Machine (timemap) – additional source
        def wayback_timemap():
            r = requests.get(f"https://web.archive.org/web/timemap/link/{self.domain}", timeout=30)
            for line in r.text.splitlines():
                if line.startswith('<') and '>' in line:
                    url = line.split(';')[0].strip('<>')
                    if self.domain in url:
                        urls.add(url)
                        if '.onion' in url:
                            onion_links.add(url)

        # 3. CommonCrawl (latest index)
        def commoncrawl():
            r = requests.get(f"https://index.commoncrawl.org/CC-MAIN-2023-50-index?url={self.domain}/*&output=json", timeout=60)
            for line in r.text.splitlines():
                try:
                    url = json.loads(line)['url']
                    urls.add(url)
                    if '.onion' in url:
                        onion_links.add(url)
                except: pass

        # 4. AlienVault OTX
        def alienvault():
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list?limit=500", timeout=30)
            for obj in r.json().get('url_list', []):
                if 'url' in obj:
                    urls.add(obj['url'])
                    if '.onion' in obj['url']:
                        onion_links.add(obj['url'])

        # 5. URLScan.io
        def urlscan():
            r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000", timeout=30)
            for result in r.json().get('results', []):
                if 'page' in result:
                    url = result['page']['url']
                    urls.add(url)
                    if '.onion' in url:
                        onion_links.add(url)

        # 6. VirusTotal
        def virustotal():
            r = requests.get(f"https://www.virustotal.com/ui/domains/{self.domain}/urls?limit=40", timeout=30)
            for item in r.json().get('data', []):
                if 'id' in item:
                    urls.add(item['id'])
                    if '.onion' in item['id']:
                        onion_links.add(item['id'])

        # 7. GhostArchive
        def ghostarchive():
            r = requests.get(f"https://ghostarchive.org/search?q={self.domain}&type=url", timeout=30)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.select('a[href]'):
                href = a['href']
                if self.domain in href:
                    urls.add(href)
                    if '.onion' in href:
                        onion_links.add(href)

        sources = [
            ("Wayback CDX", wayback),
            ("Wayback Timemap", wayback_timemap),
            ("CommonCrawl", commoncrawl),
            ("AlienVault OTX", alienvault),
            ("URLScan.io", urlscan),
            ("VirusTotal", virustotal),
            ("GhostArchive", ghostarchive),
        ]

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(fetch_source, name, func) for name, func in sources]
            for _ in as_completed(futures):
                pass

        print(f"  Collected {len(urls)} URLs.")
        self._write({"wayback_urls": list(urls)})

        if onion_links:
            print(f"  [🧅] Found {len(onion_links)} .onion links!")
            self._write({"onion_links": list(onion_links)})

        return list(urls)

    def extract_onion_links(self, url_list):
        """Extract .onion URLs from any list of URLs."""
        return [u for u in url_list if '.onion' in u]