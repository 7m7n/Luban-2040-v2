import requests, re, time, json, urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import cloudscraper

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
VULNERS_API = "https://vulners.com/api/v3/search/id/"
EXPLOITDB_SEARCH = "https://www.exploit-db.com/search?cve={cve}&format=json"

def nvd_info(cve_id):
    result = {"description": "", "cvss": "N/A", "severity": ""}
    try:
        r = requests.get(NVD_API, params={"cveId": cve_id}, timeout=10,
                        headers={"User-Agent": "Luban2040/2.0"})
        if r.status_code == 200:
            data = r.json().get("vulnerabilities", [{}])[0].get("cve", {})
            for d in data.get("descriptions", []):
                if d.get("lang") == "en":
                    result["description"] = d.get("value", "")
                    break
            metrics = data.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    score_data = metrics[key][0].get("cvssData", {})
                    result["cvss"] = str(score_data.get("baseScore", "N/A"))
                    result["severity"] = score_data.get("baseSeverity", "")
                    break
    except:
        pass
    return result

def epss_score(cve_id):
    try:
        r = requests.get(f"{EPSS_API}?cve={cve_id}", timeout=8,
                         headers={"User-Agent": "Luban2040/2.0"})
        if r.status_code == 200:
            val = r.json().get("data", [{}])[0].get("epss")
            if val:
                return f"{round(float(val)*100,2)}%"
    except:
        pass
    return "N/A"

def vulners_lookup(cve_id):
    """Fetch exploit count, references, and additional description from Vulners."""
    try:
        resp = requests.get(f"{VULNERS_API}?id={cve_id}", timeout=10,
                            headers={"User-Agent": "Luban2040/2.0"})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("result") == "OK":
                docs = data.get("data", {}).get("documents", {})
                for doc_id, doc_info in docs.items():
                    exploit_count = doc_info.get("exploit", {}).get("count", 0)
                    refs = doc_info.get("references", [])
                    description = doc_info.get("description", "")
                    return {
                        "vulners_exploit_count": exploit_count,
                        "vulners_references": refs[:5],  # max 5
                        "vulners_description": description[:500]
                    }
    except:
        pass
    return {}

def exploitdb_search(cve_id):
    """Check if Exploit-DB has entries for the CVE."""
    try:
        url = EXPLOITDB_SEARCH.format(cve=cve_id)
        resp = requests.get(url, timeout=10,
                            headers={"User-Agent": "Luban2040/2.0"})
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("total", 0)
            if total > 0:
                # get first exploit ID
                exploit_id = data.get("data", [{}])[0].get("id", "")
                return {
                    "exploitdb_count": total,
                    "exploitdb_example": f"https://www.exploit-db.com/exploits/{exploit_id}" if exploit_id else ""
                }
    except:
        pass
    return {}

class CVEScanner:
    def __init__(self, api_key, min_cvss=1.0, threads=10, verbose=False, output_file=None):
        self.api_key = api_key
        self.min_cvss = float(min_cvss)
        self.threads = threads
        self.verbose = verbose
        self.output = output_file or f"CVEs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.query = None

    def _write_json(self, data):
        with open(self.output, 'a', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write('\n')

    def search_shodan(self, query_type, query):
        if query_type == 'org':
            self.query = f'org:"{query}"'
        elif query_type == 'hostname':
            self.query = f'hostname:"{query}"'
        else:
            self.query = query
        encoded = urllib.parse.quote(self.query, safe='')
        url = f"https://api.shodan.io/shodan/host/search?key={self.api_key}&query={encoded}&facets=ip"
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            raise Exception(f"Shodan error: {r.status_code} {r.text}")
        data = r.json()
        ips = list(set([m["ip_str"] for m in data.get("matches", [])]))
        return ips

    def scan_ips(self, ips):
        print(f"🔎 Scanning {len(ips)} IPs for CVEs...")
        def scan_one(ip):
            try:
                r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
                vulns = r.json().get('vulns', [])
                if vulns:
                    self._process_cves(ip, vulns)
            except Exception as e:
                if self.verbose:
                    print(f"  [!] {ip}: {e}")
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(scan_one, ip) for ip in ips]
            for _ in as_completed(futures):
                pass

    def _process_cves(self, ip, cves):
        scraper = cloudscraper.create_scraper()
        results = []
        for cve in cves:
            nvd = nvd_info(cve)
            cvss = nvd["cvss"]
            desc = nvd["description"] or "No desc"
            sev = nvd["severity"]
            try:
                if float(cvss) < self.min_cvss:
                    continue
            except:
                pass
            epss = epss_score(cve)
            # --- Additional databases ---
            vuln_extra = vulners_lookup(cve)
            exploitdb = exploitdb_search(cve)
            # --- Exploit status from cvedetails ---
            exploit = None
            try:
                r = scraper.get(f"https://www.cvedetails.com/cve/{cve}/", timeout=12)
                if 'Public exploit exists!' in r.text:
                    exploit = 'Public'
                elif 'Potential exploit' in r.text:
                    exploit = 'Potential'
            except:
                pass
            # --- Combine exploit info ---
            if not exploit:
                # if Vulners says exploit count > 0, mark as potential public
                if vuln_extra.get("vulners_exploit_count", 0) > 0:
                    exploit = 'Public (Vulners)'
                elif exploitdb.get("exploitdb_count", 0) > 0:
                    exploit = 'Public (Exploit-DB)'
            sev_label = f" [{sev}]" if sev else ""
            if exploit and 'PUBLIC' in exploit.upper():
                print(f"   [🔥] {cve} | CVSS {cvss}{sev_label} | EPSS {epss} | PUBLIC EXPLOIT!")
            elif exploit and 'Potential' in exploit:
                print(f"   [⚠️] {cve} | CVSS {cvss}{sev_label} | EPSS {epss} | Potential")
            else:
                print(f"   [*] {cve} | CVSS {cvss}{sev_label} | EPSS {epss}")
            # --- Build result entry ---
            entry = {
                "CVE": cve,
                "CVSS": cvss,
                "Severity": sev,
                "EPSS": epss,
                "Exploit": exploit,
                "Description": desc[:200],
                "Vulners": vuln_extra,
                "ExploitDB": exploitdb
            }
            results.append(entry)
            time.sleep(0.2)   # be nice to APIs
        if results:
            self._write_json({"IP": ip, "time": datetime.now().isoformat(), "CVEs": results})