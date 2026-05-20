#!/usr/bin/env python3
import argparse, sys, json, os, socket
from datetime import datetime
from colorama import init, Fore, Style
init()

from core.cvefinder import CVEScanner
from core.recon import Recon
from core.webscanner import WebScanner
from core.redteam import RedTeamScanner
from core.portscanner import PortScanner
from core.vulnerability import VulnerabilityScanner
from core.bruteforce import BruteForcer

BANNER = f"""{Fore.RED}
██╗     ██╗   ██╗██████╗  █████╗ ███╗   ██╗  ██████╗   ██████╗  ██╗  ██╗ ██████╗ 
██║     ██║   ██║██╔══██╗██╔══██╗████╗  ██║  ╚════██╗ ██╔═══██╗ ██║  ██║██╔═══██╗
██║     ██║   ██║██████╔╝███████║██╔██╗ ██║   █████╔╝ ██║   ██║ ███████║██║   ██║
██║     ██║   ██║██╔══██╗██╔══██║██║╚██╗██║  ██╔═══╝  ██║   ██║ ╚════██║██║   ██║
███████╗╚██████╔╝██████╔╝██║  ██║██║ ╚████║  ███████╗ ╚██████╔╝      ██║╚██████╔╝
╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝  ╚═════╝       ╚═╝ ╚═════╝
{Fore.YELLOW}                     v2  by m.alfahdi{Style.RESET_ALL}
"""
print(BANNER)

def resolve_ips_from_domain(domain):
    ips = set()
    try:
        ips.add(socket.gethostbyname(domain))
    except:
        pass
    try:
        import dns.resolver
        for rtype in ['A', 'MX', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    if rtype == 'MX':
                        ips.add(socket.gethostbyname(str(rdata.exchange).rstrip('.')))
                    elif rtype == 'NS':
                        ips.add(socket.gethostbyname(str(rdata.target).rstrip('.')))
                    else:
                        ips.add(str(rdata))
            except:
                pass
    except:
        pass
    return list(ips)

def main():
    parser = argparse.ArgumentParser(description="Luban 2040")
    shodan_group = parser.add_argument_group('Shodan (API key required)')
    shodan_group.add_argument("-q", "--query")
    shodan_group.add_argument("-org", "--organization")
    parser.add_argument("-host", "--hostname")
    parser.add_argument("-l", "--list")
    parser.add_argument("-web", "--webscan")
    parser.add_argument("-redteam", "--redteam")
    parser.add_argument("-o", "--output")
    parser.add_argument("-cvss", "--least-cvss", default=1.0, type=float)
    parser.add_argument("-v", "--verbose", action='store_true')
    parser.add_argument("-t", "--threads", default=10, type=int)
    parser.add_argument("--subs", action='store_true')
    parser.add_argument("--takeover", action='store_true')
    parser.add_argument("--wayback", action='store_true')
    parser.add_argument("--headers", action='store_true')
    parser.add_argument("--cors", action='store_true')
    parser.add_argument("--tech", action='store_true')
    parser.add_argument("--sensitive", action='store_true')
    parser.add_argument("--js", action='store_true')
    parser.add_argument("--redirect", action='store_true')
    parser.add_argument("--dirb", action='store_true')
    parser.add_argument("--xss", action='store_true')
    parser.add_argument("--sqli", action='store_true')
    parser.add_argument("--cmdi", action='store_true')
    parser.add_argument("--lfi", action='store_true')
    parser.add_argument("--idor", action='store_true')
    parser.add_argument("--graphql", action='store_true')
    # NEW ARGUMENTS
    parser.add_argument("--ssrf", action='store_true')
    parser.add_argument("--ssti", action='store_true')
    parser.add_argument("--portscan", action='store_true')
    parser.add_argument("--brute", action='store_true')
    parser.add_argument("--full-web", action='store_true')
    parser.add_argument("--full", action='store_true')

    args = parser.parse_args()
    base_output = args.output or f"Luban2040_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # API-key based Shodan
    if args.organization or args.query:
        try:
            with open('config.json') as f:
                api_key = json.load(f).get('api_key')
            if not api_key: raise
        except:
            print("[!] Shodan API key required in config.json")
            sys.exit(1)
        cve = CVEScanner(api_key, args.least_cvss, args.threads, args.verbose, base_output+"_cves.json")
        if args.organization:
            ips = cve.search_shodan('org', args.organization)
        else:
            ips = cve.search_shodan(None, args.query)
        print(f"[+] Found {len(ips)} IPs via Shodan")
        cve.scan_ips(ips)

    # Hostname (free DNS + CVE + Portscan + Vuln)
    if args.hostname:
        domain = args.hostname.rstrip('/')
        recon = Recon(domain, args.threads, args.verbose, base_output+"_recon.json")
        recon.dns_enum()
        subs = []
        if args.subs or args.full:
            subs = recon.subdomain_enum()
            if args.takeover or args.full:
                recon.takeover_check(subs)
        if args.wayback or args.full:
            recon.wayback_urls()

        ips = set(resolve_ips_from_domain(domain))
        if subs:
            for sub, ip in subs:
                ips.add(ip)
        ips = list(ips)
        print(f"[+] Resolved {len(ips)} IP(s)")

        if ips:
            # Port scanner
            if args.portscan or args.full:
                ps = PortScanner(ips, args.threads, args.verbose, base_output+"_ports.json")
                ps.scan()

            # CVE scan
            cve = CVEScanner(None, args.least_cvss, args.threads, args.verbose, base_output+"_cves.json")
            cve.scan_ips(ips)

        else:
            print("[!] No IPs resolved.")

    # Web Scanner (can be combined with host)
    if args.webscan or (args.full_web and args.hostname) or args.full:
        url = args.webscan if args.webscan else f"http://{args.hostname}"
        web = WebScanner(url, args.threads, args.verbose, base_output+"_web.json")
        vuln = VulnerabilityScanner(url, args.threads, args.verbose, base_output+"_vulns.json")

        if args.headers or args.full_web or args.full: web.headers_scan()
        if args.cors or args.full_web or args.full: web.cors_scan()
        if args.tech or args.full_web or args.full: web.tech_fingerprint()
        if args.sensitive or args.full_web or args.full: web.sensitive_files()
        if args.js or args.full_web or args.full: web.js_secrets()
        if args.redirect or args.full_web or args.full: web.open_redirect()
        if args.dirb or args.full_web or args.full: web.dir_bruteforce()
        if args.xss or args.full_web or args.full: vuln.scan_xss()
        if args.sqli or args.full_web or args.full: vuln.scan_sqli()
        if args.cmdi or args.full_web or args.full: vuln.scan_cmdi()
        if args.lfi or args.full_web or args.full: vuln.scan_lfi()
        if args.idor or args.full_web or args.full: vuln.scan_idor()
        if args.graphql or args.full_web or args.full: vuln.scan_graphql()
        # NEW SCANNERS
        if args.ssrf or args.full_web or args.full: vuln.scan_ssrf()
        if args.ssti or args.full_web or args.full: vuln.scan_ssti()
        web.host_header_injection()
        web.bypass_403()
        web.broken_links()
        web.scan_admin_panels()
        web.check_git_exposure()
        web.check_http_methods()
        web.check_cookie_flags()
        web.check_backup_files()

    # Red Team (standalone)
    if args.redteam:
        red = RedTeamScanner(args.redteam, output_file=base_output+"_redteam.json", verbose=args.verbose)
        red.run_all()

    # Brute force (if requested and target present)
    if args.brute:
        target = args.webscan or f"http://{args.hostname}" if args.hostname else args.redteam
        if target:
            bf = BruteForcer(target, args.threads, args.verbose, base_output+"_brute.json")
            bf.http_brute()
            bf.ssh_brute()
            bf.ftp_brute()

    print(f"\n[+] All done! Outputs in {base_output}*.json")

if __name__ == "__main__":
    main()