import socket, json, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,5985,5986,6379,8080,8443,9000,9090,9200,27017]

class PortScanner:
    def __init__(self, ips, threads=20, verbose=False, output_file=None):
        self.ips = ips
        self.threads = threads
        self.verbose = verbose
        self.output = output_file or "ports.json"
        self.results = {}

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                banner = b''
                try:
                    sock.settimeout(0.5)
                    sock.send(b'GET / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024)
                except: pass
                sock.close()
                return port, banner.decode(errors='ignore')[:50]
        except: pass
        return None

    def scan(self):
        print(f"\n🔍 Port scanning {len(self.ips)} IPs...")
        for ip in self.ips:
            open_ports = []
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self.scan_port, ip, port): port for port in COMMON_PORTS}
                for fut in as_completed(futures):
                    res = fut.result()
                    if res:
                        port, banner = res
                        open_ports.append((port, banner))
                        print(f"  {ip}:{port} open  ({banner})")
            self.results[ip] = open_ports
        with open(self.output, 'w') as f:
            json.dump(self.results, f, indent=2)