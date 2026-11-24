#!/usr/bin/env python3
"""GrayLab Backend: serviert die Web-UI und liefert Port-Scanner + Hashes (nur Standardbibliothek)."""
import csv, hashlib, io, json, os, platform, socket, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
HOST, PORT = "127.0.0.1", 8080  # nur lokal erreichbar
SERVICES_FILE = os.path.join(HERE, "services.json")
IANA_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
BUILTIN = {20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
           110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
           993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
           5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"}


def load_services():
    s = {}
    try:
        with open(SERVICES_FILE, encoding="utf-8") as f:
            s = {int(k): v for k, v in json.load(f).items()}
    except (OSError, ValueError):
        pass
    s.update(BUILTIN)  # eigene Namen haben Vorrang
    return s


SERVICES = load_services()


def service_name(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unbekannt"


def parse_iana(text):
    """IANA-CSV -> {port: name} (nur TCP, erster Name pro Port, Bereiche werden aufgelöst)."""
    out = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3 or row[2].lower() != "tcp" or not row[1].strip():
            continue
        name, ports = row[0].strip(), row[1].strip()
        try:
            lo, _, hi = ports.partition("-")
            for p in range(int(lo), int(hi or lo) + 1):
                if name:
                    out.setdefault(p, name)
        except ValueError:
            continue
    return out


def update_services():
    import urllib.request
    print("Lade IANA-Liste ...")
    with urllib.request.urlopen(IANA_URL, timeout=30) as r:
        data = parse_iana(r.read().decode("utf-8", "replace"))
    with open(SERVICES_FILE, "w", encoding="utf-8") as f:
        json.dump({str(k): v for k, v in sorted(data.items())}, f)
    print(f"{len(data)} Ports gespeichert in services.json")


# Ports, die offen ein Risiko sein können -> Begründung (Anzeige im Scanner)
RISKY = {
    21: "FTP: unverschlüsselt, Passwörter im Klartext",
    23: "Telnet: unverschlüsselter Fernzugriff",
    25: "SMTP: Missbrauch als Spam-Relay möglich",
    79: "Finger: verrät Benutzerinfos",
    110: "POP3: Passwörter im Klartext",
    111: "RPC-Portmapper: große Angriffsfläche",
    135: "MS-RPC: häufiges Windows-Angriffsziel",
    137: "NetBIOS: Informationslecks",
    139: "NetBIOS/SMB: Informationslecks, Angriffe",
    143: "IMAP: Passwörter im Klartext",
    389: "LDAP: unverschlüsselt, Verzeichnisdaten auslesbar",
    445: "SMB: Ransomware/Würmer (z. B. EternalBlue)",
    512: "rexec: unverschlüsselt, schwache Anmeldung",
    513: "rlogin: unverschlüsselt, schwache Anmeldung",
    514: "rsh: unverschlüsselt, schwache Anmeldung",
    873: "rsync: oft ohne Passwort erreichbar",
    1080: "SOCKS-Proxy: Missbrauch als offener Proxy",
    1433: "MSSQL: Datenbank direkt erreichbar",
    1521: "Oracle-DB: Datenbank direkt erreichbar",
    1723: "PPTP: veraltetes, unsicheres VPN",
    1883: "MQTT: oft ohne Anmeldung/Verschlüsselung",
    2049: "NFS: Dateifreigaben oft zu offen",
    2181: "ZooKeeper: oft ohne Anmeldung",
    2323: "Telnet (alternativ): von Mirai-Botnetzen ausgenutzt",
    2375: "Docker-API unverschlüsselt: Vollzugriff auf Host",
    3128: "Squid-Proxy: Missbrauch als offener Proxy",
    3306: "MySQL: Datenbank direkt erreichbar",
    3389: "RDP: Brute-Force und Ransomware-Einfallstor",
    4444: "Häufig von Backdoors/Reverse-Shells genutzt",
    5037: "ADB: Android-Gerätesteuerung",
    5432: "PostgreSQL: Datenbank direkt erreichbar",
    5555: "ADB über WLAN: Android-Fernsteuerung ohne Passwort",
    5601: "Kibana: oft ohne Anmeldung",
    5900: "VNC: schwache oder keine Anmeldung",
    5901: "VNC: schwache oder keine Anmeldung",
    5902: "VNC: schwache oder keine Anmeldung",
    5984: "CouchDB: oft ohne Anmeldung",
    5985: "WinRM (HTTP): Fernverwaltung im Klartext",
    6000: "X11: unverschlüsselter Bildschirmzugriff",
    6379: "Redis: oft ohne Passwort",
    6667: "IRC: häufig von Botnetzen genutzt",
    7547: "TR-069: Router-Fernwartung, Mirai-Ziel",
    9200: "Elasticsearch: oft ohne Anmeldung",
    9300: "Elasticsearch-Cluster: oft ohne Anmeldung",
    10000: "Webmin: Admin-Oberfläche",
    10250: "Kubelet-API: Zugriff auf Container",
    11211: "Memcached: ohne Anmeldung, DDoS-Verstärkung",
    15672: "RabbitMQ-Verwaltung: Standard-Login guest/guest",
    27017: "MongoDB: oft ohne Anmeldung",
    27018: "MongoDB-Shard: oft ohne Anmeldung",
    31337: "Klassischer Backdoor-Port (Back Orifice)",
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send_json(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif u.path == "/api/info":
            try:
                ip = socket.gethostbyname(socket.gethostname())
            except OSError:
                ip = "unbekannt"
            self.send_json({"Hostname": socket.gethostname(), "Lokale IP": ip,
                            "System": f"{platform.system()} {platform.release()}",
                            "Architektur": platform.machine(), "Python": platform.python_version()})
        elif u.path == "/api/scan":
            self.scan(parse_qs(u.query))
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/api/hash":
            return self.send_error(404)
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n)
        self.send_json({"SHA3-256": hashlib.sha3_256(data).hexdigest(),
                        "BLAKE2b": hashlib.blake2b(data).hexdigest()})

    def scan(self, q):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        def out(o):
            self.wfile.write((json.dumps(o) + "\n").encode())
            self.wfile.flush()

        try:
            host = q["host"][0]
            start, end = int(q["start"][0]), int(q["end"][0])
            timeout = min(max(int(q.get("timeout", ["400"])[0]), 100), 5000) / 1000
            if not (1 <= start <= end <= 65535):
                return out({"t": "err", "msg": "Ungültiger Portbereich"})
            ip = socket.gethostbyname(host)
        except (KeyError, ValueError):
            return out({"t": "err", "msg": "Ungültige Eingabe"})
        except OSError:
            return out({"t": "err", "msg": "Host nicht auflösbar"})

        stop = threading.Event()

        def check(port):
            if stop.is_set():
                return port, False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    return port, s.connect_ex((ip, port)) == 0
            except OSError:
                return port, False

        total, done, opened, last, t0 = end - start + 1, 0, 0, -1, time.time()
        try:
            with ThreadPoolExecutor(max_workers=200) as ex:
                for port, is_open in ex.map(check, range(start, end + 1)):
                    done += 1
                    if is_open:
                        opened += 1
                        out({"t": "open", "port": port, "svc": service_name(port),
                             "risk": port in RISKY, "why": RISKY.get(port, "")})
                    pct = done * 100 // total
                    if pct != last:
                        last = pct
                        out({"t": "p", "v": pct})
            out({"t": "done", "open": opened, "secs": round(time.time() - t0, 1)})
        except (BrokenPipeError, ConnectionError, OSError):
            stop.set()  # Client hat abgebrochen


if __name__ == "__main__":
    if "--update-services" in sys.argv:
        update_services()
        sys.exit(0)
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"GrayLab läuft: http://{HOST}:{PORT}  (Strg+C zum Beenden)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)