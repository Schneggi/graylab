#!/usr/bin/env python3
"""GrayLab Backend: serviert die Web-UI und liefert Port-Scanner + Hashes (nur Standardbibliothek)."""
import hashlib, json, os, platform, socket, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
HOST, PORT = "127.0.0.1", 8080  # nur lokal erreichbar
SERVICES = {20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"}
RISKY = {21, 23, 135, 139, 445, 3389, 5900, 6379, 27017}


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
                        out({"t": "open", "port": port, "svc": SERVICES.get(port, "unbekannt"),
                             "risk": port in RISKY})
                    pct = done * 100 // total
                    if pct != last:
                        last = pct
                        out({"t": "p", "v": pct})
            out({"t": "done", "open": opened, "secs": round(time.time() - t0, 1)})
        except (BrokenPipeError, ConnectionError, OSError):
            stop.set()  # Client hat abgebrochen


if __name__ == "__main__":
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"GrayLab läuft: http://{HOST}:{PORT}  (Strg+C zum Beenden)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)