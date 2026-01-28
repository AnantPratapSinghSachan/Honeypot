#!/usr/bin/env python3
# Simple local honeypot: HTTP login trap, TCP listeners, ICMP echo snifferimport csv
import os
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs
from collections import Counter, deque

# Configuration
BIND_IP = "0.0.0.0"
HTTP_PORT = int(os.getenv("HONEYPOT_HTTP_PORT", "8080"))

DEFAULT_TCP_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5900, 8081, 2222, 2323]
TCP_PORTS = [int(p) for p in os.getenv("HONEYPOT_TCP_PORTS", ",".join(map(str, DEFAULT_TCP_PORTS))).split(",") if p]
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

rl_honeypot = None

LOGIN_CSV = os.path.join(LOG_DIR, "login_attempts.csv")
HTTP_CONN_CSV = os.path.join(LOG_DIR, "http_connections.csv")
TCP_CONN_CSV = os.path.join(LOG_DIR, "tcp_connects.csv")
ICMP_CSV = os.path.join(LOG_DIR, "icmp_echo.csv")
ALERTS_CSV = os.path.join(LOG_DIR, "alerts.csv")

os.makedirs(LOG_DIR, exist_ok=True)


_file_locks = {}
_file_locks_lock = threading.Lock()


ATTEMPT_WINDOW = 60  
ATTEMPT_THRESHOLD = 10
_attempts: dict[str, deque] = {}
_attempts_lock = threading.Lock()
_last_alert: dict[str, float] = {}
# Throttle Flag
THROTTLE_EVT = threading.Event()

def _get_lock(file_path: str) -> threading.Lock:
    with _file_locks_lock:
        if file_path not in _file_locks:
            _file_locks[file_path] = threading.Lock()
        return _file_locks[file_path]


def _ensure_header(file_path: str, headers: list[str]):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        with open(file_path, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)


def write_csv(file_path: str, headers: list[str], row: list):
    lock = _get_lock(file_path)
    with lock:
        _ensure_header(file_path, headers)
        with open(file_path, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(row)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def record_attempt(ip: str, category: str):
    now = time.time()
    with _attempts_lock:
        dq = _attempts.get(ip)
        if dq is None:
            dq = deque()
            _attempts[ip] = dq
        
        cutoff = now - ATTEMPT_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        count = len(dq)
        if count > ATTEMPT_THRESHOLD:
            last = _last_alert.get(ip, 0)
            if now - last > 15: 
                _last_alert[ip] = now
                write_csv(
                    ALERTS_CSV,
                    ["timestamp","ip","category","count_last_60s","note"],
                    [now_iso(), ip, category, count, "brute_force_suspected"]
                )
                print(f"[ALERT] Brute-force suspected from {ip}: {count} attempts/60s ({category})")


# HTTP Honeypot
from http.server import BaseHTTPRequestHandler
try:
    
    from http.server import ThreadingHTTPServer as _HTTPServer
except Exception:
    from http.server import HTTPServer
    from socketserver import ThreadingMixIn
    class _HTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

LOGIN_PAGE = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Account Login</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; }
      .card { max-width: 360px; padding: 1.5rem; border: 1px solid #ddd; border-radius: 8px; }
      label { display:block; margin: .5rem 0 .25rem; }
      input { width:100%; padding:.5rem; }
      button { margin-top: 1rem; padding:.6rem 1rem; }
    </style>
  </head>
  <body>
    <div class="card">
      <h2>Sign in</h2>
      <form method="post" action="/login">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required />
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required />
        <button type="submit">Login</button>
      </form>
    </div>
  </body>
</html>
"""

class HPHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.57"
    sys_version = ""

    def _log_http(self, method: str):
        ua = self.headers.get('User-Agent', '')
        write_csv(
            HTTP_CONN_CSV,
            ["timestamp","client_ip","method","path","user_agent"],
            [now_iso(), self.client_address[0], method, self.path, ua]
        )

    def do_GET(self):
        # New Debug
                print(f"\n[RAW REQUEST] Received GET request. Full Path: '{self.path}'")
        # End of Debug Line

        # RL Agent Hook
        if rl_honeypot:
            try:
                event_type = 'http_request'
                ip = self.client_address[0]
                data = {
                    'method': 'GET',
                    'path': self.path,
                    'user_agent': self.headers.get('User-Agent', '')
                }
                response = rl_honeypot.process_event(event_type, ip, data)
                
                # work on agent decision
                if response.get('action') == 'block':
                    self.send_error(403, "Forbidden")
                    return
                if response.get('action') == 'tarpit':
                    time.sleep(response.get('delay', 10.0))
                elif response.get('delay', 0) > 0:
                    time.sleep(response.get('delay'))
            except Exception as e:
                print(f"[RL-HOOK-ERR] {e}")
        # end of RL Hook
        
        self._log_http("GET")
        path = self.path.split("?")[0]
        if path in ("/", "/index.html", "/login"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(LOGIN_PAGE.encode("utf-8"))
            return
        if path == "/favicon.ico":
            
            self.send_response(204)
            self.send_header("Content-Type", "image/x-icon")
            self.end_headers()
            return
        
        body = f"<html><body><h1>404 Not Found</h1><p>{path} not found.</p></body></html>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body.encode('utf-8'))))
        self.end_headers()
        try:
            self.wfile.write(body.encode("utf-8"))
        except Exception:
            pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', 'ignore') if length else ''
        params = parse_qs(body)
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]

        # RL Agent Hook
        if rl_honeypot:
            try:
                event_type = 'http_request'
                ip = self.client_address[0]
                data = {
                    'method': 'POST',
                    'path': self.path,
                    'user_agent': self.headers.get('User-Agent', ''),
                    'username': username,
                    'password': password
                }
                if self.path.startswith('/login'):
                    event_type = 'login_attempt'

                response = rl_honeypot.process_event(event_type, ip, data)
                
                # Works on Agent's decision
                if response.get('action') == 'block':
                    self.send_error(403, "Forbidden")
                    return
                if response.get('action') == 'tarpit':
                    time.sleep(response.get('delay', 10.0))
                elif response.get('delay', 0) > 0:
                    time.sleep(response.get('delay'))
            except Exception as e:
                print(f"[RL-HOOK-ERR] {e}")
        # End of RL hook

        self._log_http("POST")
        
        if self.path.startswith('/login'):
            ua = self.headers.get('User-Agent', '')
            write_csv(
                LOGIN_CSV,
                ["timestamp","client_ip","user_agent","username","password"],
                [now_iso(), self.client_address[0], ua, username, password]
            )
            record_attempt(self.client_address[0], 'http_login')
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        
        body404 = f"<html><body><h1>404 Not Found</h1><p>{self.path} not found.</p></body></html>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body404.encode('utf-8'))))
        self.end_headers()
        try:
            self.wfile.write(body404.encode("utf-8"))
        except Exception:
            pass

    def log_message(self, format, *args):
        
        pass


def run_http_server():
    httpd = _HTTPServer((BIND_IP, HTTP_PORT), HPHandler)
    print(f"[HTTP] Listening on {BIND_IP}:{HTTP_PORT}")
    httpd.serve_forever()

# TCP Listener Honeypot


def recv_line(sock: socket.socket, timeout: float = 3.0, maxlen: int = 512) -> str:
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < maxlen:
            ch = sock.recv(1)
            if not ch:
                break
            data += ch
            if ch in (b"\n", b"\r"):
                break
    except Exception:
        pass
    try:
        return data.decode('utf-8', 'ignore').strip()
    except Exception:
        return ""


def ftp_session(conn: socket.socket, addr):
    try:
        conn.sendall(b"220 FTP Service ready\r\n")
        line = recv_line(conn)
        if line.upper().startswith("USER "):
            user = line.split(" ", 1)[1]
            conn.sendall(f"331 Password required for {user}\r\n".encode('utf-8'))
            _ = recv_line(conn)
            conn.sendall(b"530 Login incorrect\r\n")
        else:
            conn.sendall(b"500 Syntax error, command unrecognized\r\n")
    except Exception:
        pass


def telnet_session(conn: socket.socket, addr):
    try:
        conn.sendall(b"login: ")
        _ = recv_line(conn)
        conn.sendall(b"Password: ")
        _ = recv_line(conn)
        conn.sendall(b"Login incorrect\r\n")
    except Exception:
        pass


def smtp_session(conn: socket.socket, addr):
    try:
        conn.sendall(b"220 mail.local ESMTP ready\r\n")
        line = recv_line(conn)
        u = line.upper()
        if u.startswith("EHLO ") or u.startswith("HELO "):
            conn.sendall(b"250 Hello\r\n")
        else:
            conn.sendall(b"500 5.5.2 Syntax error, command unrecognized\r\n")
    except Exception:
        pass


def tcp_listener(port: int, stop_evt: threading.Event):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((BIND_IP, port))
        s.listen(128)
        print(f"[TCP] Listening on {BIND_IP}:{port}")
    except Exception as e:
        print(f"[TCP] Failed to bind {port}: {e}")
        try:
            s.close()
        except Exception:
            pass
        return

    s.settimeout(1.0)
    while not stop_evt.is_set():
        if THROTTLE_EVT.is_set():
            time.sleep(0.1)
        try:
            conn, addr = s.accept()
        except socket.timeout:
            continue
        except Exception:
            break
            
        # RL Agent Hook
        if rl_honeypot:
            try:
                ip = addr[0]
                event_type = 'tcp_connect'
                data = { 'port': port }
                
                response = rl_honeypot.process_event(event_type, ip, data)
                
                if response.get('action') == 'block':
                    conn.close()
                    continue 
                if response.get('action') == 'tarpit':
                    time.sleep(response.get('delay', 10.0))
                elif response.get('delay', 0) > 0:
                    time.sleep(response.get('delay'))
            except Exception as e:
                print(f"[RL-HOOK-ERR] {e}")
        # End RL Hook
        
        try:
            # Log connect
            write_csv(
                TCP_CONN_CSV,
                ["timestamp","client_ip","client_port","local_port"],
                [now_iso(), addr[0], addr[1], port]
            )
            record_attempt(addr[0], 'tcp_connect')
           
            conn.settimeout(3.0)
            if port == 21:
                ftp_session(conn, addr)
            elif port == 23:
                telnet_session(conn, addr)
            elif port == 25:
                smtp_session(conn, addr)
            else:
                try:
                    conn.sendall(b"\r\n")
                except Exception:
                    pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    try:
        s.close()
    except Exception:
        pass


# ICMP Echo Sniffer

def run_icmp_sniffer():
    try:
        from scapy.all import sniff, IP, ICMP
    except Exception as e:
        print("[ICMP] Scapy not available. Install with: pip install scapy (and Npcap on Windows).")
        return

    def cb(pkt):
        try:
            if pkt.haslayer(ICMP) and int(pkt[ICMP].type) == 8:  # Echo request
                ip = pkt.getlayer('IP') or pkt.getlayer(IP)
                src = getattr(ip, 'src', '')
                dst = getattr(ip, 'dst', '')
                icmp_id = getattr(pkt[ICMP], 'id', '')
                icmp_seq = getattr(pkt[ICMP], 'seq', '')
                size = len(bytes(pkt))
                write_csv(
                    ICMP_CSV,
                    ["timestamp","src_ip","dst_ip","icmp_id","icmp_seq","packet_len"],
                    [now_iso(), src, dst, icmp_id, icmp_seq, size]
                )
        except Exception:
            pass

    print("[ICMP] Sniffing ICMP Echo Requests (requires admin)")
    try:
        sniff(filter="icmp and icmp[icmptype] = icmp-echo", prn=cb, store=False)
    except Exception as e:
        print(f"[ICMP] Sniffer stopped: {e}")


# System Monitor

def system_monitor(stop_evt: threading.Event, max_threads: int = 200, cpu_threshold: int = 85):
    try:
        import psutil  
    except Exception:
        psutil = None
    warned = False
    while not stop_evt.is_set():
        thr = threading.active_count()
        cpu = None
        if psutil is not None:
            try:
                cpu = int(psutil.cpu_percent(interval=0.1))
            except Exception:
                cpu = None
        overload = (thr > max_threads) or (cpu is not None and cpu >= cpu_threshold)
        if overload and not THROTTLE_EVT.is_set():
            THROTTLE_EVT.set()
            print(f"[WARN] Throttling: threads={thr}" + (f", cpu={cpu}%" if cpu is not None else ""))
            warned = True
        elif not overload and THROTTLE_EVT.is_set():
            THROTTLE_EVT.clear()
            if warned:
                print("[INFO] Throttle cleared")
                warned = False
        time.sleep(5)


# Reporting

def _summarize_csv(file_path: str, ip_index: int | None = 1):
    total = 0
    ip_counts = Counter()
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return total, ip_counts
    try:
        with open(file_path, newline="", encoding="utf-8") as f:
            r = csv.reader(f)
            next(r, None)  
            for row in r:
                total += 1
                if ip_index is not None and len(row) > ip_index:
                    ip_counts[row[ip_index]] += 1
    except Exception:
        pass
    return total, ip_counts


def _summarize_tcp_ports(file_path: str):
    total = 0
    port_counts = Counter()
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return total, port_counts
    try:
        with open(file_path, newline="", encoding="utf-8") as f:
            r = csv.reader(f)
            next(r, None)
            for row in r:
                total += 1
                if len(row) > 3:
                    port_counts[row[3]] += 1  
    except Exception:
        pass
    return total, port_counts


def _fmt_duration(seconds: int) -> str:
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def print_report(start_epoch: float):
    duration = int(time.time() - start_epoch)

    http_total, http_ips = _summarize_csv(HTTP_CONN_CSV, ip_index=1)
    login_total, login_ips = _summarize_csv(LOGIN_CSV, ip_index=1)
    tcp_total, tcp_ips = _summarize_csv(TCP_CONN_CSV, ip_index=1)
    icmp_total, icmp_ips = _summarize_csv(ICMP_CSV, ip_index=1)
    tcp_total_ports, tcp_ports = _summarize_tcp_ports(TCP_CONN_CSV)

    combined_ips = http_ips + login_ips + tcp_ips + icmp_ips

    print("\n===== Honeypot Report =====")
    print(f"Uptime: {_fmt_duration(duration)}")
    print(f"HTTP hits: {http_total}")
    print(f"Login attempts: {login_total}")
    print(f"TCP connects: {tcp_total}")
    print(f"ICMP echo requests: {icmp_total}")
    print(f"Unique source IPs: {len(combined_ips)}")

    top_ips = combined_ips.most_common(5)
    if top_ips:
        print("Top source IPs:")
        for ip, cnt in top_ips:
            print(f"  {ip}: {cnt}")

    top_ports = tcp_ports.most_common(5)
    if top_ports:
        print("Top TCP local ports hit:")
        for port, cnt in top_ports:
            print(f"  {port}: {cnt}")
    print("===========================\n")


# Main

def main():
    stop_evt = threading.Event()
    start_epoch = time.time()

    # System monitor
    mon_thr = threading.Thread(target=system_monitor, args=(stop_evt,), name="monitor", daemon=True)
    mon_thr.start()

    # HTTP server
    http_thr = threading.Thread(target=run_http_server, name="http", daemon=True)
    http_thr.start()

    # TCP listeners
    tcp_threads = []
    for p in TCP_PORTS:
        thr = threading.Thread(target=tcp_listener, args=(p, stop_evt), name=f"tcp-{p}", daemon=True)
        thr.start()
        tcp_threads.append(thr)

    # ICMP sniffer
    icmp_thr = threading.Thread(target=run_icmp_sniffer, name="icmp", daemon=True)
    icmp_thr.start()

    print("Honeypot running. CSV logs in:", LOG_DIR)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        stop_evt.set()
        
        print_report(start_epoch)


if __name__ == "__main__":

    main()

