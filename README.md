# Honeypot (Windows)

This lightweight honeypot runs locally and logs to CSV files:
- login_attempts.csv — HTML login form submissions
- http_connections.csv — all HTTP GET/POST hits
- tcp_connects.csv — TCP connection attempts to configured ports
- icmp_echo.csv — ICMP Echo Requests (pings)
- alerts.csv — brute-force detections (IP, category, counts)

Files are written under `logs/` in the same folder as the script.

## Prerequisites
- Python 3.8+
- For ICMP sniffing on Windows: install Npcap (https://nmap.org/npcap/) and run PowerShell as Administrator
- Python package for ICMP sniffing:
  - `pip install scapy`

ICMP sniffing is optional — everything else works without Scapy.

## Quick start
1) Open PowerShell as Administrator.
2) (Optional, for ICMP) Install Npcap and Scapy as above.
3) Run the honeypot:

```powershell
python .\honeypot.py
```

Then visit `http://localhost:8080/` to see the fake login page.

## Configuration
- HTTP port: set env var `HONEYPOT_HTTP_PORT` (default `8080`)
- TCP ports to listen on: set env var `HONEYPOT_TCP_PORTS` as comma‑separated list

Examples:
```powershell
$env:HONEYPOT_HTTP_PORT = "9090"
$env:HONEYPOT_TCP_PORTS = "22,23,80,2222,2323,3389"
python .\honeypot.py
```

## CSV columns
- login_attempts.csv: `timestamp,client_ip,user_agent,username,password`
- http_connections.csv: `timestamp,client_ip,method,path,user_agent`
- tcp_connects.csv: `timestamp,client_ip,client_port,local_port`
- icmp_echo.csv: `timestamp,src_ip,dst_ip,icmp_id,icmp_seq,packet_len`
- alerts.csv: `timestamp,ip,category,count_last_60s,note`

## Notes
- Some ports may already be in use; those listeners will be skipped (message printed).
- ICMP sniffing requires admin and Npcap. If unavailable, the script continues without ICMP logging.
- Do not expose this to the internet without proper network isolation; it’s intentionally insecure.
