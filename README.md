#  NetGuard — Network Traffic Visualization Dashboard for Security Monitoring

NetGuard is a full-stack network security monitoring tool that captures network traffic (live or via uploaded `.pcap` files), classifies it, runs rule-based and statistical threat detection, and visualizes everything on a real-time analyst dashboard — modeled after real Security Operations Center (SOC) tooling.

**Live demo:** https://netguard-dashboard.onrender.com
*(Cloud deployment runs in PCAP-upload mode only — see "Deployment Notes" below.)*

---

## Features

- **Packet Capture** — live capture (Scapy) locally, or upload any standard `.pcap`/`.pcapng` file (including ones captured in Wireshark or tcpdump)
- **Protocol Classification** — automatic breakdown of TCP/UDP/DNS/HTTP/HTTPS/ICMP traffic
- **Rule-Based Threat Detection**
  - Port scan detection (many distinct ports from one source IP)
  - Suspicious port access (Telnet, FTP, SMB, RDP, etc.)
  - Unencrypted HTTP traffic flagging
  - Statistical traffic spike detection using **Median Absolute Deviation (MAD)** — robust to skewed traffic distributions, avoids false-positive floods common with naive z-score methods
- **GeoIP Enrichment** — maps public source IPs to country/city using MaxMind GeoLite2, with private/LAN IPs correctly labeled separately
- **Interactive World Map** — Leaflet.js map plotting real-time traffic origins
- **Packet Explorer** — paginated, searchable table of individual captured packets for drill-down analysis
- **Ports Observed Panel** — traffic-observed ports mapped to known service names (not to be confused with active port scanning — this is passive observation only)
- **PDF Report Export** — one-click downloadable session report (protocol breakdown, top talkers, alerts) via ReportLab
- **Analyst Authentication** — register/login system with hashed passwords (Werkzeug), session-based access control
- **Session History** — every capture is logged and revisitable, not just live-only

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Packet Capture/Parsing | Scapy |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |
| Maps | Leaflet.js + CARTO dark tiles |
| GeoIP | MaxMind GeoLite2 (geoip2) |
| PDF Reports | ReportLab |
| Auth | Flask sessions + Werkzeug password hashing |
| Deployment | Render (Gunicorn WSGI server) |

---

## Project Structure

```
netguard-dashboard/
├── app.py                  # Flask app & API routes
├── database/
│   └── db_setup.py         # SQLite schema (sessions, packets, alerts, geoip_cache, analysts)
├── capture/
│   └── sniffer.py          # Live capture + PCAP file parsing (Scapy)
├── detection/
│   └── rules.py            # Rule-based + statistical anomaly detection
├── geoip/
│   └── lookup.py           # GeoIP enrichment logic
├── auth/
│   └── auth.py             # Analyst registration/login logic
├── reports/
│   └── generator.py        # PDF report generation
├── templates/
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
├── static/
├── requirements.txt
├── Procfile
└── .gitignore
```

---

## Running Locally

**Live packet capture requires administrator/root privileges** (raw socket access) and the [Npcap](https://npcap.com/) driver on Windows.

```bash
# Clone the repo
git clone https://github.com/Pranoy13/netguard-dashboard.git
cd netguard-dashboard

# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# (Optional) Add MaxMind GeoLite2 City database for GeoIP lookups
# Download from https://www.maxmind.com/en/geolite2/signup
# Place the .mmdb file at: instance/GeoLite2-City.mmdb

# Run the app (as Administrator on Windows, for live capture)
python app.py
```

Visit `http://127.0.0.1:5000`, register an analyst account, and log in.

---

## Deployment Notes

Live packet sniffing requires raw socket access to a real network interface — this is **not available on shared cloud hosts** like Render, since containers don't expose a physical NIC to sniff.

NetGuard handles this gracefully with an environment check: when deployed to the cloud (`RENDER=true` environment variable), the "Start Live Capture" button is automatically disabled with a clear message, and the app runs in **PCAP-upload mode** — fully functional for classification, detection, visualization, GeoIP mapping, and reporting on any uploaded capture file.

**Note on Render's free tier:** the filesystem is ephemeral, meaning the SQLite database resets on redeploys/restarts. This is expected free-tier behavior, not a bug.

---

## Design Notes

- **Passive vs. active reconnaissance:** NetGuard observes traffic that occurs during a capture window — it reports ports *observed in traffic*, not the result of active port scanning (e.g., Nmap). This is an intentional design choice to keep the tool purely observational and non-intrusive.
- **MAD over z-score for anomaly detection:** network traffic counts are naturally skewed (a few busy hosts, many quiet ones). Standard mean/standard-deviation z-scores flag too many false positives on skewed data, so NetGuard uses the Median Absolute Deviation method with a modified z-score threshold of 3.5 — the standard robust-statistics threshold for outlier detection.

---

## Author

Built by Pranoy Albin Mascarenhas — MCA (Cyber Security), Lovely Professional University
[GitHub](https://github.com/Pranoy13) · [LeetCode](https://leetcode.com/u/Pranoy06/)
