import sys
import os
from datetime import datetime
from collections import defaultdict
import statistics

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from database.db_setup import get_connection

# Ports considered risky if seen in traffic
SUSPICIOUS_PORTS = {
    21: "FTP (unencrypted file transfer)",
    23: "Telnet (unencrypted remote login)",
    445: "SMB (common ransomware/lateral movement vector)",
    3389: "RDP (remote desktop - common brute force target)",
    139: "NetBIOS",
}

PORT_SCAN_THRESHOLD = 10       # distinct ports from same src IP
PORT_SCAN_WINDOW_SECONDS = 30  # time window to check


def save_alert(session_id, alert_type, severity, source_ip, target_ip, description):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (session_id, timestamp, alert_type, severity, source_ip, target_ip, description)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (session_id, datetime.now().isoformat(), alert_type, severity, source_ip, target_ip, description))
    conn.commit()
    conn.close()


def get_session_packets(session_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM packets WHERE session_id = ?", (session_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def detect_port_scans(session_id):
    """Flag source IPs that touched many distinct destination ports."""
    packets = get_session_packets(session_id)
    ip_ports = defaultdict(set)

    for pkt in packets:
        if pkt["src_ip"] and pkt["dst_port"]:
            ip_ports[pkt["src_ip"]].add(pkt["dst_port"])

    for ip, ports in ip_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            save_alert(
                session_id, "port_scan", "high", ip, None,
                f"{ip} contacted {len(ports)} distinct ports — possible port scan."
            )


def detect_suspicious_ports(session_id):
    """Flag traffic to/from known risky ports."""
    packets = get_session_packets(session_id)
    seen = set()

    for pkt in packets:
        for port_field in ["src_port", "dst_port"]:
            port = pkt[port_field]
            if port in SUSPICIOUS_PORTS:
                key = (pkt["src_ip"], pkt["dst_ip"], port)
                if key not in seen:
                    seen.add(key)
                    save_alert(
                        session_id, "suspicious_port", "medium",
                        pkt["src_ip"], pkt["dst_ip"],
                        f"Traffic on port {port} ({SUSPICIOUS_PORTS[port]}) between {pkt['src_ip']} and {pkt['dst_ip']}."
                    )


def detect_unencrypted_http(session_id):
    """Flag plain HTTP traffic (port 80) as a security best-practice warning."""
    packets = get_session_packets(session_id)
    seen = set()

    for pkt in packets:
        if pkt["protocol"] == "HTTP":
            key = (pkt["src_ip"], pkt["dst_ip"])
            if key not in seen:
                seen.add(key)
                save_alert(
                    session_id, "unencrypted_http", "low",
                    pkt["src_ip"], pkt["dst_ip"],
                    f"Unencrypted HTTP traffic detected between {pkt['src_ip']} and {pkt['dst_ip']}. Consider HTTPS."
                )


def detect_traffic_spikes(session_id):
    """
    Statistical anomaly detection using Median Absolute Deviation (MAD)
    instead of mean/stdev, since network traffic counts are naturally
    skewed (a few busy IPs, many quiet ones) — MAD is far more robust
    to that skew than a standard z-score.
    """
    packets = get_session_packets(session_id)
    ip_counts = defaultdict(int)

    for pkt in packets:
        if pkt["src_ip"]:
            ip_counts[pkt["src_ip"]] += 1

    counts = list(ip_counts.values())
    if len(counts) < 5:
        return  # not enough distinct IPs for meaningful stats

    median = statistics.median(counts)
    abs_deviations = [abs(c - median) for c in counts]
    mad = statistics.median(abs_deviations)

    if mad == 0:
        return  # no meaningful spread to compare against

    # 0.6745 scales MAD to be comparable to standard deviation
    for ip, count in ip_counts.items():
        modified_z = 0.6745 * (count - median) / mad
        if modified_z > 3.5:  # standard robust-outlier threshold
            save_alert(
                session_id, "traffic_spike", "high", ip, None,
                f"{ip} sent {count} packets — statistically abnormal (modified z-score={modified_z:.2f})."
            )


def run_all_detections(session_id):
    """Run the full detection suite on a session."""
    print(f"Running detection engine for session {session_id}...")
    detect_port_scans(session_id)
    detect_suspicious_ports(session_id)
    detect_unencrypted_http(session_id)
    detect_traffic_spikes(session_id)
    print("Detection complete.")


if __name__ == '__main__':
    # Quick manual test - run detections on session 1 (from our sniffer test)
    run_all_detections(3)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE session_id = 1")
    alerts = cursor.fetchall()
    conn.close()

    print(f"\nAlerts found: {len(alerts)}")
    for a in alerts:
        print(f"[{a['severity'].upper()}] {a['alert_type']}: {a['description']}")