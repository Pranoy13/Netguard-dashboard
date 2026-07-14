from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, DNS
from datetime import datetime
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from database.db_setup import get_connection


def classify_protocol(packet):
    """Determine a human-readable protocol name for a packet."""
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
        if dport == 80 or sport == 80:
            return "HTTP"
        if dport == 443 or sport == 443:
            return "HTTPS"
        if dport == 21 or sport == 21:
            return "FTP"
        if dport == 23 or sport == 23:
            return "Telnet"
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def extract_packet_info(packet, session_id):
    """Pull out the fields we care about from a single packet."""
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_port = dst_port = None
    flags = ""

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return {
        "session_id": session_id,
        "timestamp": datetime.now().isoformat(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": classify_protocol(packet),
        "packet_size": len(packet),
        "flags": flags
    }


def save_packet(info):
    """Insert one parsed packet into the database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packets (session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        info["session_id"], info["timestamp"], info["src_ip"], info["dst_ip"],
        info["src_port"], info["dst_port"], info["protocol"], info["packet_size"], info["flags"]
    ))
    conn.commit()
    conn.close()


def update_session_count(session_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE sessions SET total_packets = total_packets + 1 WHERE id = ?
    ''', (session_id,))
    conn.commit()
    conn.close()


def process_packet(packet, session_id):
    """Callback used for both live sniffing and pcap reading."""
    info = extract_packet_info(packet, session_id)
    if info:
        save_packet(info)
        update_session_count(session_id)


def start_live_capture(session_id, interface=None, packet_count=0, timeout=None):
    """
    Live capture. packet_count=0 means capture until timeout or manual stop.
    Requires admin/root privileges.
    """
    print(f"Starting live capture for session {session_id}...")
    sniff(
        iface=interface,
        prn=lambda pkt: process_packet(pkt, session_id),
        count=packet_count,
        timeout=timeout,
        store=False
    )
    print("Live capture finished.")


def process_pcap_file(session_id, filepath):
    """Read a .pcap/.pcapng file and store all packets."""
    print(f"Reading pcap file: {filepath}")
    packets = rdpcap(filepath)
    for pkt in packets:
        process_packet(pkt, session_id)
    print(f"Finished processing {len(packets)} packets from file.")


if __name__ == '__main__':
    # Quick manual test - captures 20 packets live and prints confirmation
    from database.db_setup import get_connection

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (name, source_type, interface_or_file, started_at, status)
        VALUES (?, ?, ?, ?, ?)
    ''', ("Test Session", "live", "default", datetime.now().isoformat(), "running"))
    conn.commit()
    test_session_id = cursor.lastrowid
    conn.close()

    start_live_capture(test_session_id, packet_count=20)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM packets WHERE session_id = ?", (test_session_id,))
    print("Packets saved:", cursor.fetchone()["cnt"])
    conn.close()