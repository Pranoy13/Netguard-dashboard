import geoip2.database
import ipaddress
import sys, os
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from database.db_setup import get_connection

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'instance', 'GeoLite2-City.mmdb')

_reader = None

def get_reader():
    global _reader
    if _reader is None:
        if not os.path.exists(DB_PATH):
            raise FileNotFoundError("GeoIP database not found")
        _reader = geoip2.database.Reader(DB_PATH)
    return _reader


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # treat malformed IPs as non-lookupable


def lookup_ip(ip):
    """Look up a single IP, using cache first, then GeoIP DB."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM geoip_cache WHERE ip = ?", (ip,))
    cached = cursor.fetchone()

    if cached:
        conn.close()
        return dict(cached)

    if is_private_ip(ip):
        result = {
            "ip": ip, "country": "Local Network", "city": "Private/LAN",
            "latitude": None, "longitude": None, "cached_at": datetime.now().isoformat()
        }
    else:
        try:
            reader = get_reader()
            response = reader.city(ip)
            result = {
                "ip": ip,
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "cached_at": datetime.now().isoformat()
            }
        except Exception:
            result = {
                "ip": ip, "country": "Unknown", "city": "Unknown",
                "latitude": None, "longitude": None, "cached_at": datetime.now().isoformat()
            }

    cursor.execute('''
        INSERT OR REPLACE INTO geoip_cache (ip, country, city, latitude, longitude, cached_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (result["ip"], result["country"], result["city"], result["latitude"], result["longitude"], result["cached_at"]))
    conn.commit()
    conn.close()

    return result


def get_session_geo_summary(session_id):
    """Get country breakdown for all unique source IPs in a session."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT src_ip FROM packets WHERE session_id = ? AND src_ip IS NOT NULL
    ''', (session_id,))
    ips = [row["src_ip"] for row in cursor.fetchall()]
    conn.close()

    geo_data = [lookup_ip(ip) for ip in ips]

    country_counts = {}
    for g in geo_data:
        country = g["country"]
        country_counts[country] = country_counts.get(country, 0) + 1

    return {
        "details": geo_data,
        "country_summary": [{"country": c, "count": n} for c, n in sorted(country_counts.items(), key=lambda x: -x[1])]
    }


if __name__ == '__main__':
    result = get_session_geo_summary(3)
    print("Country summary:")
    for c in result["country_summary"]:
        print(f"  {c['country']}: {c['count']} IP(s)")