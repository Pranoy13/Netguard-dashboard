import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'instance', 'netguard.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()

    # Sessions table - tracks each capture session
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,       -- 'live' or 'pcap'
            interface_or_file TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            total_packets INTEGER DEFAULT 0,
            status TEXT DEFAULT 'running'    -- 'running', 'completed', 'stopped'
        )
    ''')

    # Packets table - stores every parsed packet
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packet_size INTEGER,
            flags TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )
    ''')

    # Alerts table - stores detected security events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,        -- 'port_scan', 'traffic_spike', 'suspicious_port', 'unencrypted_http'
            severity TEXT NOT NULL,          -- 'low', 'medium', 'high'
            source_ip TEXT,
            target_ip TEXT,
            description TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )
    ''')

    # GeoIP cache table - avoids repeated lookups for same IP
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS geoip_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            cached_at TEXT
        )
    ''')
    
    # Analysts table - login credentials
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print("Database initialized successfully at:", DB_PATH)

if __name__ == '__main__':
    init_db()