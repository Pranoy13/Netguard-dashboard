from flask import session, redirect, url_for
from auth.auth import verify_analyst, create_analyst
from flask import Flask, jsonify, request, render_template, send_file
from flask_cors import CORS
from datetime import datetime
import threading
import sys, os

sys.path.append(os.path.dirname(__file__))
from database.db_setup import get_connection, init_db
from capture.sniffer import start_live_capture, process_pcap_file
from detection.rules import run_all_detections

IS_PRODUCTION = os.environ.get('RENDER', False) or os.environ.get('IS_PRODUCTION', False)

from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'analyst_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

app = Flask(__name__)
CORS(app)

app.secret_key = os.environ.get("SECRET_KEY", "netguard-secret-key-change-this-in-production")

@app.route('/api/environment', methods=['GET'])
def get_environment():
    return jsonify({
        "mode": "cloud" if IS_PRODUCTION else "local",
        "live_capture_available": not IS_PRODUCTION
    })

# Keep track of active capture threads per session
active_captures = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        analyst = verify_analyst(username, password)
        if analyst:
            session['analyst_id'] = analyst['id']
            session['analyst_username'] = analyst['username']
            session['analyst_role'] = analyst['role']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if len(username) < 3:
            return render_template('register.html', error="Username must be at least 3 characters.")
        if len(password) < 6:
            return render_template('register.html', error="Password must be at least 6 characters.")
        if password != confirm:
            return render_template('register.html', error="Passwords do not match.")

        success, message = create_analyst(username, password, role="analyst")
        if success:
            return render_template('login.html', success="Account created. Sign in below.")
        return render_template('register.html', error=message)

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})

from flask import render_template

@app.route('/', methods=['GET'])
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('analyst_username'))


from geoip.lookup import get_session_geo_summary

@app.route('/api/geoip/<int:session_id>', methods=['GET'])
def geoip_stats(session_id):
    data = get_session_geo_summary(session_id)
    return jsonify(data)


from reports.generator import generate_session_report

@app.route('/api/export/<int:session_id>', methods=['GET'])
def export_report(session_id):
    filepath = generate_session_report(session_id)
    return send_file(filepath, as_attachment=True, download_name=f"NetGuard_Session_{session_id}_Report.pdf")


# ---------- SESSION MANAGEMENT ----------

@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions ORDER BY id DESC")
    sessions = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(sessions)


@app.route('/api/sessions/start', methods=['POST'])
@login_required
def start_session():
    if IS_PRODUCTION:
        return jsonify({
            "error": "Live capture is not available in cloud deployment. Please upload a PCAP file instead."
        }), 400

    data = request.get_json() or {}
    name = data.get("name", f"Session {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    interface = data.get("interface")  # None = default interface
    duration = data.get("duration", 30)  # seconds, default 30s capture window

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (name, source_type, interface_or_file, started_at, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (name, "live", interface or "default", datetime.now().isoformat(), "running"))
    conn.commit()
    session_id = cursor.lastrowid
    conn.close()

    def capture_and_detect():
        start_live_capture(session_id, interface=interface, timeout=duration)
        conn2 = get_connection()
        cursor2 = conn2.cursor()
        cursor2.execute(
            "UPDATE sessions SET status = 'completed', ended_at = ? WHERE id = ?",
            (datetime.now().isoformat(), session_id)
        )
        conn2.commit()
        conn2.close()
        run_all_detections(session_id)
        active_captures.pop(session_id, None)

    thread = threading.Thread(target=capture_and_detect, daemon=True)
    active_captures[session_id] = thread
    thread.start()

    return jsonify({"session_id": session_id, "status": "started", "duration": duration})


@app.route('/api/sessions/upload', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    upload_dir = os.path.join(os.path.dirname(__file__), 'instance', 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, file.filename)
    file.save(filepath)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (name, source_type, interface_or_file, started_at, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (file.filename, "pcap", file.filename, datetime.now().isoformat(), "running"))
    conn.commit()
    session_id = cursor.lastrowid
    conn.close()

    process_pcap_file(session_id, filepath)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sessions SET status = 'completed', ended_at = ? WHERE id = ?",
        (datetime.now().isoformat(), session_id)
    )
    conn.commit()
    conn.close()

    run_all_detections(session_id)

    return jsonify({"session_id": session_id, "status": "completed"})


# ---------- STATS ENDPOINTS ----------

@app.route('/api/stats/protocols/<int:session_id>', methods=['GET'])
def protocol_stats(session_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT protocol, COUNT(*) as count FROM packets
        WHERE session_id = ? GROUP BY protocol ORDER BY count DESC
    ''', (session_id,))
    data = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route('/api/stats/top-talkers/<int:session_id>', methods=['GET'])
def top_talkers(session_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT src_ip, COUNT(*) as packet_count, SUM(packet_size) as total_bytes
        FROM packets WHERE session_id = ? AND src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY packet_count DESC LIMIT 10
    ''', (session_id,))
    data = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route('/api/stats/timeline/<int:session_id>', methods=['GET'])
def traffic_timeline(session_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, packet_size FROM packets
        WHERE session_id = ? ORDER BY timestamp ASC
    ''', (session_id,))
    rows = cursor.fetchall()
    conn.close()

    # Bucket into per-second counts for a cleaner timeline chart
    buckets = {}
    for row in rows:
        ts = row["timestamp"][:19]  # trim to second precision
        buckets[ts] = buckets.get(ts, 0) + 1

    data = [{"time": t, "packets": c} for t, c in sorted(buckets.items())]
    return jsonify(data)


@app.route('/api/stats/ports/<int:session_id>', methods=['GET'])
def port_stats(session_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT dst_port, COUNT(*) as count FROM packets
        WHERE session_id = ? AND dst_port IS NOT NULL
        GROUP BY dst_port ORDER BY count DESC LIMIT 10
    ''', (session_id,))
    data = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(data)


# ---------- ALERTS ----------

@app.route('/api/alerts/<int:session_id>', methods=['GET'])
def get_alerts(session_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM alerts WHERE session_id = ? ORDER BY timestamp DESC
    ''', (session_id,))
    data = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(data)


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)