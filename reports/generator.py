import sys, os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from database.db_setup import get_connection


def generate_session_report(session_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    session = cursor.fetchone()

    cursor.execute('''
        SELECT protocol, COUNT(*) as count FROM packets
        WHERE session_id = ? GROUP BY protocol ORDER BY count DESC
    ''', (session_id,))
    protocols = cursor.fetchall()

    cursor.execute('''
        SELECT src_ip, COUNT(*) as packet_count, SUM(packet_size) as total_bytes
        FROM packets WHERE session_id = ? AND src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY packet_count DESC LIMIT 10
    ''', (session_id,))
    talkers = cursor.fetchall()

    cursor.execute('''
        SELECT * FROM alerts WHERE session_id = ? ORDER BY severity DESC
    ''', (session_id,))
    alerts = cursor.fetchall()

    conn.close()

    output_dir = os.path.join(os.path.dirname(__file__), '..', 'instance', 'reports')
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"session_{session_id}_report.pdf")

    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Title'], textColor=colors.HexColor('#8b5cf6'))
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], textColor=colors.HexColor('#4c1d95'))

    elements = []

    elements.append(Paragraph("NetGuard Security Monitoring Report", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Session: {session['name']} (ID: {session_id})", styles['Normal']))
    elements.append(Paragraph(f"Source Type: {session['source_type']}", styles['Normal']))
    elements.append(Paragraph(f"Started: {session['started_at']}", styles['Normal']))
    elements.append(Paragraph(f"Ended: {session['ended_at'] or 'N/A'}", styles['Normal']))
    elements.append(Paragraph(f"Total Packets: {session['total_packets']}", styles['Normal']))
    elements.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Protocol Breakdown", heading_style))
    proto_data = [["Protocol", "Packet Count"]] + [[p["protocol"], str(p["count"])] for p in protocols]
    proto_table = Table(proto_data, colWidths=[200, 200])
    proto_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#8b5cf6')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f3f0fa')]),
    ]))
    elements.append(proto_table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Top Talkers", heading_style))
    talker_data = [["Source IP", "Packets", "Bytes"]] + [
        [t["src_ip"], str(t["packet_count"]), str(t["total_bytes"] or 0)] for t in talkers
    ]
    talker_table = Table(talker_data, colWidths=[180, 100, 100])
    talker_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#8b5cf6')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f3f0fa')]),
    ]))
    elements.append(talker_table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Security Alerts", heading_style))
    if alerts:
        alert_data = [["Severity", "Type", "Description"]] + [
            [a["severity"].upper(), a["alert_type"].replace('_',' '), a["description"]] for a in alerts
        ]
        severity_colors = {"HIGH": colors.HexColor('#f87171'), "MEDIUM": colors.HexColor('#fbbf24'), "LOW": colors.HexColor('#4ade80')}
        alert_table = Table(alert_data, colWidths=[70, 100, 300])
        style_cmds = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#8b5cf6')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]
        for i, a in enumerate(alerts, start=1):
            sev = a["severity"].upper()
            style_cmds.append(('TEXTCOLOR', (0,i), (0,i), severity_colors.get(sev, colors.black)))
        alert_table.setStyle(TableStyle(style_cmds))
        elements.append(alert_table)
    else:
        elements.append(Paragraph("No alerts detected in this session.", styles['Normal']))

    doc.build(elements)
    return filepath


if __name__ == '__main__':
    path = generate_session_report(1)
    print("Report generated at:", path)