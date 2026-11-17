
import csv
import io
import json
import sqlite3
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from database import DB_NAME

HOST = "127.0.0.1"
PORT = 8000


def get_all_incidents():
    """Retrieve all incidents from the SQLite database."""
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute(
            """
            SELECT id, timestamp, event, username, ip, service,
                   severity, attempts, detected_at
            FROM incidents
            ORDER BY id DESC
            """
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_dashboard_data():
    """Collect incident statistics and recent activity."""
    incidents = get_all_incidents()

    severity_counts = Counter(
        (incident.get("severity") or "UNKNOWN").upper()
        for incident in incidents
    )

    ip_counts = Counter(
        incident["ip"]
        for incident in incidents
        if incident.get("ip")
    )

    return {
        "total": len(incidents),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "info": severity_counts.get("INFO", 0),
        "unknown": severity_counts.get("UNKNOWN", 0),
        "top_ips": ip_counts.most_common(5),
        "recent": incidents[:50],
    }


def generate_csv():
    """Generate a downloadable CSV report."""
    incidents = get_all_incidents()

    output = io.StringIO()
    fieldnames = [
        "id",
        "timestamp",
        "event",
        "username",
        "ip",
        "service",
        "severity",
        "attempts",
        "detected_at",
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(incidents)

    return output.getvalue().encode("utf-8")


def generate_json():
    """Generate a downloadable JSON report."""
    incidents = get_all_incidents()

    return json.dumps(
        incidents,
        indent=4,
        default=str
    ).encode("utf-8")


def build_page():
    """Build the LogSentinel SOC dashboard."""
    data = get_dashboard_data()

    severity_colors = {
        "HIGH": "#ef4444",
        "MEDIUM": "#f59e0b",
        "LOW": "#3b82f6",
        "INFO": "#10b981",
    }

    rows = ""

    for incident in data["recent"]:
        severity = (
            incident.get("severity") or "UNKNOWN"
        ).upper()

        color = severity_colors.get(severity, "#94a3b8")

        rows += f"""
        <tr>
            <td>{incident.get('id', '')}</td>
            <td>{incident.get('timestamp') or ''}</td>
            <td>{incident.get('event') or ''}</td>
            <td>{incident.get('username') or '-'}</td>
            <td>{incident.get('ip') or 'Local / Unknown'}</td>
            <td>{incident.get('service') or '-'}</td>
            <td>
                <span class="severity"
                      style="background:{color}">
                    {severity}
                </span>
            </td>
            <td>{incident.get('attempts') or '-'}</td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="8" class="empty">
                No incidents recorded yet.
            </td>
        </tr>
        """

    ip_rows = ""

    for ip, count in data["top_ips"]:
        ip_rows += f"""
        <tr>
            <td>{ip}</td>
            <td>{count}</td>
        </tr>
        """

    if not ip_rows:
        ip_rows = """
        <tr>
            <td colspan="2" class="empty">
                No source IP addresses recorded.
            </td>
        </tr>
        """

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="15">
    <title>LogSentinel | SOC Dashboard</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 25px;
            background: #0b1120;
            color: #e2e8f0;
            font-family: Arial, Helvetica, sans-serif;
        }}

        .container {{
            max-width: 1450px;
            margin: auto;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 30px;
        }}

        h1 {{
            margin: 0;
            color: #38bdf8;
            font-size: 30px;
        }}

        .subtitle {{
            color: #94a3b8;
            margin-top: 8px;
        }}

        .status {{
            color: #4ade80;
            background: #123225;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 13px;
        }}

        .section-title {{
            margin: 30px 0 15px;
            font-size: 19px;
            color: #cbd5e1;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 18px;
        }}

        .card {{
            background: #172033;
            border: 1px solid #273449;
            padding: 22px;
            border-radius: 12px;
        }}

        .card h3 {{
            margin: 0;
            color: #94a3b8;
            font-size: 14px;
            font-weight: normal;
        }}

        .number {{
            margin-top: 15px;
            font-size: 34px;
            font-weight: bold;
        }}

        .total {{ color: #38bdf8; }}
        .high {{ color: #ef4444; }}
        .medium {{ color: #f59e0b; }}
        .low {{ color: #60a5fa; }}
        .info {{ color: #4ade80; }}

        .panel {{
            background: #172033;
            border: 1px solid #273449;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 22px;
        }}

        .panel h2 {{
            font-size: 18px;
            margin-top: 0;
        }}

        .columns {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}

        th, td {{
            padding: 13px 12px;
            text-align: left;
            border-bottom: 1px solid #293449;
        }}

        th {{
            color: #94a3b8;
            background: #111a2b;
        }}

        td {{
            color: #cbd5e1;
        }}

        tr:hover td {{
            background: #1e293b;
        }}

        .severity {{
            display: inline-block;
            color: white;
            padding: 5px 9px;
            border-radius: 5px;
            font-size: 11px;
            font-weight: bold;
        }}

        .empty {{
            text-align: center;
            color: #64748b;
            padding: 25px;
        }}

        .downloads {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin: 20px 0;
        }}

        .downloads a {{
            display: inline-block;
            background: #0369a1;
            color: white;
            text-decoration: none;
            padding: 11px 16px;
            border-radius: 7px;
            font-size: 13px;
        }}

        .downloads a:hover {{
            background: #0284c7;
        }}

        .footer {{
            color: #64748b;
            font-size: 12px;
            text-align: center;
            margin-top: 35px;
        }}

        @media (max-width: 850px) {{
            .columns {{
                grid-template-columns: 1fr;
            }}

            .table-wrapper {{
                overflow-x: auto;
            }}

            table {{
                min-width: 850px;
            }}
        }}
    </style>
</head>

<body>
<div class="container">

    <header>
        <div>
            <h1>LogSentinel</h1>
            <div class="subtitle">
                Security Operations Center | Log Monitoring Dashboard
            </div>
        </div>

        <div class="status">
            ● Dashboard Online
        </div>
    </header>

    <h2 class="section-title">Security Overview</h2>

    <div class="cards">
        <div class="card">
            <h3>Total Incidents</h3>
            <div class="number total">{data['total']}</div>
        </div>

        <div class="card">
            <h3>High Severity</h3>
            <div class="number high">{data['high']}</div>
        </div>

        <div class="card">
            <h3>Medium Severity</h3>
            <div class="number medium">{data['medium']}</div>
        </div>

        <div class="card">
            <h3>Low Severity</h3>
            <div class="number low">{data['low']}</div>
        </div>

        <div class="card">
            <h3>Informational</h3>
            <div class="number info">{data['info']}</div>
        </div>
    </div>

    <div class="downloads">
        <a href="/download/incidents.csv">Download CSV Report</a>
        <a href="/download/incidents.json">Download JSON Report</a>
    </div>

    <div class="columns">

        <div class="panel">
            <h2>Top Source IP Addresses</h2>
            <table>
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Incident Count</th>
                    </tr>
                </thead>
                <tbody>
                    {ip_rows}
                </tbody>
            </table>
        </div>

        <div class="panel">
            <h2>Severity Overview</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>HIGH</td><td>{data['high']}</td></tr>
                    <tr><td>MEDIUM</td><td>{data['medium']}</td></tr>
                    <tr><td>LOW</td><td>{data['low']}</td></tr>
                    <tr><td>INFO</td><td>{data['info']}</td></tr>
                    <tr><td>UNKNOWN</td><td>{data['unknown']}</td></tr>
                </tbody>
            </table>
        </div>

    </div>

    <div class="panel">
        <h2>Recent Security Incidents</h2>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>Event</th>
                        <th>Username</th>
                        <th>Source IP</th>
                        <th>Service</th>
                        <th>Severity</th>
                        <th>Attempts</th>
                    </tr>
                </thead>

                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </div>

    <div class="footer">
        LogSentinel | Automatically refreshes every 15 seconds
        <br>
        Last page generation: {generated_at}
    </div>

</div>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):

    def send_response_body(self, content, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        path = urlsplit(self.path).path

        try:
            if path == "/":
                page = build_page().encode("utf-8")
                self.send_response_body(page, "text/html; charset=utf-8")

            elif path == "/download/incidents.csv":
                report = generate_csv()
                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "text/csv; charset=utf-8"
                )
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="logsentinel_incidents.csv"'
                )
                self.send_header("Content-Length", str(len(report)))
                self.end_headers()
                self.wfile.write(report)

            elif path == "/download/incidents.json":
                report = generate_json()
                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "application/json; charset=utf-8"
                )
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="logsentinel_incidents.json"'
                )
                self.send_header("Content-Length", str(len(report)))
                self.end_headers()
                self.wfile.write(report)

            else:
                message = b"404 - Page not found"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(message)))
                self.end_headers()
                self.wfile.write(message)

        except (BrokenPipeError, ConnectionResetError):
            print("[Dashboard] Browser disconnected before response completed.")

        except (sqlite3.Error, OSError, ValueError) as error:
            print(f"[Dashboard] Request error: {error}")

            try:
                message = b"500 - Internal server error"
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(message)))
                self.end_headers()
                self.wfile.write(message)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    def log_message(self, format_string, *args):
        print(f"[Dashboard] {format_string % args}")


def main():
    try:
        server = HTTPServer((HOST, PORT), DashboardHandler)
    except OSError as error:
        print(f"[ERROR] Could not start dashboard: {error}")
        return

    print("\nLogSentinel dashboard is running.")
    print(f"Open your browser at: http://{HOST}:{PORT}")
    print(f"CSV export: http://{HOST}:{PORT}/download/incidents.csv")
    print(f"JSON export: http://{HOST}:{PORT}/download/incidents.json")
    print("Press CTRL+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping LogSentinel dashboard...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
