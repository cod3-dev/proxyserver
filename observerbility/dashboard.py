from http.server import HTTPServer, BaseHTTPRequestHandler
from observability.metrics import metrics
from observability.logger import SecurityLogger
from observability.alerts import AlertManager
import json

logger = SecurityLogger()
alerts = AlertManager()

DASHBOARD_PORT = 9100

# In-memory alert store for dashboard (latest 50 alerts)
dashboard_alerts = []

class DashboardHandler(BaseHTTPRequestHandler):
    def _send(self, code, payload, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        if content_type == "application/json":
            self.wfile.write(json.dumps(payload, indent=2).encode())
        else:
            self.wfile.write(payload.encode())

    def do_GET(self):
        if self.path == "/":
            # Serve HTML dashboard
            html = DASHBOARD_HTML
            self._send(200, html, content_type="text/html")
        elif self.path == "/metrics":
            self._send(200, metrics.snapshot())
        elif self.path == "/alerts":
            self._send(200, dashboard_alerts[-50:])  # last 50 alerts
        elif self.path == "/health":
            self._send(200, {"status": "UP", "service": "Security Proxy"})
        else:
            self._send(404, {"error": "Not found"})

    def log_message(self, format, *args):
        return  # silence default logging

def raise_dashboard_alert(level, message, context):
    alert = {
        "level": level,
        "message": message,
        "context": context
    }
    dashboard_alerts.append(alert)
    alerts.raise_alert(level, message, context)

def start_dashboard(host="127.0.0.1", port=DASHBOARD_PORT):
    server = HTTPServer((host, port), DashboardHandler)
    print(f"[+] Dashboard running on http://{host}:{port}")
    server.serve_forever()


# ---------------- HTML + JS dashboard ----------------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Proxy Dashboard</title>
<style>
body { font-family: Arial; background: #1e1e1e; color: #f0f0f0; }
h1 { color: #0f9d58; }
.container { display: flex; flex-wrap: wrap; gap: 20px; }
.card { background: #2e2e2e; padding: 15px; border-radius: 10px; flex: 1; min-width: 200px; }
pre { white-space: pre-wrap; word-wrap: break-word; }
</style>
</head>
<body>
<h1>Security Proxy Dashboard</h1>
<div class="container">
  <div class="card">
    <h2>Metrics</h2>
    <pre id="metrics">Loading...</pre>
  </div>
  <div class="card">
    <h2>Recent Alerts</h2>
    <pre id="alerts">Loading...</pre>
  </div>
</div>
<script>
async function updateMetrics() {
    const res = await fetch('/metrics');
    const data = await res.json();
    document.getElementById('metrics').textContent = JSON.stringify(data, null, 2);
}
async function updateAlerts() {
    const res = await fetch('/alerts');
    const data = await res.json();
    document.getElementById('alerts').textContent = JSON.stringify(data, null, 2);
}
function refresh() {
    updateMetrics();
    updateAlerts();
}
setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>
"""
