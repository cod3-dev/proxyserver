

"""
Security Proxy Dashboard

Endpoints:
    GET /           -> HTML dashboard
    GET /metrics   -> JSON metrics
    GET /alerts    -> JSON alerts
    GET /health    -> health check
"""

import json
import os
import ssl
import threading
from collections.abc import Mapping
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from observerbility.metrics import metrics
from observerbility.alerts import AlertManager


# =========================================================
# Setup
# =========================================================

alerts = AlertManager()

DASHBOARD_PORT = 9100
MAX_ALERTS = 50

# thread-safe bounded storage
dashboard_alerts: deque = deque(maxlen=MAX_ALERTS)
lock = threading.Lock()

DEFAULT_DASHBOARD_PORT = DASHBOARD_PORT
FALLBACK_DASHBOARD_PORT = int(os.environ.get("DASHBOARD_FALLBACK_PORT", "9200"))


class DashboardHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False


# =========================================================
# Handler
# =========================================================

class DashboardHandler(BaseHTTPRequestHandler):

    # -------------------------
    # helpers
    # -------------------------

    def _send_json(self, code: int, payload: Any) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode()

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _send_html(self, html: str) -> None:
        body = html.encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    # -------------------------
    # routes
    # -------------------------

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/":
            self._send_html(DASHBOARD_HTML)

        elif path == "/metrics":
            self._send_json(200, metrics.snapshot())

        elif path == "/alerts":
            with lock:
                self._send_json(200, list(dashboard_alerts))

        elif path == "/health":
            self._send_json(200, {"status": "UP", "service": "Security Proxy"})

        else:
            self._send_json(404, {"error": "not_found"})

    def log_message(self, *args: Any) -> None:
        return  # silence default http logs


# =========================================================
# Alert integration
# =========================================================

def _normalize_context(context: Any) -> Dict[str, Any]:
    if context is None:
        return {}
    if isinstance(context, Mapping):
        return dict(context)
    return {"context": context}


def raise_dashboard_alert(level: str, message: str, context: Any) -> None:
    """
    Call this from your proxy when an alert occurs.
    """
    normalized_context = _normalize_context(context)
    alert = {
        "level": level,
        "message": message,
        "context": normalized_context,
    }

    with lock:
        dashboard_alerts.append(alert)

    alerts.raise_alert(level, message, normalized_context)


# =========================================================
# TLS
# =========================================================

def _wrap_tls(server: ThreadingHTTPServer, certfile: Optional[str], keyfile: Optional[str]) -> bool:
    if not certfile or not keyfile:
        return False

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(certfile, keyfile)

    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return True


# =========================================================
# Start
# =========================================================

def start_dashboard(
    host: str = "127.0.0.1",
    port: int = DASHBOARD_PORT,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
) -> None:
    """
    Start dashboard server (threaded + optional TLS)
    """

    try:
        server = DashboardHTTPServer((host, port), DashboardHandler)
    except OSError as exc:
        if port == DEFAULT_DASHBOARD_PORT:
            try:
                server = DashboardHTTPServer((host, FALLBACK_DASHBOARD_PORT), DashboardHandler)
                port = FALLBACK_DASHBOARD_PORT
            except OSError:
                raise exc
        else:
            raise

    is_tls = _wrap_tls(server, certfile, keyfile)
    scheme = "https" if is_tls else "http"

    actual_port = server.server_address[1]
    print(f"[+] Dashboard running on {scheme}://{host}:{actual_port}")

    server.serve_forever()


# =========================================================
# HTML
# =========================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Security Proxy Dashboard</title>
<style>
body { font-family: Arial; background:#1e1e1e; color:#f0f0f0; padding:20px }
h1 { color:#0f9d58 }
.container { display:flex; gap:20px; flex-wrap:wrap }
.card { background:#2e2e2e; padding:15px; border-radius:10px; flex:1 }
pre { white-space:pre-wrap }
</style>
</head>
<body>
<h1>Security Proxy Dashboard</h1>

<div class="container">
  <div class="card">
    <h3>Metrics</h3>
    <pre id="metrics">Loading...</pre>
  </div>

  <div class="card">
    <h3>Alerts</h3>
    <pre id="alerts">Loading...</pre>
  </div>
</div>

<script>
async function refresh(){
    const m = await fetch('/metrics').then(r=>r.json());
    const a = await fetch('/alerts').then(r=>r.json());

    document.getElementById('metrics').textContent = JSON.stringify(m,null,2);
    document.getElementById('alerts').textContent = JSON.stringify(a,null,2);
}

setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>
"""
