import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from observability.metrics import Metrics


class AdminHandler(BaseHTTPRequestHandler):

    def _send(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload, indent=2).encode())

    def do_get(self):
        if self.path == "/health":
            self._send(200, {
                "status": "UP",
                "service": "Security Proxy",
            })

        elif self.path == "/metrics":
            self._send(200, Metrics.snapshot())

        else:
            self._send(404, {"error": "Not found"})

    def log_message(self, *args):
        # silence default HTTP logs
        return


def start_admin_api(host="127.0.0.1", port=9000):
    server = HTTPServer((host, port, [AdminHandler])
    print(f"[+] Admin API running on https://{host}:{port}")
    server.serve_forever()
