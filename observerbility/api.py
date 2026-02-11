"""
Admin API for the Security Proxy

Endpoints:
    GET /health
    GET /metrics
"""

import json
import logging
import os
import ssl
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from observerbility.metrics import metrics   # <-- ensure folder name matches



# Logging

logger = logging.getLogger(__name__)



# Config


@dataclass
class AdminServerConfig:
    host: str = "127.0.0.1"
    port: int = 9000
    certfile: Optional[str] = None
    keyfile: Optional[str] = None


# =========================================================
# HTTP Handler
# =========================================================

class AdminHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -------------------------
    # Helpers
    # -------------------------

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode()

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    # -------------------------
    # Endpoints
    # -------------------------

    def _health(self) -> None:
        self._send_json(
            200,
            {
                "status": "UP",
                "service": "security-proxy",
                "timestamp": self.date_time_string(),
            },
        )

    def _metrics(self) -> None:
        try:
            self._send_json(200, metrics.snapshot())
        except Exception as exc:
            logger.exception("metrics error: %s", exc)
            self._send_json(500, {"error": "metrics_failed"})

    # -------------------------
    # Router
    # -------------------------

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/health":
            self._health()
        elif path == "/metrics":
            self._metrics()
        else:
            self._send_json(404, {"error": "not_found"})

    # silence default logging
    def log_message(self, *args) -> None:
        return


# =========================================================
# TLS helpers
# =========================================================

def resolve_tls(cert: Optional[str], key: Optional[str]):
    return (
        cert or os.getenv("ADMIN_TLS_CERT"),
        key or os.getenv("ADMIN_TLS_KEY"),
    )


def build_ssl_context(cert: Optional[str], key: Optional[str]):
    if not cert or not key:
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(cert, key)
    return ctx


# =========================================================
# Server lifecycle
# =========================================================

@contextmanager
def create_admin_server(cfg: AdminServerConfig):
    cert, key = resolve_tls(cfg.certfile, cfg.keyfile)
    ctx = build_ssl_context(cert, key)

    server = HTTPServer((cfg.host, cfg.port), AdminHTTPHandler)

    if ctx:
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        server.is_tls = True
    else:
        server.is_tls = False

    try:
        yield server
    finally:
        server.server_close()


# =========================================================
# Start function
# =========================================================

def start_admin_api(
    host="127.0.0.1",
    port=9000,
    certfile=None,
    keyfile=None,
    debug=False,
):
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    cfg = AdminServerConfig(host, port, certfile, keyfile)

    with create_admin_server(cfg) as server:
        scheme = "https" if getattr(server, "is_tls", False) else "http"
        logger.info("Admin API running at %s://%s:%s", scheme, host, port)
        server.serve_forever()


# =========================================================
# CLI
# =========================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser("Security Proxy Admin API")

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--certfile")
    parser.add_argument("--keyfile")
    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()

    start_admin_api(
        host=args.host,
        port=args.port,
        certfile=args.certfile,
        keyfile=args.keyfile,
        debug=args.debug,
    )
