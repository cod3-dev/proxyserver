from core.parser import HTTPParser
from core.forwader import Forwarder

from security.policy_engine import PolicyEngine
from security.auth import check_basic_auth, resolve_basic_auth
from observerbility import SecurityLogger, metrics, AlertManager

BUFFER_SIZE = 4096

policy = PolicyEngine()
logger = SecurityLogger()
# metrics is a module-level singleton
alerts = AlertManager()


class ClientConnection:
    def __init__(self, client_socket, address):
        self.client = client_socket
        self.address = address
        self.client.settimeout(10)

    def _send_response(self, status_line: str, headers=None):
        headers = headers or {}
        header_blob = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        payload = f"{status_line}\r\n{header_blob}\r\n".encode()
        self.client.sendall(payload)

    @staticmethod
    def _sanitize_request(request):
        if request.is_connect or "proxy-authorization" not in request.headers:
            return request

        header_block, _, body = request.raw.partition(b"\r\n\r\n")
        lines = header_block.split(b"\r\n")
        if not lines:
            return request

        request_line = f"{request.method} {request.path} {request.version}".encode()
        filtered = [request_line]
        for line in lines[1:]:
            if line.lower().startswith(b"proxy-authorization:"):
                continue
            filtered.append(line)

        request.raw = b"\r\n".join(filtered) + b"\r\n\r\n" + body
        return request

    def handle(self):
        try:
            metrics.inc("connections")

            raw = self.client.recv(BUFFER_SIZE)
            if not raw:
                self.client.close()
                return

            request = HTTPParser.parse(raw)
            if not request:
                self.client.close()
                return

            try:
                auth_config = resolve_basic_auth("PROXY")
            except RuntimeError as exc:
                logger.log("AUTH_ERROR", {"client": self.address[0], "error": str(exc)})
                metrics.inc("auth_errors")
                self._send_response("HTTP/1.1 500 Internal Server Error", {"Content-Length": "0"})
                self.client.close()
                return

            if auth_config:
                if not check_basic_auth(request.headers.get("proxy-authorization"), *auth_config):
                    metrics.inc("auth_failed")
                    self._send_response(
                        "HTTP/1.1 407 Proxy Authentication Required",
                        {
                            "Proxy-Authenticate": 'Basic realm="security-proxy"',
                            "Content-Length": "0",
                        },
                    )
                    self.client.close()
                    return

                request = self._sanitize_request(request)

            # ðŸ” SECURITY DECISION
            decision = policy.evaluate(request, self.address[0])

            log_data = {
                "client": self.address[0],
                "method": request.method,
                "host": request.host,
                "port": request.port,
                "action": decision.action,
                "reason": getattr(decision, "reason", None),
                "code": getattr(decision, "code", None),
            }

            logger.log("REQUEST", log_data)

            if decision.action == "BLOCK":
                metrics.inc("blocked")
                alerts.raise_alert("HIGH", "Request blocked", log_data)
                self.client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                self.client.close()
                return

            if decision.action == "ALERT":
                metrics.inc("alerts")
                alerts.raise_alert("MEDIUM", "Suspicious traffic", log_data)

            # ðŸš¦ FORWARD IF ALLOWED
            forwarder = Forwarder(self.client, request)
            forwarder.process()
            metrics.inc("allowed")

        except Exception as e:
            print("[ERROR]", e)
            try:
                self.client.close()
            except Exception:
                pass
