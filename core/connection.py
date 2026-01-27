import socket
from core.parser import HTTPParser
from core.forwarder import Forwarder

from security.policy_engine import PolicyEngine
from observability.logger import SecurityLogger
from observability.metrics import Metrics
from observability.alerts import AlertManager

BUFFER_SIZE = 4096

policy = PolicyEngine()
logger = SecurityLogger()
metrics = Metrics()
alerts = AlertManager()


class ClientConnection:
    def __init__(self, client_socket, address):
        self.client = client_socket
        self.address = address
        self.client.settimeout(10)

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

            # 🔐 SECURITY DECISION
            decision = policy.evaluate(request, self.address[0])

            log_data = {
                "client": self.address[0],
                "method": request.method,
                "host": request.host,
                "port": request.port,
                "action": decision.action,
                "reason": decision.reason,
                "rule": decision.rule_id
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

            # 🚦 FORWARD IF ALLOWED
            forwarder = Forwarder(self.client, request)
            forwarder.process()
            metrics.inc("allowed")

        except Exception as e:
            print("[ERROR]", e)
            self.client.close()
