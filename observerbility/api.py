from urllib.parse import parse_qs
from security.rules import RULES, SecurityRuleSet, RULES_FILE
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from observability.metrics import metrics
from security.rules import RULES, SecurityRuleSet, RULES_FILE

class AdminHandler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        self.blocked_domains = RULES.blocked_domains
        self.blocked_ips = RULES.blocked_ips
        self.blocked_ports = RULES.blocked_ports
        self.blocked_methods = RULES.blocked_methods

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {
                "status": "UP",
                "service": "Security Proxy",
            })
        elif self.path == "/metrics":
            self._send(200, metrics.snapshot())
        elif self.path == "/rules":
            rules_dict = {
                "blocked_domains": RULES.blocked_domains,
                "blocked_ips": RULES.blocked_ips,
                "blocked_ports": RULES.blocked_ports,
                "blocked_methods": RULES.blocked_methods
            }
            self._send(200, rules_dict)
        else:
            self._send(404, {"error": "Not found"})

    def do_POST(self):
        if self.path == "/rules/reload":
            global RULES
            RULES = SecurityRuleSet.load_from_file()
            self._send(200, {"status": "reloaded"})
            return

        if self.path == "/rules":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            data = json.loads(body)

            # Add new items dynamically
            for key in ["blocked_domains", "blocked_ips", "blocked_ports", "blocked_methods"]:
                if key in data:
                    current_list = getattr(RULES, key)
                    for item in data[key]:
                        if item not in current_list:
                            current_list.append(item)
            # Save back to file
            RULES.save_to_file()
            self._send(200, {"status": "updated"})
            return

        self._send(404, {"error": "Not found"})

    def do_DELETE(self):
        if self.path == "/rules":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            data = json.loads(body)

            for key in ["blocked_domains", "blocked_ips", "blocked_ports", "blocked_methods"]:
                if key in data:
                    current_list = getattr(RULES, key)
                    for item in data[key]:
                        if item in current_list:
                            current_list.remove(item)
            RULES.save_to_file()
            self._send(200, {"status": "deleted"})
            return

        self._send(404, {"error": "Not found"})

    def log_message(self, format, *args):
        return  # silence logs
