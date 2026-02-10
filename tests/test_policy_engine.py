import unittest
from security.policy_engine import PolicyEngine
from security.rules import RULES
from core.request import ProxyRequest

class TestPolicyEngine(unittest.TestCase):

    def setUp(self):
        self.engine = PolicyEngine()
        RULES.blocked_ips.clear()
        RULES.blocked_domains.clear()
        RULES.blocked_ports.clear()
        RULES.blocked_methods.clear()

    def test_blocked_ip(self):
        RULES.blocked_ips.append("1.2.3.4")
        req = ProxyRequest("GET", "example.com", 80, "/", b"")
        decision = self.engine.evaluate(req, "1.2.3.4")
        self.assertEqual(decision.action, "BLOCK")

    def test_blocked_domain(self):
        RULES.blocked_domains.append("evil.com")
        req = ProxyRequest("GET", "evil.com", 80, "/", b"")
        decision = self.engine.evaluate(req, "8.8.8.8")
        self.assertEqual(decision.action, "BLOCK")

    def test_allowed_request(self):
        req = ProxyRequest("GET", "google.com", 80, "/", b"")
        decision = self.engine.evaluate(req, "8.8.8.8")
        self.assertEqual(decision.action, "ALLOW")

if __name__ == "__main__":
    unittest.main()
