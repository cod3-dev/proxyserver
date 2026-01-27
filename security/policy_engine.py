from security.rules import SecurityDecision
from security.rate_limiter import RateLimiter
from security.reputation import ReputationEngine
from security.detector import ThreatDetector


class PolicyEngine:
    def __init__(self):
        self.rate_limiter = RateLimiter(max_requests=80, window=60)
        self.reputation = ReputationEngine()
        self.detector = ThreatDetector()

        self.blocked_methods = {"TRACE", "TRACK"}
        self.blocked_ports = {22, 23, 445, 3389}

    def evaluate(self, ctx, client_ip):
        # 1. Rate limiting
        if not self.rate_limiter.allow(client_ip):
            return SecurityDecision("BLOCK", "RATE_LIMIT", "RL-01", 7)

        # 2. IP reputation
        if self.reputation.is_ip_blocked(client_ip):
            return SecurityDecision("BLOCK", "BAD_IP", "REP-01", 9)

        # 3. Domain reputation
        if self.reputation.is_domain_blocked(ctx.host):
            return SecurityDecision("BLOCK", "MALICIOUS_DOMAIN", "REP-02", 9)

        # 4. Dangerous methods
        if ctx.method.upper() in self.blocked_methods:
            return SecurityDecision("BLOCK", "METHOD_BLOCKED", "POL-01", 6)

        # 5. Dangerous ports
        if ctx.port in self.blocked_ports:
            return SecurityDecision("BLOCK", "DANGEROUS_PORT", "POL-02", 8)

        # 6. Behavior detection
        findings = self.detector.analyze(ctx)
        if findings:
            return SecurityDecision("ALERT", ",".join(findings), "DET-01", 4)

        return SecurityDecision("ALLOW", "OK", "CORE-00", 0)
