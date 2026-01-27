class ThreatDetector:
    def __init__(self):
        self.suspicious_paths = ["/admin", "/login", "/wp-admin", "/.env"]

    def analyze(self, ctx):
        findings = []

        if ctx.path:
            for p in self.suspicious_paths:
                if ctx.path.lower().startswith(p):
                    findings.append("SUSPICIOUS_PATH")

        if "user-agent" in ctx.headers:
            ua = ctx.headers["user-agent"].lower()
            if "sqlmap" in ua or "nikto" in ua:
                findings.append("SCANNER_USER_AGENT")

        return findings
