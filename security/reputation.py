class ReputationEngine:
    def __init__(self):
        self.blocked_domains = {
            "malware.test",
            "phishing.test",
            "badexample.com"
        }

        self.blocked_ips = {
            "10.10.10.10"
        }

    def is_domain_blocked(self, domain):
        return domain.lower() in self.blocked_domains

    def is_ip_blocked(self, ip):
        return ip in self.blocked_ips
