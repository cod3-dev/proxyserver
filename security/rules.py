import yaml
from dataclasses import dataclass
from pathlib import Path

RULES_FILE = Path("config/rules.yaml")

@dataclass
class SecurityRuleSet:
    blocked_domains: list
    blocked_ips: list
    blocked_ports: list
    blocked_methods: list

    @staticmethod
    def load_from_file(file_path=RULES_FILE):
        if not file_path.exists():
            return SecurityRuleSet([], [], [], [])
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)
        return SecurityRuleSet(
            blocked_domains=data.get("blocked_domains", []),
            blocked_ips=data.get("blocked_ips", []),
            blocked_ports=data.get("blocked_ports", []),
            blocked_methods=data.get("blocked_methods", [])
        )

    def save_to_file(self, file_path=RULES_FILE):
        data = {
            "blocked_domains": self.blocked_domains,
            "blocked_ips": self.blocked_ips,
            "blocked_ports": self.blocked_ports,
            "blocked_methods": self.blocked_methods
        }
        with open(file_path, "w") as f:
            yaml.dump(data, f)

# Global singleton for in-memory access
RULES = SecurityRuleSet.load_from_file()
