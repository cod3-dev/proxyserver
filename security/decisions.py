from dataclasses import dataclass, asdict
from typing import Dict


@dataclass(eq=True, frozen=False)
class SecurityDecision:
    """A simple value object for security decisions produced by the policy engine.

    Fields:
    - action: str (e.g. "ALLOW", "BLOCK", "ALERT")
    - reason: str (human readable reason or comma-separated list)
    - code: str (short machine-readable code, e.g. "REP-01")
    - severity: int (0-10 scale)
    """
    action: str
    reason: str
    code: str
    severity: int

    def to_dict(self) -> Dict[str, object]:
        """Return a plain dict representation suitable for JSON encoding.
        """
        return asdict(self)

    def __str__(self) -> str:
        return f"SecurityDecision(action={self.action}, code={self.code}, severity={self.severity})"
