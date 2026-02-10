import unittest
from security.decisions import SecurityDecision


class TestSecurityDecision(unittest.TestCase):

    def test_fields_and_to_dict(self):
        d = SecurityDecision("BLOCK", "RATE_LIMIT", "RL-01", 7)
        self.assertEqual(d.action, "BLOCK")
        self.assertEqual(d.reason, "RATE_LIMIT")
        self.assertEqual(d.code, "RL-01")
        self.assertEqual(d.severity, 7)

        expected = {
            "action": "BLOCK",
            "reason": "RATE_LIMIT",
            "code": "RL-01",
            "severity": 7,
        }
        self.assertEqual(d.to_dict(), expected)

    def test_str_contains_action_and_code(self):
        d = SecurityDecision("ALLOW", "OK", "CORE-00", 0)
        s = str(d)
        self.assertIn("ALLOW", s)
        self.assertIn("CORE-00", s)


if __name__ == "__main__":
    unittest.main()
