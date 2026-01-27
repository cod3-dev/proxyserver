import unittest
from security.rules import SecurityRuleSet

class TestRules(unittest.TestCase):

    def test_rules_creation(self):
        rules = SecurityRuleSet(["x.com"], ["1.1.1.1"], [22], ["TRACE"])
        self.assertIn("x.com", rules.blocked_domains)

    def test_rules_serialization(self):
        rules = SecurityRuleSet(["evil.com"], [], [], [])
        rules.save_to_file("test_rules.yaml")

        loaded = SecurityRuleSet.load_from_file("test_rules.yaml")
        self.assertIn("evil.com", loaded.blocked_domains)

if __name__ == "__main__":
    unittest.main()
