import unittest

from observerbility.metrics import metrics


class TestMetrics(unittest.TestCase):

    def test_increment(self):
        start = metrics.counters.get("blocked", 0)
        metrics.inc("blocked")
        self.assertEqual(metrics.counters["blocked"], start + 1)

    def test_snapshot(self):
        snap = metrics.snapshot()
        self.assertIsInstance(snap, dict)
        self.assertIn("uptime", snap)

if __name__ == "__main__":
    unittest.main()
