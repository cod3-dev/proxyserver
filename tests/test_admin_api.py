import unittest
import requests

class TestAdminAPI(unittest.TestCase):

    def test_health(self):
        r = requests.get("http://127.0.0.1:9000/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "UP")

    def test_metrics(self):
        r = requests.get("http://127.0.0.1:9000/metrics")
        self.assertEqual(r.status_code, 200)

if __name__ == "__main__":
    unittest.main()
