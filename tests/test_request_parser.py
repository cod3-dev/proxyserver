import unittest
from core.request import ProxyRequest

class TestRequestParser(unittest.TestCase):

    def test_basic_parse(self):
        raw = b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = ProxyRequest.from_raw(raw)

        self.assertEqual(req.method, "GET")
        self.assertEqual(req.host, "example.com")
        self.assertEqual(req.port, 80)

if __name__ == "__main__":
    unittest.main()
