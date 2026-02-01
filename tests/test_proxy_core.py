import unittest
import socket

class TestProxyCore(unittest.TestCase):

    def test_proxy_listening(self):
        s = socket.socket()
        s.connect(("127.0.0.1", 8888))
        s.send(b"GET https://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data = s.recv(1024)
        self.assertTrue(data)
        s.close()

if __name__ == "__main__":
    unittest.main()
