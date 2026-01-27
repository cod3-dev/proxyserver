import socket
from core.connection import ClientConnection

class ProxyListener:
    def __init__(self, host="0.0.0.0", port=8888):
        self.host = host
        self.port = port

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(200)

        print(f"[+] Security proxy listening on {self.host}:{self.port}")

        while True:
            client, addr = sock.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}")
            ClientConnection(client, addr).handle()
