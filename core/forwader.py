import socket
import select

BUFFER_SIZE = 4096

class Forwarder:
    def __init__(self, client_socket, request):
        self.client = client_socket
        self.request = request

    def process(self):
        if self.request.is_connect:
            self._handle_connect()
        else:
            self._handle_http()

    def _handle_http(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((self.request.host, self.request.port))
        server.sendall(self.request.raw)

        while True:
            data = server.recv(BUFFER_SIZE)
            if not data:
                break
            self.client.sendall(data)

        server.close()
        self.client.close()

    def _handle_connect(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((self.request.host, self.request.port))

        self.client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._tunnel(self.client, server)

    def _tunnel(self, client, server):
        sockets = [client, server]

        while True:
            readable, _, _ = select.select(sockets, [], [])
            for sock in readable:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    client.close()
                    server.close()
                    return
                if sock is client:
                    server.sendall(data)
                else:
                    client.sendall(data)
