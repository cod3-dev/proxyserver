class RequestContext:
    def __init__(self, method, host, port, path, version, headers, raw, is_connect):
        self.method = method
        self.host = host
        self.port = port
        self.path = path
        self.version = version
        self.headers = headers
        self.raw = raw
        self.is_connect = is_connect


class HTTPParser:

    @staticmethod
    def parse(data: bytes):
        try:
            header_block = data.split(b"\r\n\r\n", 1)[0]
            lines = header_block.split(b"\r\n")

            request_line = lines[0].decode()
            method, target, version = request_line.split()

            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.decode().lower()] = v.strip().decode()

            if method.upper() == "CONNECT":
                host, port = target.split(":")
                return RequestContext(method, host, int(port), None, version, headers, data, True)

            host_header = headers.get("host")
            if not host_header:
                return None

            if ":" in host_header:
                host, port = host_header.split(":", 1)
                port = int(port)
            else:
                host = host_header
                port = 80

            return RequestContext(method, host, port, target, version, headers, data, False)

        except Exception:
            return None
