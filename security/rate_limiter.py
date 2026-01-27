import time
from collections import defaultdict, deque

class RateLimiter:
    def __init__(self, max_requests=60, window=60):
        self.max_requests = max_requests
        self.window = window
        self.clients = defaultdict(deque)

    def allow(self, client_ip):
        now = time.time()
        q = self.clients[client_ip]

        while q and q[0] < now - self.window:
            q.popleft()

        if len(q) >= self.max_requests:
            return False

        q.append(now)
        return True
