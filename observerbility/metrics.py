import threading
import time
from collections import defaultdict

class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.counters = defaultdict(int)
        self.start_time = time.time()

    def inc(self, name, value=1):
        with self.lock:
            self.counters[name] += value

    def snapshot(self):
        with self.lock:
            uptime = int(time.time() - self.start_time)
            return {
                "uptime": uptime,
                **dict(self.counters)
            }

    def print_stats(self, interval=30):
        while True:
            time.sleep(interval)
            stats = self.snapshot()
            print("[METRICS]", stats)
