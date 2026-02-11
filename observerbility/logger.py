import logging
import json
from datetime import datetime

class SecurityLogger:
    def __init__(self, logfile="security.log"):
        self.logger = logging.getLogger("SECURITY_PROXY")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(logfile)
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)

    def log(self, event_type, data: dict):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            **data
        }
        self.logger.info(json.dumps(entry, ensure_ascii=False, default=str))
