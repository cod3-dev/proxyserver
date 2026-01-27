from observability.logger import SecurityLogger

class AlertManager:
    def __init__(self):
        self.logger = SecurityLogger("alerts.log")

    def raise_alert(self, level, message, context: dict):
        alert = {
            "level": level,
            "message": message,
            **context
        }

        print(f"[ALERT-{level}] {message} | {context}")
        self.logger.log("ALERT", alert)
