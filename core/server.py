import threading
from observability.api import start_admin_api
from observability.dashboard import start_dashboard

def main():
    # Start Admin API
    threading.Thread(
        target=start_admin_api,
        kwargs={"host": "127.0.0.1", "port": 9000},
        daemon=True
    ).start()

    # Start Dashboard
    threading.Thread(
        target=start_dashboard,
        kwargs={"host": "127.0.0.1", "port": 9100},
        daemon=True
    ).start()

    # Start security proxy
    from core.listener import ProxyListener
    proxy = ProxyListener(host="127.0.0.1", port=8888)
    proxy.start()

