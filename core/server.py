import threading
from core.listener import ProxyListener
from observability.api import start_admin_api


def main():
    # Start admin / observability API
    threading.Thread(
        target=start_admin_api,
        kwargs={"host": "127.0.0.1", "port": 9000},
        daemon=True
    ).start()

    # Start security proxy
    proxy = ProxyListener(host="127.0.0.1", port=8888)
    proxy.start()


if __name__ == "__main__":
    main()
