# Compatibility shim for code that imports `observability` while the implementation lives in `observerbility`.
# Re-export the public entrypoints used by the core proxy.
from observerbility.alerts import AlertManager
from observerbility.api import start_admin_api
from observerbility.dashboard import start_dashboard
from observerbility.logger import SecurityLogger
from observerbility.metrics import metrics, snapshot as snapshot_metrics

__all__ = [
    "AlertManager",
    "SecurityLogger",
    "metrics",
    "snapshot_metrics",
    "start_admin_api",
    "start_dashboard",
]
