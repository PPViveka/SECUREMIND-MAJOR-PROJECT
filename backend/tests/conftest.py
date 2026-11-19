import os
import sys
import pytest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

@pytest.fixture(autouse=True)
def clean_rate_limiter_state():
    try:
        import dev_server
        if hasattr(dev_server, "request_windows") and hasattr(dev_server, "_rate_limit_lock"):
            with dev_server._rate_limit_lock:
                dev_server.request_windows.clear()
    except Exception:
        pass
    yield
    try:
        import dev_server
        if hasattr(dev_server, "request_windows") and hasattr(dev_server, "_rate_limit_lock"):
            with dev_server._rate_limit_lock:
                dev_server.request_windows.clear()
    except Exception:
        pass
