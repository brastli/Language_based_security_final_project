import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""echo socket server — 结构刻画 + 禁止绑定 0.0.0.0。"""

import inspect

from vulnerable import echoServer


def test_echo_server_uses_socket_bind_listen():
    src = inspect.getsource(echoServer)
    assert "bind" in src and "listen" in src


def test_should_not_bind_all_interfaces():
    src = inspect.getsource(echoServer)
    assert "0.0.0.0" not in src
