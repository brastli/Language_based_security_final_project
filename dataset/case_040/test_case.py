import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""SSL 客户端 — 建立连接刻画 + 使用现代 TLS 上下文。"""

import inspect
import ssl
from unittest.mock import MagicMock, patch

from vulnerable import connect


def test_returns_ssl_socket():
    with patch("ssl.wrap_socket") as w:
        with patch("socket.socket") as ms:
            ms.return_value = MagicMock()
            mock_ssl = MagicMock()
            w.return_value = mock_ssl
            s = connect("127.0.0.1", 443)
            assert s is mock_ssl


def test_should_use_ssl_create_default_context():
    """基线典型为 ssl.wrap_socket；修复后推荐 SSLContext / create_default_context。"""
    src = inspect.getsource(connect)
    assert "create_default_context" in src or "SSLContext" in src
