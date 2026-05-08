import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""MySQL 连接 — 返回连接对象 + 凭证须来自环境变量。"""

import inspect
from unittest.mock import MagicMock, patch

from vulnerable import getConnection


def test_returns_connection_object():
    with patch("mysql.connector.connect", return_value=MagicMock()):
        assert getConnection() is not None


def test_must_read_credentials_from_environment():
    src = inspect.getsource(getConnection)
    assert "os.environ" in src or "getenv" in src
