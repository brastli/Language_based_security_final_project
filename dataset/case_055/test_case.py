import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""MySQL 连接 — 返回连接 + 凭证来自环境。"""

import inspect
from unittest.mock import MagicMock, patch

from vulnerable import getDBConnection


def test_returns_connection():
    with patch("mysql.connector.connect", return_value=MagicMock()):
        assert getDBConnection() is not None


def test_must_read_credentials_from_environment():
    src = inspect.getsource(getDBConnection)
    assert "os.environ" in src or "getenv" in src
