import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""银行查询 SQL 拼接 — 授权后查询 + 参数化 execute。"""

from unittest.mock import MagicMock, patch

from vulnerable import getUserBankAccount


def test_returns_result_when_authorized():
    conn = MagicMock()
    conn.execute.return_value = {"id": 1}
    with patch("vulnerable.isAuthorizedUser", return_value=True):
        assert getUserBankAccount("u1", conn) == {"id": 1}


def test_execute_accepts_bound_parameters_tuple():
    conn = MagicMock()
    with patch("vulnerable.isAuthorizedUser", return_value=True):
        getUserBankAccount("alice", conn)
        args = conn.execute.call_args[0]
        assert len(args) >= 2
