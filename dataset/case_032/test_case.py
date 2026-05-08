import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""SQL 拼接 SELECT — 返回一行 + 参数绑定。"""

from unittest.mock import MagicMock, patch

from vulnerable import show_user


def test_show_user_fetches_row():
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = ("alice",)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    with patch("vulnerable.get_connection", return_value=mock_conn):
        assert show_user("alice") == ("alice",)


def test_select_uses_parameter_binding():
    mock_cursor = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    with patch("vulnerable.get_connection", return_value=mock_conn):
        show_user("bob")
        assert len(mock_cursor.execute.call_args[0]) >= 2
