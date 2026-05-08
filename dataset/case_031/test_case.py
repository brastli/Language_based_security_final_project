import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""SQL 拼接 DELETE — 执行刻画 + 参数绑定。"""

from unittest.mock import MagicMock, patch

from vulnerable import remove_user


def test_remove_calls_execute():
    mock_cursor = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    with patch("vulnerable.get_connection", return_value=mock_conn):
        remove_user("alice")
        mock_cursor.execute.assert_called_once()


def test_delete_uses_parameter_binding_not_percent_format():
    mock_cursor = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    with patch("vulnerable.get_connection", return_value=mock_conn):
        remove_user("alice")
        args = mock_cursor.execute.call_args[0]
        assert len(args) >= 2
