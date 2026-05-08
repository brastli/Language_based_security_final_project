import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""数据库口令比对 — 用户不存在 + 须使用慢哈希校验而非明文/base64 比对。"""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("MySQLdb")

from vulnerable import checkPassword


def test_returns_false_when_user_missing():
    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.cursor.return_value = mock_cursor
    with patch("MySQLdb.connect", return_value=mock_db):
        assert checkPassword("nouser", "pw") is False


def test_must_use_password_hash_verify_not_plain_compare():
    import inspect

    src = inspect.getsource(checkPassword).lower()
    assert "bcrypt" in src or "argon2" in src or "pbkdf2" in src or "scrypt" in src
