import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")

"""注册 MD5 — 成功路径刻画 + 禁止 MD5 存储口令。"""

import inspect
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("MySQLdb")

import vulnerable as v


def test_register_new_user_success():
    v.app.testing = True
    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.cursor.return_value = mock_cursor
    with patch("MySQLdb.connect", return_value=mock_db):
        with v.app.test_client() as client:
            resp = client.post(
                "/register",
                data={"username": "newuser", "password": "secret"},
            )
            assert resp.status_code == 200
            assert b"success" in resp.data.lower()


def test_must_not_use_md5_for_password():
    src = inspect.getsource(v.register).lower()
    assert "md5" not in src
