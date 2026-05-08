import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")

"""用户名 cd + ls — 响应刻画 + 禁止 os.system。"""

import inspect
from unittest.mock import mock_open, patch

import vulnerable as v


def test_reply_returns_file_listing():
    v.app.testing = True
    with patch("os.system", return_value=0):
        with patch("builtins.open", mock_open(read_data="file.txt\n")):
            with v.app.test_client() as client:
                resp = client.get("/reply?username=testuser")
                assert resp.status_code == 200
                assert b"file.txt" in resp.data


def test_must_not_use_os_system():
    src = inspect.getsource(v.listFiles)
    assert "os.system" not in src
