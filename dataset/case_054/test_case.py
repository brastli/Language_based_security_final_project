import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""MD5 摘要库存储 — 调用链刻画 + 禁止 MD5。"""

import inspect
from unittest.mock import MagicMock

import vulnerable as v


def test_store_password_invokes_update_stub():
    v.updateUserLogin = MagicMock()
    v.storePassword("u", b"pw")
    v.updateUserLogin.assert_called_once()


def test_must_not_use_md5_digest():
    src = inspect.getsource(v.storePassword).lower()
    assert "md5" not in src
