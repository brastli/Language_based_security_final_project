import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""MD5 口令哈希 — 确定性刻画 + 禁止 MD5。"""

import inspect

from vulnerable import hash_password


def test_same_password_same_digest():
    a = hash_password("secret123")
    b = hash_password("secret123")
    assert a == b and isinstance(a, str) and len(a) == 32


def test_must_not_use_md5_for_password_storage():
    src = inspect.getsource(hash_password).lower()
    assert "md5" not in src
