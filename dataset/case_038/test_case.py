import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""管理员口令明文比对 — 允许登录刻画 + 禁止明文常量比对。"""

import inspect

from vulnerable import checkAdminPassword


def test_builtin_admin_password_matches():
    assert checkAdminPassword("admin") is True


def test_must_not_compare_plaintext_literal_password():
    src = inspect.getsource(checkAdminPassword)
    assert 'password == "admin"' not in src
