import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""管理员口令字面量 — 登录刻画 + 禁止字面量 admin 口令比对。"""

import inspect
import re
from unittest.mock import MagicMock

from vulnerable import admin_access


def test_admin_credentials_grant_access():
    req = MagicMock()
    req.POST.get.side_effect = lambda k, default=None: {
        "user_name": "admin",
        "password": "admin",
    }.get(k, default)
    assert admin_access(req) is True


def test_must_not_compare_literal_admin_password_pair():
    src = inspect.getsource(admin_access)
    assert not re.search(r"password\s*==\s*['\"]admin['\"]", src)
