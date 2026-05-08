import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""密码生成 — 长度与字符集 + 须使用加密安全随机源。"""

import inspect
import string

from vulnerable import generate_password


def test_password_length_and_charset():
    pw = generate_password(12)
    assert len(pw) == 12
    assert all(c in (string.ascii_letters + string.digits) for c in pw)


def test_must_use_secrets_for_rng():
    src = inspect.getsource(generate_password)
    assert "secrets." in src
