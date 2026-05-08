import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""会话 token — 长度与字符集 + secrets。"""

import inspect
import string

from vulnerable import generate_session_token


def test_token_length_and_alphanumeric():
    t = generate_session_token()
    assert len(t) == 32
    assert all(c in (string.ascii_letters + string.digits) for c in t)


def test_must_use_secrets_module():
    src = inspect.getsource(generate_session_token)
    assert "secrets." in src
