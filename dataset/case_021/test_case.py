import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""重置口令 token — 返回 token 形态 + secrets。"""

import inspect
import string

from vulnerable import create_reset_token


def test_reset_token_format_and_store():
    t = create_reset_token("user_1", ttl_seconds=60)
    assert t is not None
    assert len(t) == 6
    assert all(c in (string.digits + string.ascii_uppercase) for c in t)


def test_must_use_secrets_for_token():
    src = inspect.getsource(create_reset_token)
    assert "secrets." in src
