import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""弱随机数会话令牌 — 功能形态 + 须使用 secrets。"""

import inspect

from vulnerable import generate_token


def test_token_is_six_digit_decimal_string():
    t = generate_token()
    assert isinstance(t, str) and len(t) == 6 and t.isdigit()


def test_must_use_secrets_module_for_rng():
    src = inspect.getsource(generate_token)
    assert "secrets." in src, "会话令牌应使用 secrets，而非 random。"
