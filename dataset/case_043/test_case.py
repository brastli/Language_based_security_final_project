import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""随机字符串 — 长度与字符集 + secrets。"""

import inspect
import string

from vulnerable import generateRandomString


def test_fixed_length_letters():
    s = generateRandomString(10)
    assert len(s) == 10
    assert all(c in string.ascii_letters for c in s)


def test_must_use_secrets_not_random_choice():
    src = inspect.getsource(generateRandomString)
    assert "secrets." in src
