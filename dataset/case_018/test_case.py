import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""marshal.loads — 简单 dict + 建议改用 json / 签名校验。"""

import inspect
import marshal

from vulnerable import load_cached_preferences


def test_dict_roundtrip():
    b = marshal.dumps({"x": 1})
    assert load_cached_preferences(b) == {"x": 1}


def test_should_avoid_raw_marshal_on_untrusted_bytes():
    src = inspect.getsource(load_cached_preferences)
    assert "marshal.loads" not in src or "json.loads" in src or "sign" in src.lower()
