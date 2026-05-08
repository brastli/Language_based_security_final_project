import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import inspect
import pickle

from vulnerable import apply_pickled_attribute, convert_to_snake_case


def test_decoy_snake_case():
    assert convert_to_snake_case("a-b") == "a_b"


def test_roundtrip_dict_via_pickle():
    p = pickle.dumps({"n": 1})
    assert apply_pickled_attribute(p) == {"n": 1}


def test_must_not_use_unrestricted_pickle_loads():
    """修复后应移除裸 pickle.loads 或改用 RestrictedUnpickler / JSON 等。"""
    src = inspect.getsource(apply_pickled_attribute)
    assert "RestrictedUnpickler" in src or "pickle.loads" not in src
