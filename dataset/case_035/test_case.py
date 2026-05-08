import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""eval 输入 — 算术 + 拒绝代码对象。"""

import pytest

from vulnerable import evalInput


def test_simple_math():
    assert evalInput("3 * 4") == 12


def test_rejects_non_literal_expression():
    with pytest.raises(ValueError):
        evalInput("__import__('os').name")
