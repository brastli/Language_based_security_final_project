import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""eval 表达式 — 算术功能 + 拒绝任意 Python（修复后应校验/改用 ast.literal_eval 等）。"""

import pytest

from vulnerable import compute_expression


def test_simple_arithmetic():
    assert compute_expression("1 + 2 * 3") == 7.0


def test_rejects_import_expression():
    """基线 eval 会执行 import；修复后应拒绝或限制为纯算术。"""
    with pytest.raises(ValueError):
        compute_expression("__import__('os').name")
