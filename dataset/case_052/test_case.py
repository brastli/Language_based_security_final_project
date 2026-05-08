import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""input 转 int — 返回整数 + 不得依赖 assert 做类型安全。"""

import inspect
from unittest.mock import patch

from vulnerable import inputInt


def test_returns_parsed_integer():
    with patch("builtins.input", return_value="99"):
        assert inputInt() == 99


def test_should_validate_without_assert_type_only():
    src = inspect.getsource(inputInt)
    assert "assert type" not in src.lower()
