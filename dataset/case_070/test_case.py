import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if "vulnerable" in sys.modules:
    del sys.modules["vulnerable"]
sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import ast

import pytest

from vulnerable import parse_cli_value, str_to_bool_stub


def test_stub_bool():
    assert str_to_bool_stub("true") is True


def test_arithmetic_string_evaluable_by_full_eval():
    assert parse_cli_value("1 + 2") == 3


def test_literal_eval_rejects_non_literal_expression():
    """literal_eval 不接受条件表达式；用于区分「仅换 literal_eval」类修补。"""
    with pytest.raises(ValueError):
        ast.literal_eval("1 if True else 2")


def test_conditional_expression_requires_eval():
    assert parse_cli_value("1 if True else 2") == 1
