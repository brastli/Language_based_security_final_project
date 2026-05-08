import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
case_001 测试分层说明：

本文件用于安全验收：
- 保证常见表达式仍然正确执行；
- 同时验证危险表达式不再被执行。

这类测试不能穷尽证明“完全安全”，但可以作为漏洞修复后的行为约束。
"""

import ast
import pytest

from vulnerable import run


def test_evaluates_simple_expression():
    assert run("1+2") == 3


def test_evaluates_conditional_expression():
    assert run("1 if True else 2") == 1


def test_rejects_import_execution():
    """危险导入表达式应被拒绝，而不是被 eval 执行。"""
    with pytest.raises(Exception):
        run("__import__('os').getcwd()")


def test_rejects_dunder_attribute_execution():
    """危险的属性访问/调用链应被拒绝，防止任意对象遍历与执行。"""
    with pytest.raises(Exception):
        run("().__class__.__mro__[1].__subclasses__()")




def test_literal_eval_rejects_conditional_expression():
    """文档化：保证基准对照与上一测试逻辑一致。"""
    with pytest.raises(ValueError):
        ast.literal_eval("1 if True else 2")
