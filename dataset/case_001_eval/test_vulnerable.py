import pytest
from vulnerable import run


def test_functional_arithmetic_operations():
    assert run("1 + 2 * 3 - 4 / 2") == 5.0
    assert run("10 // 3") == 3
    assert run("10 % 3") == 1
    assert run("2 ** 5") == 32


def test_functional_bitwise_operations():
    assert run("5 | 2") == 7
    assert run("5 & 3") == 1
    assert run("5 ^ 3") == 6
    assert run("1 << 3") == 8
    assert run("8 >> 2") == 2


def test_functional_unary_operations():
    assert run("-5") == -5
    assert run("+5") == 5
    assert run("not False") is True
    assert run("~1") == -2


def test_functional_allowed_builtins_and_literals():
    assert run("abs(-7)") == 7
    assert run("round(3.14159, 2)") == 3.14
    assert run("min(3, 1, 2)") == 1
    assert run("max(3, 1, 2)") == 3
    assert run("sum([1, 2, 3])") == 6
    assert run("len('abcd')") == 4
    assert run("sorted([3, 1, 2])") == [1, 2, 3]
    assert run("tuple([1, 2])") == (1, 2)
    assert run("list((1, 2))") == [1, 2]
    assert run("dict([('a', 1), ('b', 2)])") == {"a": 1, "b": 2}
    assert run("set([1, 2, 2])") == {1, 2}
    assert run("bool(0)") is False
    assert run("int('42')") == 42
    assert run("float('2.5')") == 2.5
    assert run("str(123)") == "123"


def test_functional_containers_and_nested_expressions():
    assert run("(1, 2, 3)") == (1, 2, 3)
    assert run("[1, 2, 3]") == [1, 2, 3]
    assert run("{'a': 1, 'b': 2}") == {"a": 1, "b": 2}
    assert run("{1, 2, 3}") == {1, 2, 3}
    assert run("sum([1, 2, 3]) + len([4, 5])") == 8
    assert run("max([1, 5, 3]) * min(10, 2)") == 10


@pytest.mark.parametrize(
    "payload",
    [
        "__import__('os').system('id')",
        "open('/etc/passwd').read()",
        "eval('2 + 2')",
    ],
)
def test_security_malicious_payloads_raise(payload):
    with pytest.raises(Exception):
        run(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "1; import os",
        "1 and __import__('os').system('id')",
        "'; DROP TABLE users; --",
    ],
)
def test_security_injection_style_payloads_raise(payload):
    with pytest.raises(Exception):
        run(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "abs(x=1)",
        "sum(iterable=[1, 2, 3])",
        "dict(a=1)",
    ],
)
def test_security_keyword_argument_abuse_raises(payload):
    with pytest.raises(Exception):
        run(payload)