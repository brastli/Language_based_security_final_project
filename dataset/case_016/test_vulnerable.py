import pytest

from vulnerable import compute_expression


def test_functional_basic_arithmetic():
    assert compute_expression("1+2*3") == 7.0


def test_functional_parentheses_and_precedence():
    assert compute_expression("(1+2)*3") == 9.0


def test_functional_division_returns_float():
    assert compute_expression("7/2") == 3.5


def test_functional_floor_division_mod_pow():
    assert compute_expression("7//2") == 3.0
    assert compute_expression("7%4") == 3.0
    assert compute_expression("2**3") == 8.0


def test_functional_unary_operations():
    assert compute_expression("-5") == -5.0
    assert compute_expression("+5") == 5.0
    assert compute_expression("--5") == 5.0


def test_functional_whitespace_and_empty_inputs():
    assert compute_expression("   4 + 1   ") == 5.0
    assert compute_expression("") is None
    assert compute_expression("   ") is None
    assert compute_expression(None) is None


@pytest.mark.parametrize(
    "payload",
    [
        "__import__('os').system('echo hacked')",
        "1; import os; os.system('echo hacked')",
        "1 + (lambda: 2)()",
    ],
)
def test_security_malicious_payloads_rejected(payload):
    with pytest.raises(Exception):
        compute_expression(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "open('/etc/passwd').read()",
        "().__class__.__mro__",
        "1 + [x for x in range(3)]",
    ],
)
def test_security_unsafe_python_constructs_rejected(payload):
    with pytest.raises(Exception):
        compute_expression(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "2**1000000",
        "10/0",
        "9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
    ],
)
def test_security_resource_abuse_and_error_payloads_rejected(payload):
    with pytest.raises(Exception):
        compute_expression(payload)