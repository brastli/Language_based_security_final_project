import pytest
from vulnerable import evalInput


def test_functional_arithmetic_operations():
    assert evalInput("1 + 2 * 3 - 4 / 2") == 5.0
    assert evalInput("10 // 3") == 3
    assert evalInput("10 % 3") == 1
    assert evalInput("2 ** 3") == 8


def test_functional_unary_operations():
    assert evalInput("-5") == -5
    assert evalInput("+7") == 7
    assert evalInput("--5") == 5


def test_functional_literals_and_collections():
    assert evalInput("42") == 42
    assert evalInput("'hello'") == "hello"
    assert evalInput("[1, 2, 3]") == [1, 2, 3]
    assert evalInput("(1, 2, 3)") == (1, 2, 3)
    assert evalInput("{'a': 1, 'b': 2}") == {"a": 1, "b": 2}


def test_functional_allowed_builtins():
    assert evalInput("abs(-10)") == 10
    assert evalInput("round(3.14159, 2)") == 3.14
    assert evalInput("min(3, 1, 2)") == 1
    assert evalInput("max(3, 1, 2)") == 3
    assert evalInput("sum([1, 2, 3])") == 6
    assert evalInput("len([1, 2, 3, 4])") == 4


def test_security_malicious_payloads_rejected():
    malicious_payloads = [
        "__import__('os').system('id')",
        "open('/etc/passwd').read()",
        "eval('2 + 2')",
        "abs(x=1)",
        "().__class__.__mro__",
        "lambda x: x",
        "1; import os",
        "min.__globals__",
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            evalInput(payload)


def test_security_command_injection_like_payloads_rejected():
    malicious_payloads = [
        "1 and __import__('os').system('echo hacked')",
        "'; rm -rf /",
        "max(1, 2, __import__('subprocess').Popen('whoami', shell=True))",
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            evalInput(payload)


def test_security_sqli_like_payloads_rejected():
    malicious_payloads = [
        "' OR '1'='1",
        "\"; DROP TABLE users; --",
        "1 or 1=1",
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            evalInput(payload)