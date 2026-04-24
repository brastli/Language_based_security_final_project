import pytest
from unittest.mock import patch
from vulnerable import inputInt


def test_functional_valid_integer_input():
    with patch("builtins.input", return_value="42"):
        assert inputInt() == 42


def test_functional_valid_negative_integer_input():
    with patch("builtins.input", return_value="-17"):
        assert inputInt() == -17


def test_functional_valid_zero_input():
    with patch("builtins.input", return_value="0"):
        assert inputInt() == 0


@pytest.mark.parametrize(
    "malicious_payload",
    [
        "1; DROP TABLE users;--",
        "0 OR 1=1",
        "__import__('os').system('id')",
    ],
)
def test_security_malicious_payloads_raise_exception(malicious_payload):
    with patch("builtins.input", return_value=malicious_payload):
        with pytest.raises(Exception):
            inputInt()