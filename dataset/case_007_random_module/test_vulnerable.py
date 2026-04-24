import pytest
import vulnerable
from vulnerable import generate_token


def test_functional_generate_token_returns_string():
    token = generate_token()
    assert isinstance(token, str)


def test_functional_generate_token_is_six_digits():
    token = generate_token()
    assert token.isdigit()
    assert len(token) == 6
    assert 100000 <= int(token) <= 999999


def test_functional_generate_token_multiple_calls_produce_valid_tokens():
    tokens = [generate_token() for _ in range(10)]
    assert all(isinstance(token, str) for token in tokens)
    assert all(token.isdigit() and len(token) == 6 for token in tokens)
    assert all(100000 <= int(token) <= 999999 for token in tokens)


def test_security_generate_token_rejects_malicious_payloads(monkeypatch):
    malicious_payloads = [
        "__import__('os').system('id')",
        "'; DROP TABLE users; --",
        "$(rm -rf /)",
    ]

    for payload in malicious_payloads:
        def fake_randbelow(_):
            raise Exception(f"Rejected malicious payload: {payload}")

        monkeypatch.setattr(vulnerable.secrets, "randbelow", fake_randbelow)
        with pytest.raises(Exception):
            generate_token()