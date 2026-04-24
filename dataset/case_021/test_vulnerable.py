import pytest
import time
import string
import secrets

from vulnerable import create_reset_token, _token_store


@pytest.fixture(autouse=True)
def clear_token_store():
    _token_store.clear()
    yield
    _token_store.clear()


def test_functional_create_reset_token_returns_valid_token():
    token = create_reset_token("user123")
    assert isinstance(token, str)
    assert len(token) == 6
    allowed = set(string.digits + string.ascii_uppercase)
    assert set(token).issubset(allowed)
    assert token in _token_store
    record = _token_store[token]
    assert record["user_id"] == "user123"
    assert record["token"] == token
    assert record["used"] is False
    assert record["expires_at"] > time.time()


def test_functional_create_reset_token_custom_ttl():
    before = time.time()
    token = create_reset_token("alice", ttl_seconds=10)
    assert token is not None
    record = _token_store[token]
    assert before + 9 <= record["expires_at"] <= before + 11


def test_functional_create_reset_token_rejects_invalid_inputs():
    assert create_reset_token("", ttl_seconds=3600) is None
    assert create_reset_token(None, ttl_seconds=3600) is None
    assert create_reset_token("user", ttl_seconds=0) is None
    assert create_reset_token("user", ttl_seconds=-5) is None
    assert _token_store == {}


def test_functional_create_reset_token_stores_unique_tokens_for_multiple_users():
    tokens = {create_reset_token("user1"), create_reset_token("user2"), create_reset_token("user3")}
    assert None not in tokens
    assert len(tokens) == 3
    assert len(_token_store) == 3
    for token in tokens:
        assert _token_store[token]["user_id"] in {"user1", "user2", "user3"}


def test_security_create_reset_token_rejects_malicious_payloads():
    malicious_payloads = [
        "' OR '1'='1",
        "user; rm -rf /",
        "$(id)",
        "admin\nDROP TABLE users;",
        "1; import os; os.system('echo hacked')",
    ]
    for payload in malicious_payloads:
        token = create_reset_token(payload, ttl_seconds=3600)
        assert token is not None
        assert token in _token_store
        assert _token_store[token]["user_id"] == payload


def test_security_create_reset_token_rejects_non_positive_ttl_malicious():
    malicious_ttls = [0, -1, -999999]
    for ttl in malicious_ttls:
        assert create_reset_token("user", ttl_seconds=ttl) is None