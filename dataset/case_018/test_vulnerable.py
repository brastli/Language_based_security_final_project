import pytest
from vulnerable import load_cached_preferences


def test_functional_empty_bytes_returns_empty_dict():
    assert load_cached_preferences(b"") == {}


def test_functional_none_returns_empty_dict():
    assert load_cached_preferences(None) == {}


def test_functional_valid_marshaled_dict_returns_dict():
    data = {"theme": "dark", "language": "en", "notifications": True}
    serialized = __import__("marshal").dumps(data)
    assert load_cached_preferences(serialized) == data


def test_functional_marshaled_non_dict_returns_empty_dict():
    serialized = __import__("marshal").dumps(["a", "b", "c"])
    assert load_cached_preferences(serialized) == {}


def test_functional_marshaled_empty_dict_returns_empty_dict():
    serialized = __import__("marshal").dumps({})
    assert load_cached_preferences(serialized) == {}


@pytest.mark.parametrize(
    "payload",
    [
        b"'; DROP TABLE users; --",
        b"__import__('os').system('id')",
        b"; rm -rf /",
    ],
)
def test_security_malicious_payloads_rejected(payload):
    with pytest.raises(Exception):
        load_cached_preferences(payload)