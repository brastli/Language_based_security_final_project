import pytest
from vulnerable import run


def test_functional_parses_simple_yaml_mapping():
    data = "name: Alice\nage: 30\nactive: true\n"
    result = run(data)
    assert result == {"name": "Alice", "age": 30, "active": True}


def test_functional_parses_yaml_list():
    data = "- apple\n- banana\n- cherry\n"
    result = run(data)
    assert result == ["apple", "banana", "cherry"]


def test_functional_parses_nested_yaml():
    data = "user:\n  name: Bob\n  roles:\n    - admin\n    - editor\n"
    result = run(data)
    assert result == {"user": {"name": "Bob", "roles": ["admin", "editor"]}}


@pytest.mark.parametrize(
    "payload",
    [
        "!!python/object/apply:os.system ['echo pwned']",
        "!!python/object/apply:subprocess.check_output [['id']]",
        "!!python/object/new:tuple [!!python/object/apply:os.system ['whoami']]",
    ],
)
def test_security_rejects_malicious_yaml_payloads(payload):
    with pytest.raises(Exception):
        run(payload)