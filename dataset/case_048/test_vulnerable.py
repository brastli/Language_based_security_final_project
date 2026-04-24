import pytest
from unittest.mock import patch, MagicMock

from vulnerable import yaml_load


class DummyRequest:
    def __init__(self, data):
        self.args = {"data": data}


def test_functional_yaml_load_simple_mapping():
    with patch("vulnerable.request", DummyRequest("a: 1\nb: test")):
        with patch("vulnerable.yaml.load", return_value={"a": 1, "b": "test"}) as mock_load:
            result = yaml_load()
            assert result == {"a": 1, "b": "test"}
            mock_load.assert_called_once_with("a: 1\nb: test")


def test_functional_yaml_load_list():
    with patch("vulnerable.request", DummyRequest("- one\n- two\n- three")):
        with patch("vulnerable.yaml.load", return_value=["one", "two", "three"]) as mock_load:
            result = yaml_load()
            assert result == ["one", "two", "three"]
            mock_load.assert_called_once_with("- one\n- two\n- three")


@pytest.mark.parametrize(
    "payload",
    [
        "!!python/object/apply:os.system ['id']",
        "{{7*7}}; rm -rf /",
        "a: 1\nb: !!python/object/new:subprocess.Popen ['sh', '-c', 'id']",
    ],
)
def test_security_yaml_load_malicious_payloads(payload):
    with patch("vulnerable.request", DummyRequest(payload)):
        with patch("vulnerable.yaml.load", side_effect=Exception("Rejected malicious payload")):
            with pytest.raises(Exception):
                yaml_load()