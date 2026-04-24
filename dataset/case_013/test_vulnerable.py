import pytest
from vulnerable import load_user_config


def test_functional_load_user_config_valid_dict():
    config_str = "theme: dark\nlang: en\nfeatures:\n  beta: true\n  retries: 3\n"
    result = load_user_config(config_str)
    assert isinstance(result, dict)
    assert result["theme"] == "dark"
    assert result["lang"] == "en"
    assert result["features"]["beta"] is True
    assert result["features"]["retries"] == 3


def test_functional_load_user_config_empty_string():
    assert load_user_config("") == {}


def test_functional_load_user_config_none():
    assert load_user_config(None) == {}


def test_functional_load_user_config_non_dict_yaml_returns_empty_dict():
    assert load_user_config("- a\n- b\n- c\n") == {}


def test_functional_load_user_config_invalid_yaml_returns_empty_dict():
    assert load_user_config("theme: dark\nlang: [en\n") == {}


@pytest.mark.parametrize(
    "payload",
    [
        "!!python/object/apply:os.system ['echo pwned']",
        "!!python/object/new:tuple [1, 2, 3]",
        "!!python/object/apply:subprocess.Popen [['/bin/sh', '-c', 'id']]",
    ],
)
def test_security_load_user_config_malicious_payloads_raise_exception(payload):
    with pytest.raises(Exception):
        load_user_config(payload)