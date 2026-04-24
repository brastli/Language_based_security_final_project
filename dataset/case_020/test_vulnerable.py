import pytest
from vulnerable import parse_feature_flags


def test_functional_empty_input_returns_empty_dict():
    assert parse_feature_flags("") == {}
    assert parse_feature_flags(None) == {}


def test_functional_valid_yaml_dict_parsed_correctly():
    yaml_str = "new_ui: true\nbeta: false\nmax_items: 10\nname: test"
    result = parse_feature_flags(yaml_str)
    assert result == {
        "new_ui": True,
        "beta": False,
        "max_items": 10,
        "name": "test",
    }


def test_functional_non_dict_yaml_returns_empty_dict():
    assert parse_feature_flags("- a\n- b\n- c") == {}
    assert parse_feature_flags("just_a_string") == {}


def test_functional_nested_dict_parsed_correctly():
    yaml_str = "feature:\n  enabled: true\n  rollout: 25"
    result = parse_feature_flags(yaml_str)
    assert result == {"feature": {"enabled": True, "rollout": 25}}


@pytest.mark.parametrize(
    "payload",
    [
        "!!python/object/apply:os.system ['echo malicious']",
        "!!python/object/new:subprocess.Popen ['sh', '-c', 'id']",
        "!!python/object/apply:eval ['__import__(\"os\").system(\"echo pwned\")']",
    ],
)
def test_security_malicious_yaml_payloads_rejected_or_safely_handled(payload):
    with pytest.raises(Exception):
        parse_feature_flags(payload)