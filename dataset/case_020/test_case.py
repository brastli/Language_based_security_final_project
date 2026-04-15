from vulnerable import parse_feature_flags

def test_parse_feature_flags_with_valid_yaml():
    yaml_str = "new_ui: true\nbeta: false"
    expected_output = {"new_ui": True, "beta": False}
    assert parse_feature_flags(yaml_str) == expected_output

def test_parse_feature_flags_with_empty_string():
    yaml_str = ""
    expected_output = {}
    assert parse_feature_flags(yaml_str) == expected_output