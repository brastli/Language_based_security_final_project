from vulnerable import load_user_config

def test_load_user_config_with_valid_yaml():
    config_str = "theme: dark\nlang: en"
    expected_output = {"theme": "dark", "lang": "en"}
    assert load_user_config(config_str) == expected_output

def test_load_user_config_with_empty_string():
    config_str = ""
    expected_output = {}
    assert load_user_config(config_str) == expected_output