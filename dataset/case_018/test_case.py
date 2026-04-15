from vulnerable import load_cached_preferences

def test_load_cached_preferences_empty_input():
    assert load_cached_preferences(b"") == {}

def test_load_cached_preferences_valid_dict():
    # This is a marshaled version of a simple dictionary: {'key': 'value'}
    marshaled_data = b'\xe3\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x7d\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x73\x03\x00\x00\x00key\x00\x01\x00\x00\x00\x73\x05\x00\x00\x00value\x00\x00'
    expected_output = {'key': 'value'}
    assert load_cached_preferences(marshaled_data) == expected_output