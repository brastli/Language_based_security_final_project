from vulnerable import run

def test_run_with_valid_yaml():
    user_input = "a: 1\nb: 2\nc: 3"
    expected_output = {'a': 1, 'b': 2, 'c': 3}
    assert run(user_input) == expected_output

def test_run_with_empty_yaml():
    user_input = ""
    expected_output = None
    assert run(user_input) == expected_output