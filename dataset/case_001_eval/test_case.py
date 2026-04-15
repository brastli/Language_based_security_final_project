from vulnerable import run

def test_run_with_arithmetic_expression():
    assert run("2 + 2") == 4

def test_run_with_string_concatenation():
    assert run("'Hello, ' + 'World!'") == "Hello, World!"