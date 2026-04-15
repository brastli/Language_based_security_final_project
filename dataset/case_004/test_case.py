from vulnerable import run

def test_run_echo_command():
    # Test the run function with a simple echo command
    result = run("echo hello")
    assert result == 0

def test_run_ls_command():
    # Test the run function with a simple ls command
    result = run("ls")
    assert result == 0