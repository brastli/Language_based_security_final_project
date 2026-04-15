from vulnerable import run
import os
import pytest

def test_run_echo():
    # Test the run function with a simple echo command
    result = run("echo hello")
    assert result == 0  # os.system returns 0 on success

def test_run_ls():
    # Test the run function with a simple ls command
    result = run("ls")
    assert result == 0  # os.system returns 0 on success