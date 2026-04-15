from vulnerable import run
import subprocess

def test_run_echo():
    result = run("echo hello")
    assert result.returncode == 0
    assert result.stdout is None  # subprocess.run with shell=True and no capture_output doesn't capture stdout

def test_run_ls():
    result = run("ls")
    assert result.returncode == 0
    assert result.stdout is None  # subprocess.run with shell=True and no capture_output doesn't capture stdout