from vulnerable import run
import subprocess

def test_run_echo():
    process = run("echo hello")
    assert isinstance(process, subprocess.Popen)

def test_run_ls():
    process = run("ls")
    assert isinstance(process, subprocess.Popen)