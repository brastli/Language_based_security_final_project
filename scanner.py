import subprocess
import json
import sys
import os

def run_bandit_scan(target_path):
    """
    Run Bandit on a single file path; hardened for odd Windows path edge cases.
    """
    abs_target = os.path.abspath(target_path)

    cmd = [sys.executable, "-m", "bandit", "-r", abs_target, "-f", "json"]

    env = os.environ.copy()
    if "PYTHONPATH" in env:
        del env["PYTHONPATH"]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding='utf-8',
        env=env,
        shell=True,  # helps with paths containing spaces on Windows
    )

    if not result.stdout.strip():
        print(f"Bandit produced no stdout for {target_path}")
        print(f"stderr: {result.stderr}")
        return {}

    try:
        # Strip any leading noise; keep JSON from first '{'
        raw_output = result.stdout
        json_start = raw_output.find('{')
        if json_start != -1:
            return json.loads(raw_output[json_start:])
        return {}
    except json.JSONDecodeError as e:
        print(f"Bandit JSON parse failed: {e}")
        return {}