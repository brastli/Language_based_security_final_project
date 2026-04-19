import subprocess
import os

def verify_patch(file_path, cwe_id, fixed_code, test_file_path, project_path):
    """
    Run pytest quietly and validate patched code.
    Locks cwd to project_path so imports resolve consistently.
    """
    # Step 1: compile check (baseline guardrail)
    try:
        compile(fixed_code, '<string>', 'exec')
    except Exception as e:
        return False, "Syntax Error in LLM Patch", {"test_report": str(e)}

    # Step 2: write patched file before tests
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed_code)

    # Step 3: pytest functional + security fuzz guardrails
    try:
        abs_test_path = os.path.abspath(test_file_path)
        abs_project_path = os.path.abspath(project_path)

        result = subprocess.run(
            ["python", "-m", "pytest", abs_test_path, "-v"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=abs_project_path,
        )

        full_log = result.stdout + result.stderr

        if result.returncode == 0:
            return True, "Passed All Guardrails", {"test_report": full_log}
        else:
            return False, "Guardrail Rejected: Test Failed", {"test_report": full_log}

    except subprocess.TimeoutExpired:
        return False, "Guardrail Rejected: Execution Timeout", {"test_report": "Infinite loop or timeout detected."}
    except Exception as e:
        return False, f"Guardrail System Error: {e}", {"test_report": str(e)}
