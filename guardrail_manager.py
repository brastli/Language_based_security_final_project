import subprocess

def verify_patch(file_path, cwe_id, fixed_code, test_dir):
    try:
        compile(fixed_code, '<string>', 'exec')
    except SyntaxError as e:
        return False, "Syntax Error", {"test_report": str(e)}

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed_code)

    try:
        # 在整个项目测试目录下运行 pytest
        result = subprocess.run(
            ["python", "-m", "pytest", test_dir, "-v"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True, "Passed all guards", {"test_report": "", "diff": fixed_code}
        else:
            return False, "Functional/Security Regression", {"test_report": result.stdout}
    except subprocess.TimeoutExpired:
        return False, "Timeout", {"test_report": "Execution timed out."}