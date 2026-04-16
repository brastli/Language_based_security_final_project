import subprocess
import os

def verify_patch(file_path, cwe_id, fixed_code, test_file_path, project_path):
    """
    静默执行 Pytest，验证修补后的代码。
    强制将工作目录(cwd)锁定为 project_path，保证所有包导入路径正确。
    """
    # 1. 语法树检查 (基础护栏)
    try:
        compile(fixed_code, '<string>', 'exec')
    except Exception as e:
        return False, "Syntax Error in LLM Patch", {"test_report": str(e)}

    # 2. 写入文件准备测试
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed_code)

    # 3. 运行 Pytest 功能与安全 Fuzzing 护栏
    try:
        abs_test_path = os.path.abspath(test_file_path)
        abs_project_path = os.path.abspath(project_path)

        result = subprocess.run(
            ["python", "-m", "pytest", abs_test_path, "-v"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=abs_project_path  # 绝对锁定根目录
        )
        
        # 【修改点】：无论成功还是失败，都捕获并返回完整的 stdout/stderr 日志
        full_log = result.stdout + result.stderr

        if result.returncode == 0:
            return True, "Passed All Guardrails", {"test_report": full_log}
        else:
            return False, "Guardrail Rejected: Test Failed", {"test_report": full_log}
            
    except subprocess.TimeoutExpired:
        return False, "Guardrail Rejected: Execution Timeout", {"test_report": "Infinite loop or timeout detected."}
    except Exception as e:
        return False, f"Guardrail System Error: {e}", {"test_report": str(e)}