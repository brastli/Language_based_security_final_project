import subprocess
import os

def verify_patch(file_path, cwe_id, fixed_code, test_file_path):
    """
    静默执行 Pytest，验证修补后的代码。
    """
    # 1. 语法树检查 (基础护栏)
    try:
        compile(fixed_code, '<string>', 'exec')
    except Exception as e:
        return False, "Syntax Error in LLM Patch", {"test_report": str(e)}

    # 2. 写入文件准备测试
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed_code)

    # 获取测试文件所在的目录和文件名
    test_dir = os.path.dirname(test_file_path)
    test_filename = os.path.basename(test_file_path)

    # 3. 运行 Pytest 功能与安全 Fuzzing 护栏
    try:
        # 添加 cwd=test_dir，让 pytest 在目标目录 (如 src/) 下运行
        # 这样确保测试代码里的 from db import xxx 可以成功找到同级目录的 db.py
        result = subprocess.run(
            ["python", "-m", "pytest", test_filename, "-v"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=test_dir if test_dir else None
        )
        
        if result.returncode == 0:
            return True, "Passed All Guardrails", {"test_report": ""}
        else:
            # 提取报错信息
            return False, "Guardrail Rejected: Test Failed", {"test_report": result.stdout + result.stderr}
            
    except subprocess.TimeoutExpired:
        return False, "Guardrail Rejected: Execution Timeout", {"test_report": "Infinite loop or timeout detected."}
    except Exception as e:
        return False, f"Guardrail System Error: {e}", {"test_report": str(e)}