import ast
import subprocess
import os
import difflib

def apply_patch_smart(file_path, fixed_code):
    """
    智能补丁应用：保留原文件的 imports。
    """
    with open(file_path, "r", encoding="utf-8") as f:
        original_lines = f.readlines()

    # 1. 提取原文件中的所有 import 语句
    imports = [line for line in original_lines if line.startswith("import ") or line.startswith("from ")]
    
    # 2. 检查修复后的代码是否自带了 import (防止重复)
    fixed_lines = fixed_code.splitlines(keepends=True)
    new_imports = [line for line in fixed_lines if line.startswith("import ") or line.startswith("from ")]
    
    # 合并 imports 并去重
    final_imports = list(set(imports + new_imports))
    
    # 3. 提取修复后的函数体
    clean_fixed_code = "".join([line for line in fixed_lines if not (line.startswith("import ") or line.startswith("from "))])

    # 4. 重新组装文件
    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(final_imports)
        f.write("\n")
        f.write(clean_fixed_code)

def verify_patch(file_path, original_cwe, fixed_code):
    """执行自动化验证流水线并记录详细日志"""
    # 获取原始代码用于 Diff 对比
    with open(file_path, "r", encoding="utf-8") as f:
        old_code = f.read()

    # 1. 语法检查
    try:
        ast.parse(fixed_code)
    except SyntaxError as e:
        return False, f"Syntax Error: {e}", None

    # 2. 应用补丁
    apply_patch_smart(file_path, fixed_code)

    # 3. 生成 Diff 日志内容
    diff = difflib.unified_diff(
        old_code.splitlines(),
        fixed_code.splitlines(),
        fromfile='Original',
        tofile='Fixed',
        lineterm=''
    )
    diff_log = "\n".join(list(diff))

    # 4. 功能回归测试 (增加超时处理，防止死锁)
    try:
        test_res = subprocess.run(
            ["python", "-m", "pytest", "tests/test_samples.py"],
            capture_output=True,
            text=True,
            timeout=30  # 30秒超时保护
        )
        test_output = test_res.stdout if test_res.returncode != 0 else "All Tests Passed"
        success = test_res.returncode == 0
    except subprocess.TimeoutExpired:
        return False, "Test Timeout (Potential Deadlock)", None

    log_entry = {
        "diff": diff_log,
        "test_report": test_output
    }

    if not success:
        return False, "Functional Regression", log_entry

    return True, "Success", log_entry