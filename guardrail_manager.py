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


def verify_patch(file_path, original_cwe, fixed_code, test_file_path): 
    """执行自动化验证流水线并记录详细日志"""
    with open(file_path, "r", encoding="utf-8") as f:
        old_code = f.read()

    # 1. 语法检查
    try:
        ast.parse(fixed_code)
    except SyntaxError as e:
        return False, f"Syntax Error: {e}", None

    # 2. 应用补丁
    apply_patch_smart(file_path, fixed_code)

    # 3. 生成 Diff
    diff = difflib.unified_diff(
        old_code.splitlines(),
        fixed_code.splitlines(),
        fromfile='Original',
        tofile='Fixed',
        lineterm=''
    )
    diff_log = "\n".join(list(diff))

    # 4. 功能回归测试 (适配 dataset 目录结构)
    # 获取测试脚本所在的目录 (例如: dataset/case_001_eval)
    case_dir = os.path.dirname(test_file_path)
    # 获取测试脚本的文件名 (例如: test_case.py)
    test_filename = os.path.basename(test_file_path)

    try:
        test_res = subprocess.run(
            ["python", "-m", "pytest", test_filename], 
            cwd=case_dir, # 【核心改动】：将执行目录切换到 case 文件夹内
            capture_output=True,
            text=True,
            timeout=30  
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