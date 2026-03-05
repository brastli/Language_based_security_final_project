import os
from scanner import run_bandit_scan
from slicer import get_function_at_line
from repairer import request_repair
from guardrail_manager import verify_patch

def run_pipeline_for_file(file_path):
    """针对单个文件运行：扫描 -> 切片 -> 修复 -> 验证 -> 回档"""
    print(f"\n>>> 正在处理文件: {file_path}")
    
    # 备份原始有问题的代码 (用于自动回档)
    with open(file_path, "r", encoding="utf-8") as f:
        buggy_code_backup = f.read()

    # 1. 漏洞扫描
    scan_data = run_bandit_scan(file_path)
    issues = scan_data.get('results', [])
    if not issues:
        print(f"--- 未发现漏洞 ---")
        return "No Vulnerability"

    issue = issues[0]
    cwe_id = issue['issue_cwe']['id']
    line_no = issue['line_number']
    
    # 2. AST 语义切片
    func_code = get_function_at_line(file_path, line_no)
    if not func_code:
        return "Slicing Failed"

    # 3. LLM 修复请求
    fixed_code = request_repair(cwe_id, func_code)
    
    # 4. 验证并获取日志
    success, msg, repair_log = verify_patch(file_path, cwe_id, fixed_code)
    
    # --- 控制台详细日志输出 ---
    print(f"--- 修复详细报告 (CWE-{cwe_id}) ---")
    if repair_log and repair_log['diff']:
        print("【代码变更 (Diff)】:")
        print(repair_log['diff'])
    
    if not success:
        print(f"【验证失败详情】: {msg}")
        if repair_log:
            print("【Pytest 输出】:")
            print(repair_log['test_report'])
    else:
        print(f"【验证状态】: {msg}")

    # --- 自动回档逻辑 ---
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(buggy_code_backup)
    print(f"--- 已自动回档至原始版本: {file_path} ---")
    
    return msg

def main():
    samples_dir = "vulnerable_samples"
    files = [f for f in os.listdir(samples_dir) if f.endswith(".py") and f != "__init__.py"]
    
    for filename in files:
        run_pipeline_for_file(os.path.join(samples_dir, filename))

if __name__ == "__main__":
    main()