import re
import csv

def extract_pytest_stats(log_filepath, output_csv):
    results = []
    
    current_project = "Unknown"
    current_attempt = "Baseline/Unknown"
    
    # 匹配 Attempt 的正则，例如 "[ATTEMPT 1/3] Repairing CWE-78..."
    attempt_pattern = re.compile(r'\[ATTEMPT (\d+/\d+)\]')
    # 匹配 Project 的正则
    project_pattern = re.compile(r'PROJECT:\s*(.+)')
    
    with open(log_filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    for line in lines:
        # 提取当前正在处理的项目名
        proj_match = project_pattern.search(line)
        if proj_match:
            current_project = proj_match.group(1).strip()
            current_attempt = "Baseline" # 重置 attempt
            
        # 提取当前的尝试次数
        att_match = attempt_pattern.search(line)
        if att_match:
            current_attempt = att_match.group(1)
            
        # 提取 pytest 的 summary 行
        # 特征：以 "=" 开头，且包含 "failed" 或 "passed" 或 "error"
        if line.startswith("==") and ("passed" in line or "failed" in line or "error" in line):
            summary = line.strip("= \n")
            
            # 解析具体数字 (例如: 3 failed, 3 passed in 0.50s)
            failed_match = re.search(r'(\d+)\s+failed', summary)
            passed_match = re.search(r'(\d+)\s+passed', summary)
            error_match = re.search(r'(\d+)\s+error', summary)
            
            failed_count = int(failed_match.group(1)) if failed_match else 0
            passed_count = int(passed_match.group(1)) if passed_match else 0
            error_count = int(error_match.group(1)) if error_match else 0
            
            total_tests = failed_count + passed_count + error_count
            pass_rate = f"{(passed_count / total_tests * 100):.2f}%" if total_tests > 0 else "0.00%"
            
            results.append({
                "Project/Case": current_project,
                "Attempt": current_attempt,
                "Passed": passed_count,
                "Failed": failed_count,
                "Errors": error_count,
                "Pass Rate": pass_rate,
                "Raw Summary": summary
            })

    # 写入 CSV 文件
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Project/Case', 'Attempt', 'Passed', 'Failed', 'Errors', 'Pass Rate', 'Raw Summary']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in results:
            writer.writerow(row)
            
    print(f"✅ 提取完成！共找到 {len(results)} 条 Pytest 统计数据，已保存至 {output_csv}")

if __name__ == "__main__":
    # 请确保 execution_results.txt 在同一目录下
    extract_pytest_stats("execution_results.txt", "pytest_statistics.csv")