import re
import csv
import os

def extract_stats(log_file_path, output_csv_path):
    """
    解析执行日志并提取项目名、修复尝试次数、测试通过情况以及对应的 CWE 编号。
    """
    # 结果存储列表
    stats = []
    
    # 定义正则表达式
    # 匹配项目开始行
    project_re = re.compile(r"PROJECT:\s+(case_\d+(_\w+)?)")
    # 匹配修复流水线开始行，提取 CWE (例如: Line 12, CWE-78)
    pipeline_start_re = re.compile(r"STARTING REPAIR PIPELINE FOR:.*\(Line\s+\d+,\s+(CWE-\d+)\)")
    # 匹配成功修复及其尝试次数
    success_re = re.compile(r"✔\s+(case_\d+(_\w+)?)\s+\|\s+Fixed at Attempt:\s+([\w/]+)")
    # 匹配测试结果 (例如: 14 passed in 0.11s)
    test_result_re = re.compile(r"(\d+)\s+passed\s+in\s+([\d.]+)s")

    current_project = None
    current_cwe = "N/A"
    
    if not os.path.exists(log_file_path):
        print(f"错误: 找不到日志文件 {log_file_path}")
        return

    with open(log_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        # 1. 寻找当前处理的项目名
        project_match = project_re.search(line)
        if project_match:
            current_project = project_match.group(1)
            # 重置当前项目的 CWE，防止数据污染
            current_cwe = "N/A"
            continue

        # 2. 从流水线启动日志中捕获 CWE
        pipeline_match = pipeline_start_re.search(line)
        if pipeline_match:
            current_cwe = pipeline_match.group(1)
            continue

        # 3. 寻找成功标记行
        success_match = success_re.search(line)
        if success_match:
            project_name = success_match.group(1)
            attempt = success_match.group(3)
            
            # 寻找紧随其后的测试统计数据
            passed_tests = "0"
            duration = "0"
            test_match = test_result_re.search(line)
            if test_match:
                passed_tests = test_match.group(1)
                duration = test_match.group(2)
            
            stats.append({
                "Project": project_name,
                "CWE": current_cwe,
                "Fixed_at_Attempt": attempt,
                "Passed_Tests": passed_tests,
                "Duration_sec": duration
            })

    # 写入 CSV 文件
    fieldnames = ["Project", "CWE", "Fixed_at_Attempt", "Passed_Tests", "Duration_sec"]
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in stats:
            writer.writerow(row)

    print(f"统计完成！已将结果写入: {output_csv_path}")
    print(f"总计提取成功修复案例: {len(stats)} 个")

if __name__ == "__main__":
    # 默认处理项目根目录下的 execution_results.txt
    input_log = "execution_results.txt"
    output_csv = "pytest_statistics.csv"
    
    extract_stats(input_log, output_csv)