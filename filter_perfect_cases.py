import csv
from collections import defaultdict

def find_perfect_cases_by_project(input_csv, output_csv):
    # 使用字典存储每个项目的修复状态
    # key: 项目名, value: 是否曾经成功过 (True/False)
    project_status = defaultdict(bool)
    # 存储每个项目最后一次完美的记录详情，用于输出
    project_best_record = {}
    
    total_unique_cases = 0
    
    with open(input_csv, 'r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        
        for row in reader:
            project_name = row['Project/Case']
            
            # 如果是第一次见到这个项目，总数加 1
            if project_name not in project_status:
                project_status[project_name] = False
            
            # 核心判断：该 Attempt 是否 100% 成功
            is_perfect = (row['Failed'] == '0' and row['Errors'] == '0' and row['Pass Rate'] == '100.00%')
            
            if is_perfect:
                project_status[project_name] = True
                project_best_record[project_name] = row

    # 提取所有最终成功的项目记录
    perfect_projects = [record for record in project_best_record.values()]
    
    # 统计数据
    total_cases = len(project_status)
    success_count = sum(1 for status in project_status.values() if status)
    success_rate = (success_count / total_cases * 100) if total_cases > 0 else 0

    # 将成功修复的 Case 写入新的 CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(perfect_projects)
        
    # 终端打印全英文统计结果 (Case-based)
    print(f" Case-based Analysis Complete!")
    print(f" Total Unique Cases Evaluated: {total_cases}")
    print(f" Successfully Fixed Cases: {success_count}")
    print(f" Failed to Fix: {total_cases - success_count}")
    print(f" Final Success Rate: {success_rate:.2f}%")
    print("-" * 50)
    print(f"Detailed List of Successfully Fixed Projects:")
    for project_name, is_fixed in project_status.items():
        if is_fixed:
            record = project_best_record[project_name]
            print(f"✔ {project_name.ljust(30)} | Fixed at Attempt: {record['Attempt']} | {record['Raw Summary']}")

if __name__ == "__main__":
    # 执行脚本
    find_perfect_cases_by_project("pytest_statistics.csv", "perfect_cases_by_project.csv")