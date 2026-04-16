import os
import sys
import ast
from collections import deque
from auto_generate_tests import generate_test_for_file
from scanner import run_bandit_scan
from slicer import get_function_and_flow
from repairer import request_repair
from guardrail_manager import verify_patch

class RepositoryAnalyzer:
    """利用 AST 递归解析项目文件依赖，并动态生成拓扑修复序列"""
    
    @staticmethod
    def get_dependencies(file_path, all_py_files):
        deps = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    deps.append(node.module.split('.')[-1])
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        deps.append(alias.name.split('.')[-1])
        except: pass
        
        resolved_deps = []
        for d in deps:
            for f in all_py_files:
                if os.path.basename(f) == f"{d}.py":
                    resolved_deps.append(f)
        return resolved_deps

    @classmethod
    def get_repair_sequence(cls, project_path):
        files = []
        for root, dirs, filenames in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in ['tests', '.pytest_cache', '__pycache__', 'venv', 'logs']]
            for f in filenames:
                if f.endswith('.py') and not f.startswith('test_'):
                    rel_path = os.path.relpath(os.path.join(root, f), project_path)
                    files.append(rel_path)
        
        adj = {f: [] for f in files}
        in_degree = {f: 0 for f in files}
        
        for f in files:
            abs_f = os.path.join(project_path, f)
            deps = cls.get_dependencies(abs_f, files)
            for d in deps:
                if d in adj and d != f:
                    adj[d].append(f)
                    in_degree[f] += 1
        
        queue = deque([f for f in files if in_degree[f] == 0])
        sequence = []
        while queue:
            u = queue.popleft()
            sequence.append(u)
            for v in adj[u]:
                in_degree[v] -= 1
                if in_degree[v] == 0:
                    queue.append(v)
        
        for f in files:
            if f not in sequence:
                sequence.append(f)
                
        return sequence

class Logger(object):
    def __init__(self, filename="execution_results.txt"):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()
    def flush(self): pass

def run_project_pipeline(project_path):
    project_name = os.path.basename(project_path)
    repair_sequence = RepositoryAnalyzer.get_repair_sequence(project_path)
    
    print("\n" + "="*75)
    print(f"PROJECT: {project_name}\nTOPOLOGY: {repair_sequence}")
    print("="*75)

    if not repair_sequence:
        print(f"[SKIP] No valid source files found in {project_name}.")
        return

    for rel_file_path in repair_sequence:
        file_path = os.path.join(project_path, rel_file_path)
        
        dir_name = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)
        test_file_path = os.path.join(dir_name, f"test_{base_name}")
        
        print(f"\n>>> TARGETING LAYER: {rel_file_path}")
        
        with open(file_path, "r", encoding="utf-8") as f:
            original_code = f.read()

        # [STEP 0] 生成测试（将 base_name 传递给生成器，防止幻觉）
        print(f"Generating dynamic tests for {base_name}...")
        test_code = generate_test_for_file(original_code, base_name)
        
        if test_code:
            with open(test_file_path, "w", encoding="utf-8") as f: 
                f.write(test_code)

        # [STEP 1] 扫描与切片
        scan_data = run_bandit_scan(file_path)
        issues = scan_data.get('results', [])
        if not issues:
            print(f"STATUS: [SECURE]")
            continue

        issue = issues[0]
        cwe_id = issue['issue_cwe']['id']
        line_no = issue['line_number']
        
        func_code, data_flow_fact = get_function_and_flow(file_path, line_no)

        # [STEP 2] 自治修复循环
        MAX_RETRIES = 3
        previous_error = None
        repair_success = False
        
        for attempt in range(1, MAX_RETRIES + 1):
            print(f"[ATTEMPT {attempt}/{MAX_RETRIES}] Repairing CWE-{cwe_id}...")
            reasoning, fixed_code = request_repair(cwe_id, func_code, data_flow_fact, previous_error)
            print(f"STRATEGY: {reasoning}")

            success, msg, repair_log = verify_patch(file_path, cwe_id, fixed_code, test_file_path)
            if success:
                print(f"RESULT: [PASSED] {msg}")
                repair_success = True
                break
            else:
                print(f"RESULT: [REJECTED] {msg}")
                if repair_log and repair_log['test_report']:
                    error_tail = "\n".join(repair_log['test_report'].strip().splitlines()[-5:])
                    print(f"--- ERROR ---\n{error_tail}")
                    previous_error = repair_log['test_report'][-1500:]
                
                # 回档
                with open(file_path, "w", encoding="utf-8") as f: 
                    f.write(original_code)

        # 如果底层熔断，停止修复该项目的上层代码
        if not repair_success:
            print(f"!!! CRITICAL FAILURE AT {rel_file_path}. HALTING PIPELINE FOR THIS PROJECT.")
            break

def main():
    sys.stdout = Logger("execution_results.txt")
    dataset_dir = "dataset"
    
    if os.path.exists(dataset_dir):
        for item in sorted(os.listdir(dataset_dir)):
            path = os.path.join(dataset_dir, item)
            # 仅处理文件夹
            if os.path.isdir(path): 
                run_project_pipeline(path)
    else:
        print(f"Error: Directory '{dataset_dir}' not found.")

if __name__ == "__main__":
    main()