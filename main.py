import os
import sys
import analyzer
import scanner
import slicer
import repairer
import guardrail_manager
from auto_generate_tests import generate_test_for_file

class Logger:
    def __init__(self, filename="execution_results.txt"):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")
    def write(self, m):
        self.terminal.write(m); self.log.write(m); self.log.flush()
    def flush(self): pass

def run_project_pipeline(project_path):
    src_dir = os.path.join(project_path, "src")
    test_dir = os.path.join(project_path, "tests")
    
    # [STEP 0] 计算自底向上的修复序列
    repair_order = analyzer.get_repair_order(src_dir)
    print(f"\n{'='*60}\nPROJECT: {os.path.basename(project_path)}\nSEQUENCE: {[os.path.basename(x) for x in repair_order]}\n{'='*60}")

    # 确保测试目录存在
    os.makedirs(test_dir, exist_ok=True)

    for file_path in repair_order:
        print(f"\n>>> TARGETING LAYER: {os.path.basename(file_path)}")
        with open(file_path, "r", encoding="utf-8") as f: 
            buggy_backup = f.read()

        # 【修复】检查当前特定文件的测试用例是否存在，而不是查整个目录
        target_test_file = os.path.join(test_dir, f"test_{os.path.basename(file_path)}")
        if not os.path.exists(target_test_file):
            print(f"Generating test cases for {os.path.basename(file_path)}...")
            test_code = generate_test_for_file(buggy_backup)
            if test_code:
                with open(target_test_file, "w", encoding="utf-8") as f:
                    f.write(test_code)

        # 发现漏洞
        scan_data = scanner.run_bandit_scan(file_path)
        issues = scan_data.get('results', [])
        if not issues: 
            print("STATUS: Secure layer. Moving upward.")
            continue

        issue = issues[0]
        cwe_id = issue['issue_cwe']['id']
        func_code, flow_fact = slicer.get_function_and_flow(file_path, issue['line_number'])

        # 记忆闭环修复
        prev_err = None
        for attempt in range(1, 4):
            print(f"[ATTEMPT {attempt}/3] Patching CWE-{cwe_id}...")
            reason, patch = repairer.request_repair(cwe_id, func_code, flow_fact, prev_err)
            success, msg, log = guardrail_manager.verify_patch(file_path, cwe_id, patch, test_dir)
            
            if success:
                print(f"[PASSED] Layer secured."); break
            else:
                print(f"[REJECTED] {msg}"); prev_err = log.get("test_report", "")[-1000:]
                with open(file_path, "w", encoding="utf-8") as f: f.write(buggy_backup)
        else:
            print("!!! CRITICAL FAILURE AT BASE LAYER. HALTING."); return
        
def main():
    sys.stdout = Logger()
    dataset = "dataset"
    for proj in sorted(os.listdir(dataset)):
        path = os.path.join(dataset, proj)
        if os.path.isdir(path): run_project_pipeline(path)

if __name__ == "__main__":
    main()