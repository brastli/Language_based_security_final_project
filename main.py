import os
import sys
# 导入测试生成逻辑
from auto_generate_tests import generate_test_for_file 
from scanner import run_bandit_scan
from slicer import get_function_at_line
from repairer import request_repair
from guardrail_manager import verify_patch

# Logger class to sync console output to a txt file
class Logger(object):
    def __init__(self, filename="execution_results.txt"):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        pass

def run_pipeline_for_file(file_path, test_file_path):
    """Run the pipeline for a single file: Auto-Test-Gen -> Scan -> Slice -> Repair -> Verify -> Rollback"""
    
    # Backup original buggy code for auto-rollback 
    with open(file_path, "r", encoding="utf-8") as f:
        buggy_code_backup = f.read()

    # --- [NEW STEP] Automated Test Case Generation ---
    # In Slide 10, we emphasize "no human intervention".
    # We generate the test case dynamically based on the current vulnerable code.
    print(f"\n[STEP 0] GENERATING TEST CASE FOR: {os.path.basename(os.path.dirname(file_path))}")
    test_code = generate_test_for_file(buggy_code_backup)
    if test_code:
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(test_code)
        print(f"STATUS: test_case.py generated successfully.")
    else:
        print(f"STATUS: Failed to generate test case. Proceeding with existing one.")

    # 1. Vulnerability Discovery [cite: 132-136]
    scan_data = run_bandit_scan(file_path)
    issues = scan_data.get('results', [])
    if not issues:
        return "No Vulnerability"

    issue = issues[0]
    cwe_id = issue['issue_cwe']['id']
    line_no = issue['line_number']
    
    # 2. Context Extraction (AST Slicing)
    func_code = get_function_at_line(file_path, line_no)
    if not func_code:
        return "Slicing Failed"

    # 3. AI Patching
    reasoning, fixed_code = request_repair(cwe_id, func_code)
    
    # 4. Triple-Guardrail Verification 
    success, msg, repair_log = verify_patch(file_path, cwe_id, fixed_code, test_file_path)
    
    # --- Professional English Console Output ---
    print(f"\n" + "="*60)
    print(f"PROCESSING FILE: {file_path}")
    print(f"VULNERABILITY DETECTED: CWE-{cwe_id}")
    print("="*60)

    print(f"\n[STEP 1] LLM REPAIR STRATEGY:")
    print(f"{reasoning}")

    print(f"\n[STEP 2] PATCH ANALYSIS (DIFF):")
    if repair_log and repair_log['diff']:
        print(repair_log['diff'])
    else:
        print("No changes detected in the patch.")

    print(f"\n[STEP 3] TRIPLE-GUARDRAIL VERIFICATION:")
    if success:
        print(f"RESULT: [PASSED]")
        print(f"STATUS: {msg}")
    else:
        print(f"RESULT: [REJECTED]")
        print(f"REASON: {msg}")
        if repair_log and repair_log['test_report']:
            print(f"\n--- PYTEST EXECUTION LOG ---")
            print(repair_log['test_report'])

    print(f"\n[STEP 4] POST-PROCESS:")
    # Automated Rollback to original buggy code 
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(buggy_code_backup)
    print(f"ACTION: Automated Rollback Triggered.")
    print(f"STATUS: Environment restored to initial baseline.")
    print("="*60 + "\n")
    
    return msg

def main():
    # Activate Logger to save everything to execution_results.txt [cite: 132-136]
    sys.stdout = Logger("execution_results.txt")
    
    dataset_dir = "dataset"
    if not os.path.exists(dataset_dir):
        print(f"Error: Directory '{dataset_dir}' not found.")
        return

    # Iterate through all case folders in the dataset [cite: 132-136]
    for case_folder in sorted(os.listdir(dataset_dir)):
        case_path = os.path.join(dataset_dir, case_folder)
        
        if os.path.isdir(case_path):
            vuln_file = os.path.join(case_path, "vulnerable.py")
            test_file = os.path.join(case_path, "test_case.py")
            
            if os.path.exists(vuln_file):
                # Even if test_case.py doesn't exist, we'll try to generate it now
                run_pipeline_for_file(vuln_file, test_file)

if __name__ == "__main__":
    main()