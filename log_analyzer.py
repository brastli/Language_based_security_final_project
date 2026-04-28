import re
import os
from collections import Counter

def analyze_execution_log(log_path="execution_results.txt"):
    """
    解析 SurgicalPatch 流水线执行日志，生成多维度的统计报告。
    """
    if not os.path.exists(log_path):
        print(f"错误: 找不到日志文件 {log_path}")
        return

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # 以“▶ 正在处理目标文件”作为分隔符，将日志切分为各个文件的处理块
    blocks = re.split(r"▶ 正在处理目标文件:\s*", content)
    
    if len(blocks) > 0 and not blocks[0].strip().endswith(".py"):
        blocks = blocks[1:]

    # ================= 统计指标初始化 =================
    total_processed = 0
    safe_files = 0
    evaluated_files = 0
    success_count = 0
    failed_count = 0
    
    cwe_counter = Counter()
    attempt_counter = Counter()
    
    static_bypass_count = 0
    dynamic_bypass_count = 0
    
    failure_reasons = Counter()
    successful_files = []

    cwe_pattern = re.compile(r"\[SCANNER\] 发现漏洞:\s*(CWE-[\w-]+|General)")
    sandbox_fail_pattern = re.compile(r"\[SANDBOX 失败\]")
    sast_warn_pattern = re.compile(r"\[SAST 警告\]")
    api_error_pattern = re.compile(r"(insufficient_quota|LLM Repair Request Failed|Rate limit reached)")
    syntax_error_pattern = re.compile(r"Syntax Error in LLM Patch")

    # ================= 开始分析每个代码块 =================
    for block in blocks:
        if not block.strip():
            continue
            
        total_processed += 1
        current_file = block.splitlines()[0].strip()
        
        if "[STATUS] 未检测到漏洞" in block:
            safe_files += 1
            continue
            
        evaluated_files += 1

        cwe_match = cwe_pattern.search(block)
        if cwe_match:
            cwe_counter[cwe_match.group(1)] += 1
        else:
            cwe_counter["Unknown"] += 1

        # ================= 修复核心：精准捕获 3 种胜利模式 =================
        success_perfect = re.search(r"\[SUCCESS\] 漏洞在第 (\d+) 次尝试中被完美修复", block)
        success_static = re.search(r"【静态信任豁免】", block)
        success_dynamic = re.search(r"【动态信任豁免】", block)
        
        is_success = False
        attempt_str = "1"
        
        # 提取当前胜利所属的 Attempt 次数
        att_match = re.findall(r"--- 迭代尝试 (\d+)/", block)
        if att_match:
            attempt_str = att_match[-1]

        if success_perfect:
            is_success = True
            attempt_str = success_perfect.group(1)
        elif success_static:
            is_success = True
            static_bypass_count += 1
        elif success_dynamic:
            is_success = True
            dynamic_bypass_count += 1
            
        if is_success:
            success_count += 1
            attempt_counter[f"Attempt {attempt_str}"] += 1
            successful_files.append(current_file)
        else:
            failed_count += 1
            if api_error_pattern.search(block):
                failure_reasons["API 额度耗尽/请求失败 (API Error)"] += 1
            elif syntax_error_pattern.search(block):
                failure_reasons["LLM 生成了语法错误代码 (Syntax Error)"] += 1
            elif sast_warn_pattern.search(block) and not sandbox_fail_pattern.search(block[block.rfind("--- 迭代尝试"):]):
                failure_reasons["静态扫描器持续死锁 (SAST Persistent Rejection)"] += 1
            elif sandbox_fail_pattern.search(block):
                failure_reasons["沙箱动态测试未通过 (Sandbox/Logic Failed)"] += 1
            else:
                failure_reasons["达到最大迭代次数未能收敛 (Max Attempts Reached)"] += 1

    # ================= 打印分析报告 =================
    print("\n" + "="*60)
    print(" SurgicalPatch 日志深度分析报告")
    print("="*60)
    
    print("\n[1] 处理规模 (Processing Scale)")
    print(f" - 总计处理文件数: {total_processed}")
    print(f" - 原生安全文件数: {safe_files}")
    print(f" - 包含漏洞需修复: {evaluated_files}")

    if evaluated_files > 0:
        success_rate = (success_count / evaluated_files) * 100
        print(f"\n[2] 成功/失败统计 (Success/Failure Rates)")
        print(f" - 成功修复数量: {success_count}")
        print(f" - 修复失败数量: {failed_count}")
        print(f" - 全局修复成功率: {success_rate:.2f}%")

        print(f"\n[3] 漏洞类型分布 (CWE Distribution)")
        for cwe, count in cwe_counter.most_common():
            print(f" - {cwe}: {count} 个")

        print(f"\n[4] 成功修复模式 (Success Patterns)")
        for attempt, count in sorted(attempt_counter.items()):
            percentage = (count / success_count) * 100 if success_count > 0 else 0
            print(f" - 在 {attempt} 成功: {count} 个 ({percentage:.1f}%)")
        print(f" - 触发【静态信任豁免】(残缺伪代码): {static_bypass_count} 次")
        print(f" - 触发【动态信任豁免】(SAST死板误报): {dynamic_bypass_count} 次")

        if failed_count > 0:
            print(f"\n[5] 核心失败原因分析 (Primary Failure Causes)")
            for reason, count in failure_reasons.most_common():
                percentage = (count / failed_count) * 100
                print(f" - {reason}: {count} 个 ({percentage:.1f}%)")
                
        if successful_files:
            print(f"\n[6] 成功修复的文件列表 (Successfully Fixed Files)")
            for i, file_name in enumerate(successful_files, 1):
                print(f"  {i}. {file_name}")

    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    analyze_execution_log("execution_results.txt")