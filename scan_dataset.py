import subprocess
import json
import os

def scan_vulnerable_files(target_dir="dataset"):
    """
    使用 Bandit 扫描指定目录，汇总所有包含漏洞的文件名（智能排除测试文件）。
    """
    if not os.path.exists(target_dir):
        print(f"❌ 错误: 找不到目录 '{target_dir}'。")
        return

    print(f"[*] 正在使用 Bandit 扫描目录 '{target_dir}' (已自动过滤测试文件)...\n")

    try:
        # 使用 -x 排除带有 test 字样的文件和目录
        process = subprocess.run(
            ["bandit", "-r", target_dir, "-x", "*test*,*tests*", "-f", "json"],
            capture_output=True,
            text=True,
            check=False 
        )
    except FileNotFoundError:
        print("❌ 错误: 系统中未找到 'bandit' 命令。请先运行 'pip install bandit'。")
        return

    try:
        scan_results = json.loads(process.stdout)
    except json.JSONDecodeError:
        print("❌ 错误: 无法解析 Bandit 的输出结果。")
        return

    vulnerable_files = set()
    issues = scan_results.get("results", [])
    
    for issue in issues:
        file_path = issue.get("filename")
        if file_path:
            # 双重保险：在 Python 层面再次过滤包含 test 的文件
            if "test" in file_path.lower():
                continue
                
            try:
                rel_path = os.path.relpath(file_path, start=os.getcwd())
                vulnerable_files.add(rel_path)
            except ValueError:
                vulnerable_files.add(file_path)

    print("=" * 60)
    print("🛡️ 核心业务代码漏洞残余报告 (已过滤 Test)")
    print("=" * 60)
    
    if vulnerable_files:
        print(f"🚨 发现 {len(vulnerable_files)} 个业务文件仍存在已知漏洞:")
        for index, file_name in enumerate(sorted(vulnerable_files), start=1):
            print(f"  {index}. {file_name}")
    else:
        print("\n✅ 完美收官！目标目录中所有的业务代码均已不存在已知漏洞。")
        
    print("\n" + "=" * 60)

if __name__ == "__main__":
    scan_dataset_dir = "dataset"
    scan_vulnerable_files(scan_dataset_dir)