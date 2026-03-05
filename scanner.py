import subprocess
import json
import sys
import os

def run_bandit_scan(target_path):
    """
    针对 Windows WinError 123 优化的扫描函数
    """
    # 强制获取绝对路径，避免相对路径产生的解析歧义
    abs_target = os.path.abspath(target_path)
    
    # 构建命令：直接调用 python 运行 bandit 模块
    # 增加 --ignore-nocodes 减少干扰
    cmd = [sys.executable, "-m", "bandit", "-r", abs_target, "-f", "json"]
    
    # 关键点：创建一个干净的环境变量副本，移除可能冲突的变量
    env = os.environ.copy()
    if "PYTHONPATH" in env:
        del env["PYTHONPATH"]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding='utf-8',
        env=env, # 使用清理后的环境变量
        shell=True # 在 Windows 上处理路径空格
    )

    if not result.stdout.strip():
        print(f"错误：Bandit 在处理 {target_path} 时未产生输出！")
        print(f"标准错误信息: {result.stderr}")
        return {}

    try:
        # 过滤掉可能混入 stdout 的调试信息，只保留 JSON 部分
        raw_output = result.stdout
        json_start = raw_output.find('{')
        if json_start != -1:
            return json.loads(raw_output[json_start:])
        return {}
    except json.JSONDecodeError as e:
        print(f"JSON 解析失败: {e}")
        return {}