import os
import pandas as pd
from main import run_pipeline # 假设你将 main 中的逻辑封装成了函数

def run_benchmark():
    samples_dir = "vulnerable_samples/"
    results = []

    for filename in os.listdir(samples_dir):
        if filename.endswith(".py"):
            file_path = os.path.join(samples_dir, filename)
            # 运行全流程并获取结果
            status = run_pipeline(file_path) 
            results.append({"File": filename, "Status": status})

    # 将结果保存为表格，方便汇报使用
    df = pd.DataFrame(results)
    df.to_csv("evaluation_results.csv", index=False)
    print("\n--- Benchmark 评估完成 ---")
    print(df)

if __name__ == "__main__":
    run_benchmark()