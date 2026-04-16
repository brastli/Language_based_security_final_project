import os
import re
from openai import OpenAI
from dotenv import load_dotenv

# 加载项目根目录下的 .env 文件
load_dotenv()

# 初始化 OpenAI 客户端
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("未找到 OPENAI_API_KEY。请在 .env 文件中配置或设置环境变量。")

client = OpenAI(api_key=api_key)

def generate_test_for_file(vuln_code, file_name="module.py"):
    """
    针对给定的源代码自动生成 pytest 脚本。
    增加 file_name 参数，用于防止大模型产生 import 幻觉。
    """
    # 提取模块名 (例如 'db.py' -> 'db')
    module_name = os.path.basename(file_name).replace('.py', '')
    
    prompt = f"""
    You are an Expert QA and Security Engineer. Your task is to write a comprehensive `pytest` script for the following Python code.
    
    CRITICAL IMPORT RULE:
    The code provided resides in a file named `{file_name}`. 
    You MUST import the functions you are testing directly from `{module_name}`.
    DO NOT use placeholders like 'your_module'.
    Example: `from {module_name} import [function_name]`
    
    CRITICAL REQUIREMENT - You MUST write TWO categories of tests:
    1. Functional Tests (methods starting with `test_functional_`): Verify the normal business logic with valid, expected inputs.
    2. Security Fuzzing Tests (methods starting with `test_security_`): Generate malicious payloads. Since the patched function might raise an Exception (like ValueError) when encountering malicious payloads, you MUST use a `with pytest.raises(Exception):` block around the function call to catch expected security rejections.
    STRICT OUTPUT RULES:
    - Output ONLY the valid Python code. 
    - NO markdown formatting (e.g., no ```python).
    - Ensure all necessary imports (including pytest) are included.
    
    Code to test:
    {vuln_code}
    """
    
    try:
        print("--- 正在调用 AI 生成测试用例 (Functional + Security Fuzzing) ---")
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a professional security testing assistant. You output clean, executable Python code."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2  # 保持低随机性
        )
        
        content = response.choices[0].message.content.strip()
        
        # 清洗 Markdown 标记
        content = re.sub(r"^```python\n", "", content)
        content = re.sub(r"^```\n", "", content)
        content = re.sub(r"```$", "", content).strip()
        
        return content

    except Exception as e:
        print(f"生成测试用例失败: {e}")
        return None

if __name__ == "__main__":
    # 简单测试入口
    pass