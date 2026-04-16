import os
import re
import json
from openai import OpenAI
from dotenv import load_dotenv

# ==========================================
# 1. 环境配置与客户端初始化
# ==========================================
# 加载项目根目录下的 .env 文件
load_dotenv()

# 初始化 OpenAI 客户端
# 确保你的 .env 文件中有 OPENAI_API_KEY=sk-xxxx
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("未找到 OPENAI_API_KEY。请在 .env 文件中配置或设置环境变量。")

client = OpenAI(api_key=api_key)

def generate_test_for_file(vuln_code):
    """
    针对给定的源代码，利用 LLM 自动生成包含业务逻辑验证和安全攻击验证的 pytest 脚本。
    
    参数:
    - vuln_code: 需要进行测试的原始（或修复后）代码字符串。
    
    返回:
    - 生成的 pytest 完整代码字符串。
    """
    
    # ==========================================
    # 2. 核心提示词 (专家级安全测试指令)
    # ==========================================
    # 在这里我们要求 LLM 必须生成两类测试：
    # 1. Functional Tests: 确保代码没修坏，正常功能还能跑。
    # 2. Security Fuzzing Tests: 模拟黑客攻击（如注入、穿越），确保漏洞已闭合。
    prompt = f"""
    You are an Expert QA and Security Engineer. Your task is to write a comprehensive `pytest` script for the following Python code.
    
    CRITICAL REQUIREMENT - You MUST write TWO categories of tests:
    1. Functional Tests (methods starting with `test_functional_`): 
       Verify the normal business logic with valid, expected inputs. 
       Example: If it's a calculator, test that 1+1=2.
       
    2. Security Fuzzing Tests (methods starting with `test_security_`): 
       Generate at least 3 common malicious payloads relevant to the code (e.g., SQLi strings like "' OR 1=1 --", 
       Command Injection characters like "; ls -la", or Path Traversal like "../../../etc/passwd"). 
       Assert that the function safely handles these (e.g., raises an expected Exception, returns a default value, or 
       sanitizes the input) WITHOUT executing the malicious payload or crashing.

    STRICT OUTPUT RULES:
    - Output ONLY the valid Python code. 
    - NO markdown formatting (e.g., no ```python).
    - Ensure all necessary imports (like `pytest` and the functions from the code) are included.
    
    Code to test:
    {vuln_code}
    """
    
    try:
        print("--- 正在调用 AI 生成测试用例 (Functional + Security Fuzzing) ---")
        response = client.chat.completions.create(
            model="gpt-4o",  # 或使用 gpt-3.5-turbo
            messages=[
                {"role": "system", "content": "You are a professional security testing assistant. You output clean, executable Python code."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2  # 保持低随机性，确保生成的测试逻辑严谨
        )
        
        content = response.choices[0].message.content.strip()
        
        # ==========================================
        # 3. 后处理：清洗 Markdown 标记
        # ==========================================
        # LLM 有时会习惯性加上 ```python ... ```，这会导致代码无法直接执行
        content = re.sub(r"^```python\n", "", content)
        content = re.sub(r"^```\n", "", content)
        content = re.sub(r"```$", "", content).strip()
        
        return content

    except Exception as e:
        print(f"生成测试用例失败: {e}")
        return None

# ==========================================
# 4. 独立运行测试 (用于单独调试此脚本)
# ==========================================
if __name__ == "__main__":
    # 这是一个简单的 SQL 注入示例代码，用于测试脚本是否能生成正确的测试
    sample_code = """
import sqlite3
def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # 这是一个有漏洞的查询
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    return cursor.fetchone()
    """
    
    test_script = generate_test_for_file(sample_code)
    if test_script:
        print("\n--- 生成的 pytest 脚本预览 ---")
        print(test_script)
        
        # 你可以取消下面两行的注释来将结果保存到本地查看
        # with open("debug_test_case.py", "w", encoding="utf-8") as f:
        #     f.write(test_script)