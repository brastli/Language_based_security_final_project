import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def request_repair(cwe_id, function_code):
    """
    将受污染的函数代码发送给 LLM 进行修复。
    通过系统提示词（System Prompt）约束 AI 必须保持逻辑完整性。
    """
    
    prompt = f"""
    You are a Senior Security Engineer. Your task is to fix a security vulnerability (CWE-{cwe_id}) in the provided Python function.
    
    STRICT RULES:
    1. Fix the vulnerability using security best practices (e.g., parameterized queries for SQLi).
    2. DO NOT change the function name or parameter list.
    3. DO NOT hallucinate variable names. If you define a variable, use that exact name consistently (e.g., 'result' not 'resul').
    4. RETAIN all functional logic, including table creation or database initialization present in the original code.
    5. Return ONLY the fixed Python code. No explanations, no markdown code blocks.
    
    Original Function Code:
    {function_code}
    """

    try:
        print(f"--- 正在请求 LLM 修复 CWE-{cwe_id} ---")
        
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a precise code repair assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1  
        )
        
        fixed_code = response.choices[0].message.content.strip()
        if fixed_code.startswith("```python"):
            fixed_code = fixed_code.replace("```python", "").replace("```", "").strip()
        elif fixed_code.startswith("```"):
            fixed_code = fixed_code.replace("```", "").strip()
            
        return fixed_code

    except Exception as e:
        print(f"LLM 请求失败: {e}")
        return function_code 