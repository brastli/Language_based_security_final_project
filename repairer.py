import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def request_repair(cwe_id, function_code):
    """
    将受污染的函数代码发送给 LLM 进行修复，并要求返回修复思路。
    """
    
    prompt = f"""
    You are a Senior Security Engineer. Your task is to fix a security vulnerability (CWE-{cwe_id}) in the provided Python function.
    
    STRICT RULES:
    1. Fix the vulnerability using security best practices.
    2. DO NOT change the function name or parameter list.
    3. DO NOT hallucinate variable names. 
    4. RETAIN all functional logic.
    5. You MUST output ONLY a valid JSON object with exactly two keys:
       - "reasoning": A brief explanation of your repair strategy in English.
       - "fixed_code": The fixed Python code.
    
    Original Function Code:
    {function_code}
    """

    try:
        print(f"--- requesting LLM to repair CWE-{cwe_id} ---")
        
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a precise code repair assistant. Always output valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={ "type": "json_object" }, # 强制 JSON 输出
            temperature=0.1  
        )
        
        raw_content = response.choices[0].message.content.strip()
        
        # 解析 JSON
        data = json.loads(raw_content)
        reasoning = data.get("reasoning", "LLM didn't provide reasoning")
        fixed_code = data.get("fixed_code", function_code)
            
        return reasoning, fixed_code

    except Exception as e:
        print(f"LLM 请求或解析失败: {e}")
        return "修复请求失败", function_code