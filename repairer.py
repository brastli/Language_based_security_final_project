import os
import json
from openai import OpenAI
from dotenv import load_dotenv

# 加载环境变量 (确保根目录下有 .env 文件包含 OPENAI_API_KEY)
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ==========================================
# 核心创新 1: 漏洞特定专家规则库 (Vulnerability-Specific Knowledge Base)
# 作用: 防止大模型产生过度妥协(Sycophancy)，强制执行工业级防御架构
# ==========================================
CWE_SPECIFIC_RULES = {
    "78": "CRITICAL: Replace `os.system`, `eval`, or `shell=True` with `subprocess.run()`. Command arguments MUST be passed as a Python list, NEVER as a concatenated string.",
    "89": "CRITICAL: Use parameterized SQL queries (e.g., `cursor.execute(query, (params,))`). DO NOT use string formatting or concatenation for SQL.",
    "22": "CRITICAL: Resolve absolute paths using `os.path.abspath` and explicitly verify that the final path starts with the intended safe base directory using `.startswith()`.",
    "94": "CRITICAL: DO NOT use `eval()` or `exec()`. If evaluating data structures, use `ast.literal_eval()`. If complex logic is needed, use a safe mapping dictionary.",
    "330": "CRITICAL: DO NOT use the `random` module for security/cryptographic purposes. You MUST use the `secrets` module (e.g., `secrets.token_hex`, `secrets.choice`).",
    "327": "CRITICAL: DO NOT use broken or risky cryptographic algorithms like MD5 or SHA1. You MUST upgrade to secure algorithms like SHA256 (e.g., `hashlib.sha256`) or PBKDF2."
}

def request_repair(cwe_id, function_code, data_flow_fact="", previous_error=None):
    """
    向 LLM 发送带有极强上下文和护栏约束的修复请求。
    
    参数:
    - cwe_id: 漏洞编号 (如 89)
    - function_code: 存在漏洞的代码切片
    - data_flow_fact: (可选) 变量污染的数据流事实描述
    - previous_error: (可选) 上一次尝试失败的 Pytest 报错信息
    """
    
    # 动态获取针对该漏洞的特定规则
    specific_rule = CWE_SPECIFIC_RULES.get(
        str(cwe_id), 
        "Fix the vulnerability using general security best practices."
    )
    
    # ==========================================
    # 基础 Prompt 构造 (包含数据流注入)
    # ==========================================
    prompt = f"""
    You are an Autonomous Security Engineer. Your task is to fix a security vulnerability (CWE-{cwe_id}) in the provided Python function.
    
    STRICT RULES:
    1. {specific_rule}
    2. DO NOT change the function name or parameter list signatures.
    3. DO NOT hallucinate variable names.
    4. Retain existing business logic while neutralizing the threat.
    
    [DATA-FLOW FACTS]:
    {data_flow_fact if data_flow_fact else "No specific data flow facts provided."}
    Ensure you sanitize or validate the specific variables mentioned above.

    Original Code:
    {function_code}
    """
    
    # ==========================================
    # 核心创新 2: 记忆与反馈闭环 (Test-Driven Feedback Loop)
    # 作用: 拦截失败后赋予 Agent 自我反思和定向纠错的能力
    # ==========================================
    if previous_error:
        prompt += f"""
        \n[CRITICAL FEEDBACK FROM PREVIOUS ATTEMPT]:
        Your previous patch FAILED the guardrail verification. 
        
        Pytest Error Log:
        {previous_error}
        
        CRITICAL INSTRUCTIONS FOR THIS RETRY:
        1. DO NOT repeat the exact same code you just generated.
        2. If the error is an 'AssertionError' from a Functional Test, your patch broke the business logic. You MUST relax your filtering while maintaining security.
        3. If the error is from a Security Fuzzing Test, your patch is bypassable. You MUST use strict library-level defenses, NOT simple string manipulation.
        
        Analyze why it failed and generate a NEW, robust patch that satisfies both functionality and security.
        """
        
    # 强制输出格式为 JSON，方便后端精确解析
    prompt += '\nOutput ONLY a valid JSON object with exactly two keys: "reasoning" (A brief English explanation of your repair strategy) and "fixed_code" (The fixed Python code).'

    # ==========================================
    # 请求大模型
    # ==========================================
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a precise code repair assistant. Always output valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={ "type": "json_object" },
            temperature=0.1  # 保持低温度以确保代码稳定性 (严谨性优先)
        )
        
        # 解析返回的 JSON
        data = json.loads(response.choices[0].message.content.strip())
        reasoning = data.get("reasoning", "No reasoning provided.")
        fixed_code = data.get("fixed_code", function_code)
        
        return reasoning, fixed_code

    except Exception as e:
        print(f"LLM Repair Request Failed: {e}")
        return f"Error: {e}", function_code