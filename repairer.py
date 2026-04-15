import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

CWE_SPECIFIC_RULES = {
    "78": "CRITICAL: Replace `os.system` or `shell=True` with `subprocess.run()`. Arguments MUST be a list.",
    "89": "CRITICAL: Use parameterized queries. NEVER use string formatting/concatenation for SQL.",
    "22": "CRITICAL: Use `os.path.abspath` and verify the path starts with the safe base directory.",
    "94": "CRITICAL: Replace `eval()` with `ast.literal_eval()` or safe mapping dictionaries."
}

def request_repair(cwe_id, func_code, data_flow_fact="", prev_error=None):
    rule = CWE_SPECIFIC_RULES.get(str(cwe_id), "Apply general security best practices.")
    
    prompt = f"""
    You are a Senior Security Engineer. Fix CWE-{cwe_id} in the code below.
    
    [STRICT RULES]
    1. {rule}
    2. Maintain function signatures and business logic.
    3. [DATA-FLOW CONTEXT]: {data_flow_fact}
    
    [ORIGINAL CODE]
    {func_code}
    """
    
    if prev_error:
        prompt += f"\n\n[PREVIOUS ATTEMPT FAILED]\nError Log: {prev_error}\nAnalyze the regression and provide a better fix."

    prompt += '\nOutput ONLY a JSON object: {"reasoning": "...", "fixed_code": "..."}'

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.2
    )
    data = json.loads(response.choices[0].message.content)
    return data.get("reasoning", ""), data.get("fixed_code", func_code)