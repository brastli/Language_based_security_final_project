import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY missing; set it in .env or the environment.")

client = OpenAI(api_key=api_key)

def generate_test_for_file(vuln_code, rel_file_path="module.py", quiet=False):
    """
    Generate a pytest module for vuln_code.
    rel_file_path (e.g. 'src/db.py') becomes import path 'src.db'.
    """
    module_path = rel_file_path.replace('\\', '/').replace('.py', '').replace('/', '.')
    
    prompt = f"""
    You are an Expert QA and Security Engineer. Your task is to write a comprehensive `pytest` script for the following Python code.
    
    CRITICAL IMPORT RULE:
    You MUST import the functions you are testing directly from `{module_path}`.
    DO NOT use placeholders like 'your_module' or just the file name.
    Example: `from {module_path} import [function_name]`
    
    CRITICAL REQUIREMENT - You MUST write TWO categories of tests:
    1. Functional Tests (methods starting with `test_functional_`): Verify the normal business logic with valid, expected inputs.
    2. Security Fuzzing Tests (methods starting with `test_security_`): Generate at least 3 malicious payloads relevant to the code (e.g., SQLi strings, Command Injection characters). Since the patched function might raise an Exception (like ValueError) when encountering malicious payloads, you MUST use a `with pytest.raises(Exception):` block around the function call to catch expected security rejections.

    STRICT OUTPUT RULES:
    - Output ONLY the valid Python code. 
    - NO markdown formatting.
    - Ensure all necessary imports (including pytest) are included.
    
    Code to test:
    {vuln_code}
    """
    
    try:
        if not quiet:
            print("Generating pytest (functional + security) via LLM...")
        response = client.chat.completions.create(
            model="gpt-5.4-mini",
            messages=[
                {"role": "system", "content": "You output clean, executable Python code."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2 
        )
        
        content = response.choices[0].message.content.strip()
        
        # Strip markdown fences so the result is valid Python
        content = content.replace("```python", "").replace("```", "").strip()
        
        return content

    except Exception as e:
        print(f"Test generation failed: {e}")
        return None

if __name__ == "__main__":
    pass