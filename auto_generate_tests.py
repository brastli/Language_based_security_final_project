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
    Generate a pytest module for vuln_code using Advanced Mocking to prevent Sandbox crashing.
    """
    module_path = rel_file_path.replace('\\', '/').replace('.py', '').replace('/', '.')
    
    prompt = f"""
    You are an Expert QA and Security Engineer. Your task is to write a comprehensive `pytest` script for the following Python code.
    
    CRITICAL IMPORT & EXECUTION RULES:
    1. The target module is `{module_path}`.
    2. WARNING: Many code snippets are RAW SCRIPTS WITHOUT FUNCTIONS. 
       - IF the code contains functions/classes, import them: `from {module_path} import func_name`.
       - IF the code is just top-level global statements, DO NOT try to import functions. Instead, write tests that use `subprocess.run(['python', '{rel_file_path}'])` to verify it executes without errors.

    🛑 CRITICAL MOCKING RULES (PREVENT HANGING):
    Many of these scripts contain blocking calls like `app.run()`, `socket.listen()`, `urllib.urlopen()`, or `input()`.
    You MUST extensively use `@patch` from `unittest.mock` to mock out network calls, file system operations, web server startups, and standard inputs. Do NOT let the test hang!

    CRITICAL REQUIREMENT - Write TWO categories of tests:
    1. Functional Tests: Verify the normal behavior (mocking required components).
    2. Security Guardrail Tests: Generate malicious payloads relevant to the sink. Assert the patched code safely rejects the attack WITHOUT crashing.

    STRICT OUTPUT RULES:
    - Output ONLY the valid Python code. NO markdown formatting (do not wrap in ```python).
    - Ensure `import pytest` and `from unittest.mock import patch, MagicMock` are included.
    
    Code to test:
    {vuln_code}
    """
    
    try:
        if not quiet:
            print("[TEST GEN] Generating dynamic Pytest suite via LLM...")
        response = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[
                {"role": "system", "content": "You output clean, executable Python pytest code. Never use markdown code blocks."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1 
        )
        
        content = response.choices[0].message.content.strip()
        
        # 终极 Markdown 清洗机制
        if content.startswith("```python"):
            content = content[9:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
            
        return content.strip()

    except Exception as e:
        print(f"[TEST GEN ERROR] Test generation failed: {e}")
        return None