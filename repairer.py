import os
import json
from openai import OpenAI
from dotenv import load_dotenv
import anthropic

# Load .env from project root (OPENAI_API_KEY).
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
# client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ======================================================================
# CWE-specific rule catalog (reference knowledge for the model).
# Goal: curb sycophantic shortcuts and steer toward standard defenses.
# This acts as the baseline/fallback if the SQL Strategy DB is empty.
# ======================================================================
CWE_SPECIFIC_RULES = {
    "78": "CRITICAL: Replace `os.system`, `eval`, or `shell=True` with `subprocess.run()`. Command arguments MUST be passed as a Python list, NEVER as a concatenated string.",
    "89": "CRITICAL: Use parameterized SQL queries (e.g., `cursor.execute(query, (params,))`). DO NOT use string formatting or concatenation for SQL.",
    "22": "CRITICAL: Resolve absolute paths using `os.path.abspath` and explicitly verify that the final path starts with the intended safe base directory using `.startswith()`.",
    "94": "CRITICAL: DO NOT use `eval()` or `exec()`. If evaluating data structures, use `ast.literal_eval()`. If complex logic is needed, use a safe mapping dictionary.",
    "330": "CRITICAL: DO NOT use the `random` module for security/cryptographic purposes. You MUST use the `secrets` module (e.g., `secrets.token_hex`, `secrets.choice`).",
    "327": "CRITICAL: DO NOT use broken or risky cryptographic algorithms like MD5 or SHA1. You MUST upgrade to secure algorithms like SHA256 (e.g., `hashlib.sha256`) or PBKDF2.",
    "259": "CRITICAL: DO NOT hardcode passwords or secrets. Use `os.getenv('SECRET_KEY', 'default_safe_value')` or decouple the secret from the source code entirely. Maintain the exact same return structure."
}

def get_base_strategy(cwe_id):
    """Fallback to local rules if the strategy database doesn't have an entry yet."""
    return CWE_SPECIFIC_RULES.get(
        str(cwe_id),
        "Fix the vulnerability using general security best practices while strictly maintaining business logic."
    )

def request_repair(cwe_id, function_code, current_strategy=None, data_flow_fact="", previous_error=None):
    """
    Send a contextual, guardrail-aware repair request to the LLM.
    Now supports the "Strategy Evolution Loop".
    """

    # 1. Decide which strategy to use (DB provided vs. Local Fallback)
    active_strategy = current_strategy if current_strategy else get_base_strategy(cwe_id)

    # ---------- Base prompt (includes data-flow facts when present) ----------
    prompt = f"""
    You are an Autonomous Security Engineer. Your task is to fix a security vulnerability (CWE-{cwe_id}) in the provided Python function.

    [CURRENT REPAIR STRATEGY FOR CWE-{cwe_id}]:
    {active_strategy}

    STRICT RULES:
    1. You MUST strictly adhere to the [CURRENT REPAIR STRATEGY] above.
    2. DO NOT change the function name or parameter list signatures.
    3. Retain existing business logic while neutralizing the threat.
    4. 🛑 CRITICAL SYNTAX UPGRADE: This code might be written in Python 2 (e.g., `print "hi"`, `except Exception, e:`). You MUST automatically upgrade any legacy syntax to modern Python 3 so it can execute without SyntaxErrors. Add any obviously missing imports.

    [DATA-FLOW FACTS]:
    {data_flow_fact if data_flow_fact else "No specific data flow facts provided."}

    Original Code:
    {function_code}
    """

    # ---------- Feedback from a failed verification round (Strategy Evolution) ----------
    if previous_error:
        prompt += f"""
        \n[CRITICAL FEEDBACK FROM PREVIOUS ATTEMPT]:
        Your previous patch AND strategy FAILED the guardrail verification.

        Pytest Error Log:
        {previous_error}

        CRITICAL EVOLUTION INSTRUCTIONS FOR THIS RETRY:
        1. DO NOT repeat the exact same code you just generated.
        2. If the error is an 'AssertionError' or 'TypeError' from a Functional Test, your patch broke the business logic. You MUST relax your filtering. Maintain the expected return types and structural data flow.
        3. If the error is an OS/Environment Error (like WinError 2), your strategy conflicts with the sandbox environment. Refine the strategy to be environment-aware.
        4. Analyze WHY the previous strategy failed. You MUST EVOLVE and refine the [CURRENT REPAIR STRATEGY] to handle this edge case so we learn from this mistake.
        5. Output the new, refined strategy description, and then the updated robust patch.
        """
    else:
        prompt += """
        \nSince this is the first attempt, you may reuse the [CURRENT REPAIR STRATEGY] as is, or slightly refine it if you notice environment-specific nuances.
        """

    # Force JSON-shaped output for reliable parsing downstream.
    prompt += '\nOutput ONLY a valid JSON object with exactly three keys: "reasoning" (A brief explanation of your code edit), "strategy" (The evolved/refined repair strategy text to be saved in the database for future use), and "fixed_code" (The fixed Python code).'

    # ---------- LLM call ----------
    try:
        response = client.chat.completions.create(
            model="gpt-5.4-mini", 
            messages=[
                {"role": "system", "content": "You are a precise code repair assistant. Always output valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={ "type": "json_object" },
            temperature=0.1  
        )

        data = json.loads(response.choices[0].message.content.strip())
        
        reasoning = data.get("reasoning", "No reasoning provided.")
        evolved_strategy = data.get("strategy", active_strategy)
        fixed_code = data.get("fixed_code", function_code)

        # ================= 新增：自动清洗 LLM 幻觉产生的 Markdown =================
        if isinstance(fixed_code, str):
            fixed_code = fixed_code.strip()
            if fixed_code.startswith("```python"):
                fixed_code = fixed_code[9:]
            elif fixed_code.startswith("```"):
                fixed_code = fixed_code[3:]
            if fixed_code.endswith("```"):
                fixed_code = fixed_code[:-3]
            fixed_code = fixed_code.strip()
        # =========================================================================

        return reasoning, evolved_strategy, fixed_code

    except Exception as e:
        print(f"LLM Repair Request Failed: {e}")
        return f"Error: {e}", active_strategy, function_code