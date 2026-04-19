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
# ======================================================================
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
    Send a contextual, guardrail-aware repair request to the LLM.

    Args:
        cwe_id: CWE id (e.g. 89).
        function_code: Vulnerable code slice (usually one function).
        data_flow_fact: Optional short data-flow summary for tainted vars.
        previous_error: Optional pytest/guardrail log from the previous attempt.
    """

    # Pick CWE-specific constraint text when available.
    specific_rule = CWE_SPECIFIC_RULES.get(
        str(cwe_id),
        "Fix the vulnerability using general security best practices."
    )

    # ---------- Base prompt (includes data-flow facts when present) ----------
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

    # ---------- Feedback from a failed verification round ----------
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

    # Force JSON-shaped output for reliable parsing downstream.
    prompt += '\nOutput ONLY a valid JSON object with exactly two keys: "reasoning" (A brief English explanation of your repair strategy) and "fixed_code" (The fixed Python code).'

    # ---------- LLM call ----------
    try:
        response = client.chat.completions.create(
            model="gpt-5.4-mini",
            messages=[
                {"role": "system", "content": "You are a precise code repair assistant. Always output valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={ "type": "json_object" },
            temperature=0.1  # Low temperature for deterministic code edits
        )

        data = json.loads(response.choices[0].message.content.strip())
        reasoning = data.get("reasoning", "No reasoning provided.")
        fixed_code = data.get("fixed_code", function_code)

        return reasoning, fixed_code

    except Exception as e:
        print(f"LLM Repair Request Failed: {e}")
        return f"Error: {e}", function_code

    # Anthropic (optional)
    # try:
    #     # Swap in Claude API if desired.
    #     response = client.messages.create(
    #         model="claude-3-5-sonnet-20240620",
    #         max_tokens=4096,
    #         system="You are a precise code repair assistant. Always output valid JSON.",
    #         messages=[
    #             {"role": "user", "content": prompt}
    #         ],
    #         temperature=0.1
    #     )

    #     content = response.content[0].text  # Claude response extraction differs slightly
    #     data = json.loads(content.strip())

    #     reasoning = data.get("reasoning", "No reasoning provided.")
    #     fixed_code = data.get("fixed_code", function_code)

    #     return reasoning, fixed_code

    # except Exception as e:
    #     print(f"Claude Repair Request Failed: {e}")
    #     return f"Error: {e}", function_code
