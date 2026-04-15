import re
from openai import OpenAI

client = OpenAI()

def generate_test_for_file(code_content):
    prompt = f"""
    Write a `pytest` file for the following code.
    You MUST include:
    1. test_functional_*: Verify normal inputs work correctly.
    2. test_security_*: Provide malicious payloads (SQLi, Command Injection, etc.) and assert they are safely handled or rejected.
    
    Code:
    {code_content}
    """
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1
    )
    content = response.choices[0].message.content.strip()
    return re.sub(r"```python\n|```", "", content)