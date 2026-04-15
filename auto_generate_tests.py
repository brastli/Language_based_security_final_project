import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def generate_test_for_file(vuln_code):
    """请求 LLM 自动生成合法的 pytest 测试代码"""
    prompt = f"""
    You are an expert Python QA Engineer. 
    I will give you a piece of Python code. Your task is to write a simple `pytest` file to test its NORMAL functional behavior.
    
    STRICT RULES:
    1. You MUST import the function from a module named `vulnerable`. (e.g., `from vulnerable import my_function`).
    2. Read the provided code to find out the exact function name and its required parameters.
    3. Write 1 or 2 basic tests to ensure the business logic works with normal, legal, and safe inputs.
    4. DO NOT write payloads to exploit the vulnerability. Only test normal functionality.
    5. Output ONLY the valid Python code. Do not include markdown code blocks like ```python.
    
    Original Code:
    {vuln_code}
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a precise test generation assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1
        )
        
        test_code = response.choices[0].message.content.strip()
        # 移除可能存在的 markdown 标记
        if test_code.startswith("```python"):
            test_code = test_code.replace("```python", "").strip()
        if test_code.endswith("```"):
            test_code = test_code[:-3].strip()
            
        return test_code
    except Exception as e:
        print(f"Failed to generate test case: {e}")
        return ""

def main():
    dataset_dir = "dataset"
    
    if not os.path.exists(dataset_dir):
        print(f"Directory not found: {dataset_dir}")
        return

    # 遍历所有 case
    for case_folder in sorted(os.listdir(dataset_dir)):
        case_path = os.path.join(dataset_dir, case_folder)
        
        if os.path.isdir(case_path):
            vuln_file = os.path.join(case_path, "vulnerable.py")
            test_file = os.path.join(case_path, "test_case.py")
            
            if os.path.exists(vuln_file):
                print(f"⏳ generating test case for {case_folder} ...")
                with open(vuln_file, "r", encoding="utf-8") as f:
                    vuln_code = f.read()
                
                # 调用 LLM 生成专属测试用例
                test_code = generate_test_for_file(vuln_code)
                
                if test_code:
                    with open(test_file, "w", encoding="utf-8") as f:
                        f.write(test_code)
                    print(f"✅ success！{case_folder} 's test case generated.")
                else:
                    print(f"❌ {case_folder} test generation failed.")

if __name__ == "__main__":
    print("=== Auto-Generating Test Cases ===")
    main()
    print("=== All test cases generated ===")