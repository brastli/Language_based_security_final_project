import ast

def get_function_at_line(filename, line_no):
    """利用 AST 提取特定行号所属的函数 [cite: 24]"""
    with open(filename, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.lineno <= line_no <= node.end_lineno:
                return ast.unparse(node) # 返回函数源码 [cite: 25]
    return None