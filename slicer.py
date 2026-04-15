import ast

class DefUseVisitor(ast.NodeVisitor):
    def __init__(self, target_lineno):
        self.target_lineno = target_lineno
        self.vulnerable_vars = set()
        self.dependency_lines = set()

    def visit(self, node):
        if hasattr(node, 'lineno') and node.lineno == self.target_lineno:
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    self.vulnerable_vars.add(child.id)
            self.dependency_lines.add(node.lineno)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in self.vulnerable_vars:
                    self.dependency_lines.add(node.lineno)
        self.generic_visit(node)

def get_function_and_flow(filename, line_no):
    """提取带有数据流注释的代码及自然语言事实"""
    with open(filename, "r", encoding="utf-8") as f:
        source_code = f.read()
    
    tree = ast.parse(source_code)
    source_lines = source_code.splitlines()
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.lineno <= line_no <= node.end_lineno:
                visitor = DefUseVisitor(line_no)
                visitor.visit(node)
                
                sliced_code = []
                for i in range(node.lineno - 1, node.end_lineno):
                    curr_line = i + 1
                    line_text = source_lines[i]
                    if curr_line == line_no:
                        sliced_code.append(f"{line_text}  # <--- [VULNERABILITY SINK]")
                    elif curr_line in visitor.dependency_lines:
                        sliced_code.append(f"{line_text}  # <--- [DATA FLOW: DEFINITION]")
                    else:
                        sliced_code.append(line_text)
                
                fact = f"Vulnerability at line {line_no} is driven by variables {visitor.vulnerable_vars}, defined at lines {list(visitor.dependency_lines)}."
                return "\n".join(sliced_code), fact
    return None, "No specific data flow facts identified."