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
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in self.vulnerable_vars:
                    self.dependency_lines.add(node.lineno)
        self.generic_visit(node)

def get_function_and_flow(filename, line_no):
    with open(filename, "r", encoding="utf-8") as f: source_code = f.read()
    tree = ast.parse(source_code)
    lines = source_code.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.lineno <= line_no <= node.end_lineno:
            v = DefUseVisitor(line_no); v.visit(node)
            sliced = [lines[i] + (" # <--- SINK" if i+1==line_no else " # <--- DEP" if i+1 in v.dependency_lines else "") for i in range(node.lineno-1, node.end_lineno)]
            fact = f"Vars {v.vulnerable_vars} flow into sink at line {line_no} from lines {list(v.dependency_lines)}."
            return "\n".join(sliced), fact
    return None, ""