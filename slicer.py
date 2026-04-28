import ast
import traceback

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

def extract_semantic_slice(source_text, vulnerability_line_number, fallback_lines=30):
    """
    修改点：增加了 try-except 降级机制，防止 AST 解析失败导致整个 Case 崩溃
    """
    try:
        tree = ast.parse(source_text)
        lines = source_text.splitlines()
        
        best_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= vulnerability_line_number <= node.end_lineno:
                        if best_node is None or (node.end_lineno - node.lineno < best_node.end_lineno - best_node.lineno):
                            best_node = node
                            
        if best_node:
            slice_text = "\n".join(lines[best_node.lineno - 1 : best_node.end_lineno])
            return slice_text, "AST_EXACT_MATCH"
            
    except SyntaxError as e:
        print(f"[SLICER WARNING] AST 语法解析失败，启用降级方案: {e}")
    except Exception as e:
        print(f"[SLICER WARNING] 未知切片错误，启用降级方案:\n{traceback.format_exc()}")

    # 降级保底方案：直接提取漏洞行前后的文本，确保 LLM 始终有代码可看
    lines = source_text.splitlines()
    start_line = max(0, vulnerability_line_number - fallback_lines - 1)
    end_line = min(len(lines), vulnerability_line_number + fallback_lines)
    fallback_text = "\n".join(lines[start_line:end_line])
    
    return fallback_text, "FALLBACK_TEXT_WINDOW"