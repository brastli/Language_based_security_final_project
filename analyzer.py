import os
import ast
from collections import defaultdict, deque

def extract_local_imports(file_path, base_dir):
    """通过 AST 解析文件，提取其对同项目内其他文件的依赖 (支持 import 和 from import)"""
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read())
        except SyntaxError:
            return []

    imports = []
    
    # 辅助函数：尝试将模块名转换为绝对路径并检查是否存在
    def add_if_local(module_name):
        if not module_name: return
        parts = module_name.split('.')
        if parts[0] == 'src': # 剔除 src 前缀
            parts = parts[1:]
        potential_path = os.path.normpath(os.path.join(base_dir, *parts) + '.py')
        if os.path.exists(potential_path):
            imports.append(potential_path)

    for node in ast.walk(tree):
        # 处理 `from X import Y` 或 `from . import Y`
        if isinstance(node, ast.ImportFrom):
            if node.module:
                add_if_local(node.module)
            elif node.level > 0: # 处理 from . import utils
                for alias in node.names:
                    add_if_local(alias.name)
        
        # 处理 `import X`
        elif isinstance(node, ast.Import):
            for alias in node.names:
                add_if_local(alias.name)
                
    return imports

def get_repair_order(src_dir):
    """基于拓扑排序计算自底向上的修复序列"""
    graph = defaultdict(list)
    in_degree = defaultdict(int)
    
    files = []
    for root, _, filenames in os.walk(src_dir):
        for f in filenames:
            if f.endswith('.py') and f != '__init__.py':
                files.append(os.path.normpath(os.path.join(root, f)))

    for f in files:
        in_degree[f] = 0

    for f in files:
        deps = extract_local_imports(f, src_dir)
        for dep in deps:
            if dep in files:
                graph[dep].append(f)
                in_degree[f] += 1

    queue = deque([f for f in files if in_degree[f] == 0])
    repair_order = []

    while queue:
        node = queue.popleft()
        repair_order.append(node)
        for neighbor in graph[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    # 兜底：处理可能的循环依赖或未排序文件
    for f in files:
        if f not in repair_order:
            repair_order.append(f)

    return repair_order