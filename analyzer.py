import os
import ast
from collections import defaultdict, deque

def extract_local_imports(file_path, base_dir):
    """通过 AST 解析文件，提取其对同项目内其他文件的依赖"""
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read())
        except SyntaxError:
            return []

    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            # 处理相对导入与绝对导入路径映射
            module_parts = node.module.split('.')
            # 假设项目源码都在 src 目录下
            if module_parts[0] == 'src':
                module_parts = module_parts[1:]
            
            potential_path = os.path.normpath(os.path.join(base_dir, *module_parts) + '.py')
            if os.path.exists(potential_path):
                imports.append(potential_path)
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