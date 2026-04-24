import os
import ast
from collections import defaultdict, deque

def extract_local_imports(file_path, base_dir):
    """Parse a file with AST and list same-project .py dependencies (import and from ... import)."""
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read())
        except SyntaxError:
            return []

    imports = []
    
    def add_if_local(module_name):
        if not module_name: return
        parts = module_name.split('.')
        if parts[0] == 'src':  # drop package root label when resolving paths
            parts = parts[1:]
        potential_path = os.path.normpath(os.path.join(base_dir, *parts) + '.py')
        if os.path.exists(potential_path):
            imports.append(potential_path)

    for node in ast.walk(tree):
        # `from X import Y` or relative `from . import Y`
        if isinstance(node, ast.ImportFrom):
            if node.module:
                add_if_local(node.module)
            elif node.level > 0:
                for alias in node.names:
                    add_if_local(alias.name)
        
        elif isinstance(node, ast.Import):
            for alias in node.names:
                add_if_local(alias.name)
                
    return imports

def get_repair_order(src_dir):
    """Topological order: repair dependencies before dependents (bottom-up)."""
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

    # Append any leftovers (cycles or unresolved edges)
    for f in files:
        if f not in repair_order:
            repair_order.append(f)

    return repair_order