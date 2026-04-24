def compute_expression(expr):
    """Evaluate a math expression string and return the result (e.g. '1+2*3')."""
    if not expr or not expr.strip():
        return None
    try:
        import ast
        import operator

        allowed_binops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.FloorDiv: operator.floordiv,
            ast.Mod: operator.mod,
            ast.Pow: operator.pow,
        }
        allowed_unaryops = {
            ast.UAdd: operator.pos,
            ast.USub: operator.neg,
        }

        def _safe_eval(node):
            if isinstance(node, ast.Expression):
                return _safe_eval(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return node.value
            if isinstance(node, ast.BinOp) and type(node.op) in allowed_binops:
                return allowed_binops[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
            if isinstance(node, ast.UnaryOp) and type(node.op) in allowed_unaryops:
                return allowed_unaryops[type(node.op)](_safe_eval(node.operand))
            raise ValueError("Unsupported expression")

        tree = ast.parse(expr.strip(), mode='eval')
        result = _safe_eval(tree)
        return float(result) if isinstance(result, (int, float)) else result
    except Exception:
        return None