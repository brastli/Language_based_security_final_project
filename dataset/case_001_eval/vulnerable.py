def run(user_input):
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
        ast.BitOr: operator.or_,
        ast.BitAnd: operator.and_,
        ast.BitXor: operator.xor,
        ast.LShift: operator.lshift,
        ast.RShift: operator.rshift,
    }
    allowed_unaryops = {
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
        ast.Not: operator.not_,
        ast.Invert: operator.invert,
    }
    allowed_names = {
        "abs": abs,
        "round": round,
        "min": min,
        "max": max,
        "sum": sum,
        "len": len,
        "sorted": sorted,
        "tuple": tuple,
        "list": list,
        "dict": dict,
        "set": set,
        "bool": bool,
        "int": int,
        "float": float,
        "str": str,
    }

    def _safe_eval(node):
        if isinstance(node, ast.Expression):
            return _safe_eval(node.body)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float, complex, str, bytes, bool, type(None))):
                return node.value
            raise ValueError("unsupported constant")
        if isinstance(node, ast.BinOp) and type(node.op) in allowed_binops:
            return allowed_binops[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in allowed_unaryops:
            return allowed_unaryops[type(node.op)](_safe_eval(node.operand))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in allowed_names:
            if node.keywords:
                raise ValueError("keyword arguments are not allowed")
            return allowed_names[node.func.id](*[_safe_eval(arg) for arg in node.args])
        if isinstance(node, ast.Tuple):
            return tuple(_safe_eval(elt) for elt in node.elts)
        if isinstance(node, ast.List):
            return [_safe_eval(elt) for elt in node.elts]
        if isinstance(node, ast.Dict):
            return {_safe_eval(k): _safe_eval(v) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.Set):
            return {_safe_eval(elt) for elt in node.elts}
        raise ValueError("unsafe expression")

    tree = ast.parse(user_input, mode="eval")
    return _safe_eval(tree)