def compute_expression(expr):
    """Evaluate a math expression string and return the result (e.g. '1+2*3')."""
    if not expr or not expr.strip():
        return None
    try:
        result = eval(expr.strip())
        return float(result) if isinstance(result, (int, float)) else result
    except Exception:
        return None

if __name__ == "__main__":
    print(compute_expression("1 + 2"))
