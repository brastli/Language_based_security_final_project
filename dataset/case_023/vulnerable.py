def render_user_template(template_code, context):
    """Run user-supplied template snippet with given context (e.g. placeholder substitution)."""
    if not template_code or not isinstance(context, dict):
        return ""
    allowed_keys = {"name", "title", "items", "count"}
    local_ctx = {k: context[k] for k in context if k in allowed_keys}
    local_ctx["output"] = ""
    local_ctx["__builtins__"] = {}
    try:
        exec(template_code, {"__builtins__": {}}, local_ctx)
        result = local_ctx.get("output", "")
        return str(result) if result is not None else ""
    except Exception:
        return ""

if __name__ == "__main__":
    render_user_template("output = name", {"name": "Alice"})
