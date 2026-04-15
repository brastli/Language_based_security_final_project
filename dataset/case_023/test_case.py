from vulnerable import render_user_template

def test_render_user_template_with_valid_context():
    template_code = "output = name"
    context = {"name": "Alice"}
    result = render_user_template(template_code, context)
    assert result == "Alice"

def test_render_user_template_with_missing_context_key():
    template_code = "output = name"
    context = {"title": "Engineer"}
    result = render_user_template(template_code, context)
    assert result == ""