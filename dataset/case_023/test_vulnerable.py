import pytest
from vulnerable import render_user_template


def test_functional_returns_empty_string_for_empty_template():
    assert render_user_template("", {"name": "Alice"}) == ""


def test_functional_returns_empty_string_for_non_dict_context():
    assert render_user_template("output = name", ["Alice"]) == ""


def test_functional_renders_allowed_context_value():
    assert render_user_template("output = name", {"name": "Alice"}) == "Alice"


def test_functional_renders_multiple_allowed_values():
    template = "output = f'{title}: {name} ({count})'"
    context = {"title": "Hello", "name": "Alice", "count": 3}
    assert render_user_template(template, context) == "Hello: Alice (3)"


def test_functional_ignores_disallowed_keys():
    template = "output = secret if 'secret' in locals() else name"
    context = {"name": "Alice", "secret": "TOP_SECRET"}
    assert render_user_template(template, context) == "Alice"


@pytest.mark.parametrize(
    "payload",
    [
        "output = __import__('os').system('echo pwned')",
        "output = open('/etc/passwd').read()",
        "output = eval('2 + 2')",
    ],
)
def test_security_malicious_payloads_raise_exception(payload):
    with pytest.raises(Exception):
        render_user_template(payload, {"name": "Alice", "title": "Hi", "items": [], "count": 1})