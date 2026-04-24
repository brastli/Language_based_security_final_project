import pytest
from flask import Flask
from vulnerable import app, render_response_from_env


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_functional_render_with_valid_name(client):
    response = client.get("/render?name=Alice")
    assert response.status_code == 200
    assert b"Alice" in response.data


def test_functional_render_with_empty_name(client):
    response = client.get("/render")
    assert response.status_code == 200
    assert response.data is not None


def test_functional_render_with_special_characters(client):
    response = client.get("/render?name=John%20Doe")
    assert response.status_code == 200
    assert b"John Doe" in response.data


def test_security_template_injection_payload(client):
    payload = "{{7*7}}"
    with pytest.raises(Exception):
        client.get(f"/render?name={payload}")


def test_security_jinja_expression_payload(client):
    payload = "{{config}}"
    with pytest.raises(Exception):
        client.get(f"/render?name={payload}")


def test_security_command_injection_like_payload(client):
    payload = "; cat /etc/passwd"
    with pytest.raises(Exception):
        client.get(f"/render?name={payload}")