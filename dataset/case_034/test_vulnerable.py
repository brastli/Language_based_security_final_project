import pytest
from flask import Flask
from vulnerable import app, index


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_functional_index_imports_valid_module_version(client):
    response = client.get("/?module=.request")
    assert response.status_code == 200
    assert response.data == b"Module imported"


def test_functional_index_imports_another_valid_module_version(client):
    response = client.get("/?module=.parse")
    assert response.status_code == 200
    assert response.data == b"Module imported"


@pytest.mark.parametrize(
    "payload",
    [
        ";__import__('os').system('echo pwned')#",
        ";import os;os.system('id')#",
        ";__import__('subprocess').check_output('whoami', shell=True)#",
    ],
)
def test_security_malicious_module_payloads_raise_exception(payload):
    with app.test_request_context(f"/?module={payload}"):
        with pytest.raises(Exception):
            index()