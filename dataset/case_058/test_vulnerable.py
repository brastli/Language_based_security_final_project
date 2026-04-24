import pytest
from unittest.mock import Mock, patch

from vulnerable import app, retrieve_info


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_functional_retrieve_info_returns_github_response_text():
    mock_response = Mock()
    mock_response.text = '{"login":"octocat","id":1}'

    with patch("vulnerable.requests.get", return_value=mock_response) as mock_get:
        with app.test_request_context("/user?user_id=octocat"):
            result = retrieve_info()

    assert result == '{"login":"octocat","id":1}'
    mock_get.assert_called_once_with("https://api.github.com/users/octocat")


def test_functional_route_user_endpoint_returns_response_text(client):
    mock_response = Mock()
    mock_response.text = "user-data"

    with patch("vulnerable.requests.get", return_value=mock_response) as mock_get:
        response = client.get("/user?user_id=octocat")

    assert response.status_code == 200
    assert response.data.decode() == "user-data"
    mock_get.assert_called_once_with("https://api.github.com/users/octocat")


def test_functional_missing_user_id_raises_keyerror():
    with app.test_request_context("/user"):
        with pytest.raises(KeyError):
            retrieve_info()


@pytest.mark.parametrize(
    "payload",
    [
        "octocat%0d%0aX-Injected-Header: evil",
        "../../etc/passwd",
        "octocat?foo=bar&admin=true",
    ],
)
def test_security_malicious_user_id_payloads_raise_exception(payload):
    with app.test_request_context(f"/user?user_id={payload}"):
        with pytest.raises(Exception):
            retrieve_info()