import pytest
import hashlib

from vulnerable import storePassword


def updateUserLogin(userName, hashed_password):
    return {"userName": userName, "hashed_password": hashed_password}


def test_functional_storePassword_hashes_password_and_updates_user():
    user = "alice"
    password = b"secret123"

    result = storePassword(user, password)

    expected_hash = hashlib.md5(password).digest()
    assert result == {"userName": user, "hashed_password": expected_hash}


def test_functional_storePassword_handles_empty_password():
    user = "bob"
    password = b""

    result = storePassword(user, password)

    expected_hash = hashlib.md5(password).digest()
    assert result == {"userName": user, "hashed_password": expected_hash}


@pytest.mark.parametrize(
    "malicious_user, malicious_password",
    [
        ("admin' OR '1'='1", b"password"),
        ("; rm -rf /", b"password"),
        ("$(touch /tmp/pwned)", b"password"),
    ],
)
def test_security_storePassword_rejects_malicious_inputs(malicious_user, malicious_password):
    with pytest.raises(Exception):
        storePassword(malicious_user, malicious_password)