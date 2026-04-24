import pytest
from vulnerable import checkAdminPassword


def test_functional_valid_admin_password():
    assert checkAdminPassword("admin") is True


def test_functional_invalid_non_admin_password():
    assert checkAdminPassword("Admin") is False


def test_functional_invalid_wrong_password():
    assert checkAdminPassword("password123") is False


def test_functional_rejects_non_string_input():
    with pytest.raises(TypeError):
        checkAdminPassword(12345)


def test_functional_rejects_control_characters():
    with pytest.raises(ValueError):
        checkAdminPassword("admi\n")


def test_functional_rejects_unicode_normalization_changes():
    with pytest.raises(ValueError):
        checkAdminPassword("a\u212dm\u0069n")


def test_security_sql_injection_payloads():
    malicious_payloads = [
        "' OR '1'='1",
        '" OR 1=1 --',
        "admin'/*",
    ]
    for payload in malicious_payloads:
        with pytest.raises(Exception):
            checkAdminPassword(payload)


def test_security_command_injection_payloads():
    malicious_payloads = [
        "$(id)",
        "admin; rm -rf /",
        "admin && whoami",
    ]
    for payload in malicious_payloads:
        with pytest.raises(Exception):
            checkAdminPassword(payload)


def test_security_comment_and_boolean_bypass_payloads():
    malicious_payloads = [
        "admin--",
        "admin/*comment*/",
        "OR admin",
    ]
    for payload in malicious_payloads:
        with pytest.raises(Exception):
            checkAdminPassword(payload)