import hashlib
import pytest
from vulnerable import verify_package_checksum


def test_functional_bytes_valid_checksum():
    data = b"payload"
    expected = hashlib.sha1(data).hexdigest()
    assert verify_package_checksum(data, expected) is True


def test_functional_file_path_valid_checksum(tmp_path):
    data = b"hello world"
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(data)
    expected = hashlib.sha1(data).hexdigest()
    assert verify_package_checksum(str(file_path), expected) is True


def test_functional_invalid_checksum_returns_false():
    data = b"payload"
    wrong_expected = "0" * 40
    assert verify_package_checksum(data, wrong_expected) is False


def test_functional_empty_data_returns_false():
    assert verify_package_checksum(b"", "a" * 40) is False


def test_functional_invalid_expected_length_returns_false():
    data = b"payload"
    assert verify_package_checksum(data, "abc") is False


def test_functional_nonexistent_file_returns_false():
    assert verify_package_checksum("/path/does/not/exist.bin", "a" * 40) is False


def test_functional_unsupported_input_type_returns_false():
    assert verify_package_checksum(12345, "a" * 40) is False


def test_security_malicious_payloads_raise_or_reject():
    malicious_payloads = [
        b"' OR '1'='1",
        b"; rm -rf /",
        b"$(touch /tmp/pwned)",
    ]
    expected = "a" * 40

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            verify_package_checksum(payload, expected)


def test_security_malicious_file_paths_raise_or_reject(tmp_path):
    malicious_paths = [
        "../../etc/passwd",
        "/tmp/test;echo hacked",
        "C:\\Windows\\System32\\drivers\\etc\\hosts && calc.exe",
    ]
    expected = "a" * 40

    for path in malicious_paths:
        with pytest.raises(Exception):
            verify_package_checksum(path, expected)