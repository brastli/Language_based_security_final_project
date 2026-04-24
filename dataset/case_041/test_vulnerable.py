import pytest
from vulnerable import certificate_matches


def test_functional_certificate_matches_true():
    certificate = b"valid-certificate-bytes"
    known_hash = __import__("hashlib").md5(certificate).hexdigest()
    assert certificate_matches(certificate, known_hash) is True


def test_functional_certificate_matches_false():
    certificate = b"valid-certificate-bytes"
    known_hash = "0" * 32
    assert certificate_matches(certificate, known_hash) is False


@pytest.mark.parametrize(
    "malicious_certificate, known_hash",
    [
        (b"' OR '1'='1", "0" * 32),
        (b"; rm -rf /", "0" * 32),
        (b"$(id)", "0" * 32),
    ],
)
def test_security_certificate_matches_malicious_payloads(malicious_certificate, known_hash):
    with pytest.raises(Exception):
        certificate_matches(malicious_certificate, known_hash)