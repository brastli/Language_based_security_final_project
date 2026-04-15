from vulnerable import encrypt_secret
import pytest

def test_encrypt_secret_with_valid_input():
    plaintext = "secret12"
    key = "key12345"
    encrypted = encrypt_secret(plaintext, key)
    assert isinstance(encrypted, bytes)
    assert len(encrypted) % 8 == 0

def test_encrypt_secret_with_padding():
    plaintext = "secret"
    key = "key12345"
    encrypted = encrypt_secret(plaintext, key)
    assert isinstance(encrypted, bytes)
    assert len(encrypted) % 8 == 0