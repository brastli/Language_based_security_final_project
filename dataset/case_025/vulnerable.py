import hashlib

def verify_package_checksum(file_path_or_data, expected_hex):
    """Verify integrity of downloaded package or data using stored SHA1 checksum."""
    if not expected_hex or len(expected_hex) != 40:
        return False
    expected_hex = expected_hex.strip().lower()
    if isinstance(file_path_or_data, str):
        try:
            with open(file_path_or_data, "rb") as f:
                data = f.read()
        except OSError:
            return False
    elif isinstance(file_path_or_data, bytes):
        data = file_path_or_data
    else:
        return False
    if not data:
        return False
    digest = hashlib.sha1(data).hexdigest()
    return digest == expected_hex

if __name__ == "__main__":
    verify_package_checksum(b"payload", "a" * 40)
