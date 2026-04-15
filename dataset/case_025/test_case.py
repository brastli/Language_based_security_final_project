from vulnerable import verify_package_checksum
import hashlib

def test_verify_package_checksum_with_valid_file():
    # Create a temporary file with known content
    file_content = b"test content"
    expected_checksum = hashlib.sha1(file_content).hexdigest()
    
    with open("temp_test_file.txt", "wb") as temp_file:
        temp_file.write(file_content)
    
    # Test the function with the file path
    assert verify_package_checksum("temp_test_file.txt", expected_checksum) == True

def test_verify_package_checksum_with_valid_data():
    # Use known data and its checksum
    data = b"another test content"
    expected_checksum = hashlib.sha1(data).hexdigest()
    
    # Test the function with the data directly
    assert verify_package_checksum(data, expected_checksum) == True