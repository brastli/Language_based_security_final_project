from vulnerable import run
import pickle

def test_run_with_valid_data():
    # Create a simple dictionary and serialize it using pickle
    original_data = {'key': 'value'}
    serialized_data = pickle.dumps(original_data)
    
    # Test the run function with the serialized data
    result = run(serialized_data)
    
    # Assert that the deserialized object matches the original data
    assert result == original_data

def test_run_with_empty_data():
    # Test the run function with empty serialized data
    serialized_data = pickle.dumps({})
    
    # Test the run function with the serialized data
    result = run(serialized_data)
    
    # Assert that the deserialized object is an empty dictionary
    assert result == {}