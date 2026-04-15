from vulnerable import checkout_branch
import pytest

def test_checkout_branch_success():
    # Assuming '/tmp/repo' is a valid repository path and 'main' is a valid branch
    result = checkout_branch("/tmp/repo", "main")
    assert result == True

def test_checkout_branch_invalid_branch():
    # Assuming '/tmp/repo' is a valid repository path but 'nonexistent' is not a valid branch
    result = checkout_branch("/tmp/repo", "nonexistent")
    assert result == False