from vulnerable import check_host_reachable

def test_check_host_reachable_localhost():
    assert check_host_reachable("127.0.0.1") == True

def test_check_host_reachable_empty_string():
    assert check_host_reachable("") == False