from vulnerable import compute_expression

def test_compute_expression_basic_addition():
    assert compute_expression("1 + 2") == 3.0

def test_compute_expression_multiplication_and_addition():
    assert compute_expression("1 + 2 * 3") == 7.0