import pytest
from vulnerable_samples.db_service import fetch_user_profile

def test_fetch_user_logic():
    """
    验证基础查询逻辑：
    1. 输入合法用户 'guest' 应能返回结果。
    2. 返回结果应为 list 类型。
    """
    try:
        results = fetch_user_profile("guest")
        
        # 验证返回是否为列表
        assert isinstance(results, list), "返回结果应为列表格式"
        
        # 验证是否查询到了正确的数据
        if len(results) > 0:
            assert results[0][0] == "guest", "查询结果与输入用户名不匹配"
            
    except Exception as e:
        pytest.fail(f"基础业务逻辑运行失败，错误详情: {e}")

def test_empty_user():
    """验证查询不存在的用户时，程序不应崩溃"""
    results = fetch_user_profile("non_existent_user")
    assert len(results) == 0