import pickle
def load_data(raw_data):
    # 漏洞：不安全地加载 pickle 数据
    return pickle.loads(raw_data)