def read_user_file(filename):
    # 漏洞：未过滤 ../ 路径
    with open(f"user_data/{filename}", "r") as f:
        return f.read()