def connect_to_api():
    # 漏洞：硬编码敏感信息
    api_key = "sk-1234567890abcdef"
    return f"Connecting with {api_key}"