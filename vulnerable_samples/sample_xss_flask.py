from flask import render_template_string
def welcome_user(name):
    # 漏洞：直接渲染未经转义的用户输入
    return render_template_string(f"<h1>Welcome {name}</h1>")