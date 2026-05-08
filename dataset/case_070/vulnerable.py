"""
case_070 ← exported case_011_CVE-2022-0845_argparse (pytorch_lightning utilities/argparse.py).

parse 流程中使用 eval(str)；混入占位解析辅助函数。
"""


def str_to_bool_stub(x):
    return x in ("1", "true", "True")


def parse_cli_value(val: str):
    """VULNERABLE：对标 eval(val) 分支。"""
    try:
        return eval(val)
    except Exception:
        return val


def collect_init_args_stub(names):
    """占位。"""
    return list(names)