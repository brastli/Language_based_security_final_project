from pathlib import Path


def read_log_file(filename: str):
    """???:??? filename,??????"""
    base_dir = Path(__file__).resolve().parent / 'logs'
    target_path = base_dir / filename

    with target_path.open('r', encoding='utf-8') as f:
        return f.read()
