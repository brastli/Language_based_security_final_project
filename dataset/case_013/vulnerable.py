import yaml

def load_user_config(config_str):
    """Load app configuration from YAML string provided by user."""
    if not config_str:
        return {}
    try:
        config = yaml.load(config_str, Loader=yaml.Loader)
        return config if isinstance(config, dict) else {}
    except yaml.YAMLError:
        return {}

if __name__ == "__main__":
    print(load_user_config("theme: dark\nlang: en"))
