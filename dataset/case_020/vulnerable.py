import yaml

def parse_feature_flags(yaml_str):
    """Parse feature flags from YAML string (e.g. from API or file upload)."""
    if not yaml_str:
        return {}
    try:
        flags = yaml.load(yaml_str, Loader=yaml.Loader)
        return flags if isinstance(flags, dict) else {}
    except yaml.YAMLError:
        return {}

if __name__ == "__main__":
    parse_feature_flags("new_ui: true\nbeta: false")
