import yaml

def load_config(config_string):
    # Intentional: Unsafe Deserialization
    return yaml.load(config_string, Loader=yaml.Loader)
