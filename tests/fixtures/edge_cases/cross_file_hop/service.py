import yaml


def parse_document(raw_text):
    """Parses YAML using the vulnerable yaml.load() function."""
    return yaml.load(raw_text)
