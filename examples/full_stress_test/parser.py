import yaml as y
from jinja2 import escape

def parse_untrusted_payload(raw_text: str):
    return y.load(raw_text)

def format_safe_label(name: str):
    return escape(name)
