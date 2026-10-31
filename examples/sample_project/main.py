"""
Sample evaluation project demonstrating multi-finding reachability.
PyYAML 5.3.1 triggers confirmed REACHABLE via yaml.load().
Requests 2.19.0 triggers UNCERTAIN due to dynamic reflection.
"""

import yaml
import requests


def run_pipeline(payload):
    return yaml.load(payload)

def dispatch_action(action_name):
    return getattr(requests, action_name)

if __name__ == "__main__":
    run_pipeline("test: 123")
