import yaml

def process_safe_input(data: str):
    # NOT REACHABLE: Using yaml.safe_load, which is safe against arbitrary code execution
    parsed = yaml.safe_load(data)
    return parsed

def main():
    payload = "name: Antigravity\nstatus: active"
    process_safe_input(payload)

if __name__ == "__main__":
    main()
