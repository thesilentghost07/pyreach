import yaml

def parse_safely(raw_yaml: str):
    return yaml.safe_load(raw_yaml)

def main():
    return parse_safely("safe: true")

if __name__ == "__main__":
    main()
