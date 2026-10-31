import yaml

def process_untrusted_input(data: str):
    # REACHABLE VULNERABILITY: Directly calling yaml.load on untrusted input
    # Matches vulnerable symbol 'yaml.load' in PyYAML 5.3.1 (CVE-2020-14343)
    parsed = yaml.load(data)
    return parsed

def main():
    payload = "!!python/object/apply:os.system ['echo pwned']"
    process_untrusted_input(payload)

if __name__ == "__main__":
    main()
