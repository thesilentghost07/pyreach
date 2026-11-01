import yaml

def load_from_disk(raw_yaml):
    return yaml.load(raw_yaml)

def ingest_webhook(payload):
    return load_from_disk(payload)

def main():
    return ingest_webhook("foo: bar")

if __name__ == "__main__":
    main()
