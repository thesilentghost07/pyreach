import yaml

def dynamic_dispatch(raw_yaml: str, mode: str):
    loader_fn = getattr(yaml, mode)
    return loader_fn(raw_yaml)

def main():
    return dynamic_dispatch("key: val", "safe_load")

if __name__ == "__main__":
    main()
