import yaml

def execute_dynamic_loader(loader_name: str, data: str):
    # UNCERTAIN: Dynamic reflection hazard via getattr() prevents static certainty
    func = getattr(yaml, loader_name)
    return func(data)

def main():
    execute_dynamic_loader("load", "foo: bar")

if __name__ == "__main__":
    main()
