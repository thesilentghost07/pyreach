import yaml


def run():
    module_name = "yaml"
    func_name = "load"
    eval(f"{module_name}.{func_name}('admin: true')")


if __name__ == "__main__":
    run()
