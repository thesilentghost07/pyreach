import yaml


def unused_legacy_importer():
    """This function calls a vulnerable symbol but is never invoked."""
    return yaml.load("admin: true")


def run():
    """Entry point — uses only safe APIs."""
    data = yaml.safe_load("safe: true")
    print(data)


if __name__ == "__main__":
    run()
