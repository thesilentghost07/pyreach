import yaml


def outer_processor():
    def inner_dispatch(data):
        return yaml.load(data)
    return inner_dispatch("payload: true")


def run():
    outer_processor()


if __name__ == "__main__":
    run()
