import yaml


def ping(n):
    if n <= 0:
        return yaml.safe_load("done: true")
    return pong(n - 1)


def pong(n):
    if n <= 0:
        return yaml.safe_load("done: true")
    return ping(n - 1)


def run():
    result = ping(10)
    print(result)


if __name__ == "__main__":
    run()
