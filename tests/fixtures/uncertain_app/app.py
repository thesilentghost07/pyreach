import yaml

def run():
    loader = getattr(yaml, "load")
    loader("payload: true")

if __name__ == "__main__":
    run()
