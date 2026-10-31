from service import parse_document


def run():
    result = parse_document("key: value")
    print(result)


if __name__ == "__main__":
    run()
