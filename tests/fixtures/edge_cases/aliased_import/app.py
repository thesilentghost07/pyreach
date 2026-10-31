from yaml import load as untrusted_parser


def run():
    payload = "admin: true"
    untrusted_parser(payload)


if __name__ == "__main__":
    run()
