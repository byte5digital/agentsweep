"""Turn the configured hex colour into the three channel values."""


def channels(colour: str) -> tuple[int, int, int]:
    red, green, blue = bytes.fromhex(colour.lstrip("#"))
    return red, green, blue


if __name__ == "__main__":
    print(channels("ff8800"))
