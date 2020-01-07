def random_string(size: int = 10) -> str:
    import random
    import string
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(size)])
