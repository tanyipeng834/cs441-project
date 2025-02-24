import atexit
from models.router import Router


if __name__ == "__main__":
    router = Router("R1", 50004, {"R1": ["N1"], "R2": ["N2", "N3"]})
    atexit.register(router.shutdown)
