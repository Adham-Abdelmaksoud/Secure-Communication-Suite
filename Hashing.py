from Crypto.Hash import SHA256, MD5
from enum import Enum


class HashingType(Enum):
    SHA256 = SHA256
    MD5 = MD5


class Hashing:
    @staticmethod
    def hash(message: bytes, algorithm: HashingType):
        return algorithm.value.new(message)


if __name__ == '__main__':
    HASH = HashingType.SHA256
    hashing = Hashing()
    msg = b"Some message"
    message_hash = hashing.hash(msg, HASH)
    print(message_hash.hexdigest())
