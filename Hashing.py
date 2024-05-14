from Crypto.Hash import SHA256, MD5
from enum import Enum
from typing import Union


class HashingType(Enum):
    SHA256 = 'SHA256'
    MD5 = 'MD5'


class Hashing:
    @staticmethod
    def hash(message: bytes, algorithm: HashingType) -> Union[SHA256.SHA256Hash, MD5.MD5Hash]:
        return eval(algorithm.value).new(message)


if __name__ == '__main__':
    HASH = HashingType.SHA256
    hashing = Hashing()
    msg = b"Some message"
    message_hash = hashing.hash(msg, HASH)
    print(message_hash.hexdigest())