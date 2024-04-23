from Crypto.Hash import SHA256
from Crypto.Hash import MD5

class Hashing:
    @staticmethod
    def hash(message: bytes, algorithm: str):
        if algorithm == "SHA-256":
            return SHA256.new(message)
        if algorithm == "MD5":
            h = MD5.new()
            h.update(message)
            return h
        raise ValueError("Algorithm should be either SHA-256 or MD5")


if __name__ == '__main__':
    hashing = Hashing()
    msg = b"Some message"
    message_hash = hashing.hash(msg, "SHA-256")
    print(message_hash.hexdigest())
