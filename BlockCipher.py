from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from enum import Enum


class BlockCipherType(Enum):
    AES = AES
    DES = DES


class BlockCipherEncryption:
    def __init__(self, cipher: BlockCipherType, key: bytes) -> None:
        self.cipher = cipher.value.new(key, cipher.value.MODE_EAX)

    def get_nonce(self) -> bytes:
        return self.cipher.nonce

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt(plaintext)
        return ciphertext
    

class BlockCipherDecyption:
    def __init__(self, cipher: BlockCipherType, key: bytes, nonce: bytes) -> None:
        self.cipher = cipher.value.new(key, cipher.value.MODE_EAX, nonce)

    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt(ciphertext)
        return plaintext


if __name__ == '__main__':
    CIPHER = BlockCipherType.DES
    KEY_SIZE = 8

    key = get_random_bytes(KEY_SIZE)
    encryption = BlockCipherEncryption(CIPHER, key)
    with open('inputs/Skeleton.py', 'rb') as f:
        plaintext = f.read()
    
    ciphertext = encryption.encrypt(plaintext)
    with open('outputs/ciphertext.txt', 'wb') as f:
        f.write(ciphertext)

    decryption = BlockCipherDecyption(CIPHER, key, encryption.get_nonce())
    plaintext = decryption.decrypt(ciphertext)
    with open('outputs/plaintext.py', 'wb') as f:
        f.write(plaintext)