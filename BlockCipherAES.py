from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class BlockCipherEncryption:
    def __init__(self, key):
        self.cipher = AES.new(key, AES.MODE_EAX)

    def get_nonce(self):
        return self.cipher.nonce

    def encrypt(self, plaintext):
        ciphertext = self.cipher.encrypt(plaintext)
        return ciphertext
    

class BlockCipherDecyption:
    def __init__(self, key, nonce):
        self.cipher = AES.new(key, AES.MODE_EAX, nonce)

    def decrypt(self, ciphertext):
        plaintext = self.cipher.decrypt(ciphertext)
        return plaintext


if __name__ == '__main__':
    key = get_random_bytes(16)
    encryption = BlockCipherEncryption(key)
    with open('Tests/Skeleton.py', 'rb') as f:
        plaintext = f.read()
    ciphertext = encryption.encrypt(plaintext)
    with open('Code/ciphertext.txt', 'wb') as f:
        f.write(ciphertext)

    decryption = BlockCipherDecyption(key, encryption.get_nonce())
    plaintext = decryption.decrypt(ciphertext)
    with open('Code/plaintext.py', 'wb') as f:
        f.write(plaintext)