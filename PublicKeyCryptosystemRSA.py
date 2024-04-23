from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss

class PublicKeyCryptosystemEncryption:
    def __init__(self, public_key) -> None:
        self.public_key = public_key
        self.cipher_rsa = PKCS1_OAEP.new(public_key)

    def encrypt(self, message):
        return self.cipher_rsa.encrypt(message)

class PublicKeyCryptosystemDecryption:
    def __init__(self, private_key) -> None:
        self.private_key = private_key
        self.cipher_rsa = PKCS1_OAEP.new(private_key)

    def decrypt(self, message):
        return self.cipher_rsa.decrypt(message)

class PublicKeyCryptosystemSigning:
    def __init__(self, private_key) -> None:
        self.private_key = private_key
        self.signer = pss.new(private_key)

    def sign(self, hashed_message):
        return self.signer.sign(hashed_message)

class PublicKeyCryptosystemVerification:
    def __init__(self, public_key) -> None:
        self.private_key = public_key
        self.verifier = pss.new(public_key)

    def verify(self, hashed_message, signature):
        try:
            self.verifier.verify(hashed_message,signature)
            return True
        except ValueError:
            return False


if __name__ == '__main__':
    from Hashing import Hashing
    private_key = RSA.generate(1024)
    public_key = private_key.public_key()

    encryption = PublicKeyCryptosystemEncryption(public_key)

    ORIGINAL_MESSAGE = b"Hello, this is a message to be encrypted"
    original_cipher_text = encryption.encrypt(ORIGINAL_MESSAGE)
    # print(original_cipher_text)

    TAMPERED_MESSAGE = b"This is a tampered message"
    tampered_cipher_text = encryption.encrypt(TAMPERED_MESSAGE)

    hash_sender = Hashing.hash(ORIGINAL_MESSAGE,"SHA-256")
    signing = PublicKeyCryptosystemSigning(private_key)
    signed_message = signing.sign(hash_sender)

    # normal receive
    decryption = PublicKeyCryptosystemDecryption(private_key)
    plain_text = decryption.decrypt(original_cipher_text)
    print(plain_text)
    hash_receiver = Hashing.hash(plain_text,"SHA-256")
    verifying = PublicKeyCryptosystemVerification(public_key)
    if verifying.verify(hash_receiver,signed_message):
        print("The message is original")
    else:
        print("The message have been tampered with")

    # tampered receive
    decryption = PublicKeyCryptosystemDecryption(private_key)
    plain_text = decryption.decrypt(tampered_cipher_text)
    print(plain_text)
    hash_receiver = Hashing.hash(plain_text,"SHA-256")
    verifying = PublicKeyCryptosystemVerification(public_key)
    if verifying.verify(hash_receiver,signed_message):
        print("The message is original")
    else:
        print("The message have been tampered with")
