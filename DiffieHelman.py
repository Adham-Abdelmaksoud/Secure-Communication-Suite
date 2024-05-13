from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class DiffieHelman:
    def __init__(self, my_priv_key, other_pub_key) -> None:
        self.priv_key = my_priv_key
        self.pub_key = other_pub_key

    def calculate_shared_key(self):
        shared_key = self.priv_key.exchange(self.pub_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key