from socket import *
import pickle
from OpenSSL import crypto

from BlockCipher import BlockCipherType
from PublicKeyCryptosystemRSA import PublicKeyCryptosystemVerification
from Hashing import Hashing, HashingType
from KeyManagement import KeyManager

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, ParameterFormat, load_pem_public_key, load_pem_parameters


SERVER_IP = '127.0.0.1'
SERVER_PORT = 10000

def start_connection():
    client_sock = socket(AF_INET, SOCK_STREAM)
    client_sock.connect((SERVER_IP, SERVER_PORT))
    return client_sock

def close_connection(client_sock):
    client_sock.close()

def send_security_params(client_sock, blockcipher_t=BlockCipherType.AES, hashing_t=HashingType.SHA256):
    client_sock.send(pickle.dumps([blockcipher_t, hashing_t]))

def recv_cert_ecdhKey_sign(client_sock):
    pickle_obj = client_sock.recv(4096)
    cert_bytes, cert_sign, dh_params_bytes, dh_server_pub_key_bytes = pickle.loads(pickle_obj)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_bytes)
    cert_server_pub_key = cert.get_pubkey()

    dh_params = load_pem_parameters(dh_params_bytes)
    dh_server_pub_key = load_pem_public_key(dh_server_pub_key_bytes)
    dh_client_priv_key = dh_params.generate_private_key()
    dh_client_pub_key = dh_client_priv_key.public_key()
    shared_key = dh_client_priv_key.exchange(dh_server_pub_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    print(derived_key)
        
    manager = KeyManager(None, None)
    cert_server_pub_key = manager.bytes_2_RSAKey(manager.certKey_2_bytes(cert_server_pub_key))

    verifier = PublicKeyCryptosystemVerification(cert_server_pub_key)
    print(verifier.verify(Hashing.hash(cert_bytes, HashingType.SHA256), cert_sign))
    return dh_client_pub_key


def send_dh_client_pub_key(client_sock, dh_client_pub_key):
    dh_client_pub_key_bytes = dh_client_pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    client_sock.send(pickle.dumps(dh_client_pub_key_bytes))


if __name__ == '__main__':
    client_sock = start_connection()

    dh_client_pub_key = recv_cert_ecdhKey_sign(client_sock)
    send_dh_client_pub_key(client_sock, dh_client_pub_key)

    close_connection(client_sock)