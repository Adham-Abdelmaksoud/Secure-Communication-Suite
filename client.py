from socket import *
import pickle
from OpenSSL import crypto

from BlockCipher import BlockCipherType
from PublicKeyCryptosystemRSA import PublicKeyCryptosystemVerification
from Hashing import Hashing, HashingType
from KeyManagement import KeyManager
from DiffieHelman import DiffieHelman


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
    cert_bytes, dh_params_bytes, dh_server_pub_key_bytes, msg_sign = pickle.loads(pickle_obj)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_bytes)
    cert_server_pub_key = cert.get_pubkey()

    manager = KeyManager()
    dh_params = manager.bytes_2_dhParams(dh_params_bytes)
    dh_server_pub_key = manager.bytes_2_dhPubKey(dh_server_pub_key_bytes)
    dh_client_priv_key, dh_client_pub_key = manager.generate_DH_keys(dh_params)

    dh = DiffieHelman(dh_client_priv_key, dh_server_pub_key)
    derived_key = dh.calculate_shared_key()
    print(derived_key)
        
    manager = KeyManager()
    cert_server_pub_key = manager.bytes_2_RSAKey(manager.certKey_2_bytes(cert_server_pub_key))

    verifier = PublicKeyCryptosystemVerification(cert_server_pub_key)
    all_bytes = cert_bytes + dh_params_bytes + dh_server_pub_key_bytes
    print(verifier.verify(Hashing.hash(all_bytes, HashingType.SHA256), msg_sign))
    return dh_client_pub_key


def send_dh_client_pub_key(client_sock, dh_client_pub_key):
    manager = KeyManager()
    dh_client_pub_key_bytes = manager.dhPubKey_2_bytes(dh_client_pub_key)
    client_sock.send(pickle.dumps(dh_client_pub_key_bytes))


if __name__ == '__main__':
    client_sock = start_connection()

    send_security_params(client_sock, BlockCipherType.AES, HashingType.SHA256)
    dh_client_pub_key = recv_cert_ecdhKey_sign(client_sock)
    send_dh_client_pub_key(client_sock, dh_client_pub_key)

    close_connection(client_sock)