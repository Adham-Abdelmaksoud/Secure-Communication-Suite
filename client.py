from socket import *
import pickle
import threading
import sys
import os

from BlockCipher import BlockCipherType
from PublicKeyCryptosystemRSA import PublicKeyCryptosystemVerification, PublicKeyCryptosystemSigning
from Hashing import Hashing, HashingType
from KeyManagement import KeyManager
from DiffieHelman import DiffieHelman
from CertificateVerification import CertificateVerifier
from MessageThreads import *


SERVER_IP = '127.0.0.1'
SERVER_PORT = 10000

def start_connection():
    client_sock = socket(AF_INET, SOCK_STREAM)
    client_sock.connect((SERVER_IP, SERVER_PORT))
    return client_sock

def close_connection(client_sock):
    client_sock.close()


def send_security_params(client_sock):    
    print('(1) AES')
    print('(2) DES')
    blockcipher_t = int(input('Enter the number corresponding to the desired block cipher: '))
    if blockcipher_t == 1:
        blockcipher_t = BlockCipherType.AES
    elif blockcipher_t == 2:
        blockcipher_t = BlockCipherType.DES
    print('(1) SHA256')
    print('(2) MD5')
    hashing_t = int(input('Enter the number corresponding to the desired hash: '))
    if hashing_t == 1:
        hashing_t = HashingType.SHA256
    elif hashing_t == 2:
        hashing_t = HashingType.MD5
    client_sock.send(pickle.dumps([blockcipher_t, hashing_t]))
    print(f"\nInitiated handshake with paramters: {blockcipher_t.value} block encryption, and {hashing_t.value} hashing algorithm")
    return blockcipher_t, hashing_t

def recv_cert_dhPubKey_sign(client_sock, blockcipher_t, hashing_t):
    # receive message
    pickle_obj = client_sock.recv(4096)
    cert_bytes, dh_params_bytes, dh_server_pub_key_bytes, msg_sign = pickle.loads(pickle_obj)

    # convert message bytes to objects
    manager = KeyManager()
    server_cert = manager.bytes_2_cert(cert_bytes)
    cert_server_pub_key = server_cert.get_pubkey()
    RSA_server_pub_key = manager.bytes_2_RSAKey(manager.certKey_2_bytes(cert_server_pub_key))
    dh_params = manager.bytes_2_dhParams(dh_params_bytes)
    dh_server_pub_key = manager.bytes_2_dhPubKey(dh_server_pub_key_bytes)

    # calculate Diffie-Helman shared key
    dh_client_priv_key, dh_client_pub_key = manager.generate_DH_keys(dh_params)
    dh = DiffieHelman(dh_client_priv_key, dh_server_pub_key)
    derived_key = dh.calculate_shared_key(blockcipher_t)

    print(f"Derived shared {blockcipher_t.value} key using Diffie Helman key exhange")

    # verify server certificate
    cert_verifier = CertificateVerifier()
    if cert_verifier.verify_certificate(server_cert):
        print('Server certificate verified using CA public key')
    else:
        print('Invalid server certificate')
    
    # verify server signature
    sign_verifier = PublicKeyCryptosystemVerification(RSA_server_pub_key)
    all_bytes = cert_bytes + dh_params_bytes + dh_server_pub_key_bytes
    if sign_verifier.verify(Hashing.hash(all_bytes, hashing_t), msg_sign):
        print('Server signature verified using server public key')
    else:
        print('Invalid server signature')

    print()

    return dh_client_pub_key, derived_key


def send_username_password(client_sock, blockcipher_t, hashing_t):
    print('(1) Login')
    print('(2) Signup')
    login_signup = int(input('Enter the number corresponding to the desired action: '))
    print()
    username = input('Enter your username: ')
    password = input('Enter your password: ')

    all_data = pickle.dumps([username, password, login_signup])
    cipher_msg, msg_signature, nonce = encrypt_message(all_data, derived_key, blockcipher_t, hashing_t)

    client_sock.send(pickle.dumps([cipher_msg, msg_signature, nonce]))


def send_dhPubKey(client_sock, dh_client_pub_key):
    # convert objects to bytes
    manager = KeyManager()
    dh_client_pub_key_bytes = manager.dhPubKey_2_bytes(dh_client_pub_key)

    # send message
    client_sock.send(pickle.dumps(dh_client_pub_key_bytes))


def send_authentication_method(client_sock):
    print('(1) Password-based Authentication')
    print('(2) Certificate-based Authentication')
    auth_method = int(input('Enter the number corresponding to the desired authentication: '))
    client_sock.send(f'{auth_method}'.encode())
    return auth_method

def read_cert_bytes(cert_dir='./Client', cert_name = 'certificate.crt'):
    with open(os.path.join(cert_dir, cert_name), 'rb') as f:
        return f.read()
    
def read_private_key(priv_key_dir='./Client', priv_key_name = 'private.key'):
    manager = KeyManager()
    return manager.read_RSA_key(priv_key_name, priv_key_dir)

def send_cert(client_sock, derived_key, blockcipher_t, hashing_t):
    cert_bytes = read_cert_bytes()
    my_priv_key = read_private_key()

    hashed_cert = Hashing.hash(cert_bytes, hashing_t)

    # form message signature
    signer = PublicKeyCryptosystemSigning(my_priv_key)
    msg_sign = signer.sign(hashed_cert)

    print("Sending client certificate")

    client_sock.send(pickle.dumps([cert_bytes, msg_sign]))




if __name__ == '__main__':
    client_sock = start_connection()

    # Key Exchange
    blockcipher_t, hashing_t = send_security_params(client_sock)
    dh_client_pub_key, derived_key = recv_cert_dhPubKey_sign(client_sock, blockcipher_t, hashing_t)
    send_dhPubKey(client_sock, dh_client_pub_key)

    # Authentication
    auth_method = send_authentication_method(client_sock)
    if auth_method == 1:
        send_username_password(client_sock, blockcipher_t, hashing_t)
    elif auth_method == 2:
        send_cert(client_sock, derived_key, blockcipher_t, hashing_t)

    # Authentication Status
    status = client_sock.recv(4096)
    status = eval(status.decode())
    if status:
        print("Authentication successful\n")
        print('Handshake completed')
        print(f'All further communication will be encrypted using {blockcipher_t.value}, and hashed using {hashing_t.value} for checking data integrity')
        print()
    else:
        print("Authentication failed\n")
        print("Hanshake aborted")
        print("Terminating connection")
        close_connection(client_sock)
        sys.exit(0)
    
    # Send & Receive Threads
    send_thread = threading.Thread(target=send_message_thread, args=(client_sock, derived_key, blockcipher_t, hashing_t,))
    recv_thread = threading.Thread(target=recv_message_thread, args=(client_sock, derived_key, blockcipher_t, hashing_t,"Server:"))
    send_thread.start()
    recv_thread.start()

    send_thread.join()
    recv_thread.join()

    close_connection(client_sock)