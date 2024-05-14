from BlockCipher import BlockCipherEncryption, BlockCipherDecyption
from Hashing import Hashing
import pickle

def encrypt_message(message: bytes, derived_key, blockcipher_t, hashing_t):
    blockCipherEncrypt = BlockCipherEncryption(blockcipher_t, derived_key)
    nonce = blockCipherEncrypt.get_nonce()

    cipher_msg = blockCipherEncrypt.encrypt(message)
    hashed_msg = Hashing.hash(message, hashing_t)
    msg_signature = blockCipherEncrypt.encrypt(hashed_msg.digest())

    return cipher_msg, msg_signature, nonce


def decrypt_message(cipher_msg: bytes, msg_signature, nonce, derived_key, blockcipher_t, hashing_t):
    blockCipherDecrypt = BlockCipherDecyption(blockcipher_t, derived_key, nonce)
    message = blockCipherDecrypt.decrypt(cipher_msg)
    my_hashed_msg = Hashing.hash(message, hashing_t).digest()
    hashed_msg = blockCipherDecrypt.decrypt(msg_signature)

    return message, my_hashed_msg, hashed_msg


def send_message_thread(client_sock, derived_key, blockcipher_t, hashing_t):    
    while True:
        try:
            message = input()
            cipher_msg, msg_signature, nonce = encrypt_message(message.encode(), derived_key, blockcipher_t, hashing_t)

            client_sock.send(pickle.dumps([cipher_msg, nonce, msg_signature]))
            if message == 'q':
                break
        except:
            break


def recv_message_thread(client_sock, derived_key, blockcipher_t, hashing_t):
    while True:
        try:
            pickle_obj = client_sock.recv(4096)
            cipher_msg, nonce, msg_signature = pickle.loads(pickle_obj)

            message, my_hashed_msg, hashed_msg = decrypt_message(cipher_msg, msg_signature, nonce, derived_key, blockcipher_t, hashing_t)
            message = message.decode()

            if(my_hashed_msg == hashed_msg):
                print(message)
            else:
                print('TAMPERED MESSAGE!!!')
            
            if message == 'q':
                break
        except:
            break