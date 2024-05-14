from BlockCipher import BlockCipherEncryption, BlockCipherDecyption
from Hashing import Hashing
import pickle

def send_message(client_sock, derived_key, blockcipher_t, hashing_t):    
    while True:
        message = input()
        blockCipherEncrypt = BlockCipherEncryption(blockcipher_t, derived_key)
        nonce = blockCipherEncrypt.get_nonce()

        cipher_msg = blockCipherEncrypt.encrypt(message.encode())
        hashed_msg = Hashing.hash(message.encode(), hashing_t)
        msg_signature = blockCipherEncrypt.encrypt(hashed_msg.digest())

        client_sock.send(pickle.dumps([cipher_msg, nonce, msg_signature]))
        if message == 'q':
            break


def recv_message(client_sock, derived_key, blockcipher_t, hashing_t):
    while True:
        pickle_obj = client_sock.recv(4096)
        cipher_msg, nonce, msg_signature = pickle.loads(pickle_obj)

        blockCipherDecrypt = BlockCipherDecyption(blockcipher_t, derived_key, nonce)
        message = blockCipherDecrypt.decrypt(cipher_msg).decode()
        my_hashed_msg = Hashing.hash(message.encode(), hashing_t).digest()
        hashed_msg = blockCipherDecrypt.decrypt(msg_signature)

        if(my_hashed_msg == hashed_msg):
            print(message)
        else:
            print('TAMPERED MESSAGE!!!')
        
        if message == 'q':
            break