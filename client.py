import socket
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate client's RSA keys
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()
client_pem_public = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Encrypt and decrypt functions
def encrypt_message(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_message = message + b'\0' * (16 - len(message) % 16)
    return encryptor.update(padded_message) + encryptor.finalize()

def decrypt_message(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return padded_data.rstrip(b'\0')

def client():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(('localhost', 12345))
            print("Connected to server")
            
            # Exchange public keys
            server_pem_public = s.recv(1024)
            if not server_pem_public:
                print("Failed to receive server public key")
                s.close()
                continue
            server_public_key = serialization.load_pem_public_key(server_pem_public)
            s.send(client_pem_public)
            print("Sent client public key")

            # Send message to server
            message = input("Client: Enter message to send: ").encode()
            aes_key = os.urandom(32)
            iv = os.urandom(16)
            encrypted_aes_key = server_public_key.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            encrypted_message = encrypt_message(message, aes_key, iv)
            s.send(encrypted_aes_key)
            s.send(iv)
            s.send(encrypted_message)
            print(f"Client sent: {message.decode()}")

            # Receive server's response
            encrypted_server_aes_key = s.recv(256)
            server_iv = s.recv(16)
            encrypted_server_msg = s.recv(1024)
            if not encrypted_server_msg:
                print("No response from server")
                s.close()
                continue
            server_aes_key = client_private_key.decrypt(
                encrypted_server_aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            decrypted_server_msg = decrypt_message(encrypted_server_msg, server_aes_key, server_iv)
            print(f"Server: {decrypted_server_msg.decode()}")

            s.close()
        except Exception as e:
            print(f"Client error: {e}")
            s.close()
            continue

if __name__ == "__main__":
    client()