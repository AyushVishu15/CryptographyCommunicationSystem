import socket
import os
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate server's RSA keys
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()
server_pem_public = server_public_key.public_bytes(
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

# Socket server
def socket_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('localhost', 12345))
    s.listen(1)
    print("Server listening on localhost:12345...")

    while True:
        conn, addr = s.accept()
        print(f"Connected by {addr}")
        
        # Exchange public keys
        conn.send(server_pem_public)
        client_pem_public = conn.recv(1024)
        if not client_pem_public:
            print("Failed to receive client public key")
            conn.close()
            continue
        client_public_key = serialization.load_pem_public_key(client_pem_public)
        print("Received client public key")

        try:
            # Receive client's message
            encrypted_aes_key = conn.recv(256)
            iv = conn.recv(16)
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                print("No message received from client")
                conn.close()
                continue

            aes_key = server_private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            message = decrypt_message(encrypted_message, aes_key, iv)
            print(f"Client: {message.decode()}")

            # Server sends a response
            server_msg = input("Server: Enter message to send: ").encode()
            server_aes_key = os.urandom(32)
            server_iv = os.urandom(16)
            encrypted_server_aes_key = client_public_key.encrypt(
                server_aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            encrypted_server_msg = encrypt_message(server_msg, server_aes_key, server_iv)
            conn.send(encrypted_server_aes_key)
            conn.send(server_iv)
            conn.send(encrypted_server_msg)
            print(f"Server sent: {server_msg.decode()}")

        except Exception as e:
            print(f"Error: {e}")
            conn.close()
            continue

        conn.close()

if __name__ == "__main__":
    server_thread = threading.Thread(target=socket_server)
    server_thread.daemon = True
    server_thread.start()
    server_thread.join()  # Keep the main thread running