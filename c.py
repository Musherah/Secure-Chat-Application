# client.py
import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import sys
import os
from utils import message_handler
from utils import message_handler
from s import scan_url_with_virustotal


# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to server
client_socket.connect(('localhost', 8000))

# Recieve the PUserver from the server as bytes
PU_server = client_socket.recv(2048)
# Convert it to a public key object
PU_server = serialization.load_pem_public_key(PU_server, backend=default_backend())

# Generate an AES-256 key
key = os.urandom(32)

# Encrypt the key using PUserver
encrypted_key = PU_server.encrypt(
    key, # The message you want to encrypt
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Send the encrypted key to the server
client_socket.sendall(encrypted_key)
print('>>>> Encrypted key sent to the server')
shared_key = key

choice = input('Enter (r) for register or (l) for login: ')
encrypted_choice = message_handler(choice, shared_key)
client_socket.sendall(encrypted_choice)

username = input('Username: ')
password = input('Password: ')
encrypted_username = message_handler(username, shared_key)
encrypted_password = message_handler(password, shared_key)

client_socket.sendall(encrypted_username)
print('>>>> Encrypted username sent to the server')
client_socket.sendall(encrypted_password)
print('>>>> Encrypted password sent to the server')
enc_confo = client_socket.recv(2048)
confo = message_handler(enc_confo, shared_key)
print('>>>> Received Conformation:', confo)
isAuthenticated = confo not in ['User already exist.', 'Invalid username or password.']

if isAuthenticated:
    while True:
        # Send data to server
        message = input('Enter a message to send to the server:')
        send_msg = message_handler(message, shared_key)
        client_socket.sendall(send_msg)

        if message == 'exit':
            client_socket.close()

        if message.startswith('http'):
             # If the received message is a URL, perform link scanning
            scan_result= scan_url_with_virustotal(message)
            print(scan_result)


        # Receive response from server, 1024 is the buffer size
        encrypted_server_message = client_socket.recv(1024)
        server_message = message_handler(encrypted_server_message, shared_key)
        print('Received from server:', server_message)

        