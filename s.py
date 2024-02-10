# server.py
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from utils import message_handler, verify_password, hashPassword
import json
import signal
import sys
import requests


# VIRUSTOTAL_API_KEY = "b272d6adb9421d74186bea5e14eba29ec8e745a2a6cdf6e8572b135bdda7ea01"

def scan_url_with_virustotal(urlß):
      url = "https://www.virustotal.com/api/v3/urls"

      payload = { "url": "https://www.youtube.com/watch?v=sqYrofj52kA" }
      headers = {
          "accept": "application/json",
          "x-apikey": "b272d6adb9421d74186bea5e14eba29ec8e745a2a6cdf6e8572b135bdda7ea01",
          "content-type": "application/x-www-form-urlencoded"
      }

      response = requests.post(url, data=payload, headers=headers)
      if response.status_code == 200:
          print("Secure link", response.status_code)
      else:
          print("Malicious link", response.status_code)    



def load_user_db():
    try:
        with open("DB.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_user_db(user_db):
    with open("DB.json", "w") as file:
        json.dump(user_db, file)

def server():
    key_pair = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key = key_pair.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_socket.bind(('localhost', 8000))
        server_socket.listen(5)
        print('Server started, waiting for connections on port 8000...')
    except socket.error as e:
        print('Error starting the server:', e)
        server_socket.close()
        return

    while True:
        try:
            # Wait for a connection, and then accept it
            connection, client_address = server_socket.accept()
            print('>>>> Client connected:', client_address)

            connection.sendall(public_key)
            print('>>>> Public Key sent to the client')

            encrypted_key = connection.recv(2048)
            print('>>>> Encrypted key received from the client')

            decrypted_key = key_pair.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            shared_key = decrypted_key

            isAuthenticated = False
            encrypted_choice = connection.recv(2048)
            encrypted_username = connection.recv(2048)
            encrypted_password = connection.recv(2048)
            print('Encrypted choice received from the client') 
            print('Encrypted username received from the client') 
            print('Encrypted password received from the client')
            
            client_choice = message_handler(encrypted_choice, shared_key)
            print('choice:', client_choice)
            client_username = message_handler(encrypted_username, shared_key)
            # print('username:', client_username)
            client_password = message_handler(encrypted_password, shared_key)
            # print('password:', client_password)


            user_db = load_user_db()
            if client_choice == 'r':
               if client_username not in user_db:
                   hashed_password = hashPassword(client_password)  
                   user_db[client_username] = {'password': hashed_password}
                   confo = 'Registered successfully.'
                   en_confo = message_handler(confo, shared_key)
                   connection.sendall(en_confo)
                   save_user_db(user_db)
                   isAuthenticated = True
               else:
                   confo = 'User already exist.'
                   en_confo = message_handler(confo, shared_key)
                   connection.sendall(en_confo)
                   isAuthenticated = False

            else:
                if verify_password(client_password, user_db[client_username]['password']):
                    confo = 'Logged in successful.'
                    enc_confo = message_handler(confo, shared_key)
                    connection.sendall(enc_confo)
                    isAuthenticated = True
                else:
                    confo = 'Invalid username or password.'
                    enc_confo = message_handler(confo, shared_key)
                    connection.sendall(enc_confo)

            if isAuthenticated:
                while True:
                    data = connection.recv(1024)
                    if not data:
                        break
                    
                    client_message = message_handler(data, shared_key)
                    print('Received from' ,client_username, ':' , client_message)

                    if client_message.startswith('http'):
                       # If the received message is a URL, perform link scanning
                       scan_result = scan_url_with_virustotal(client_message)
                       print(scan_result)


                    if client_message == 'exit':
                        print('>>>> Client closed the connection')
                        connection.close()
                        break

                    message = input('Enter a message to send to the client: ')
                    send_msg = message_handler(message, shared_key)
                    connection.sendall(send_msg)
                    

        except socket.error as e:
            print('>>>> Error receiving data:', e)

        except KeyboardInterrupt:
            connection.close()
            sys.exit()

if __name__ == "__main__":
    server()
