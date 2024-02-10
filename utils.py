from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes
import binascii
   

def message_handler(message, key: bytes):
    # Validate the key
    assert len(key) == 32, "Key must be 32 bytes long"
    
    # Create a cipher object
    cipher_obj = Cipher(algorithms.AES256(key), modes.CBC(b"myinitialvector6"), backend=default_backend())

    # Check if the message is encrypted or decrypted
    # If the message is encrypted, decrypt it
    if isinstance(message, bytes):
        message = decrypt(cipher_obj, message)
    # If the message is decrypted, encrypt it
    else:
        # Convert the message to bytes
        message = bytes(message, encoding="utf-8")
        message = encrypt(cipher_obj, message)
    return message

def encrypt(cipher_obj, message):
    # Pad the message
    padder = PKCS7(256).padder() # 256 is the block size of AES
    padded_message = padder.update(message) + padder.finalize()
    # Hash the message
    hashed_message = hash(padded_message)
    # Encrypt the message and hash
    encryptor = cipher_obj.encryptor()
    cipher_text = encryptor.update(padded_message) + encryptor.update(hashed_message) + encryptor.finalize()
    return cipher_text

def decrypt(cipher_obj, message):
    decryptor = cipher_obj.decryptor()
    decrypted_message_hash = decryptor.update(message) + decryptor.finalize()
    # Split the decrypted message and hash
    decrypted_padded_message = decrypted_message_hash[:-32]
    decrypted_hash = decrypted_message_hash[-32:]
    # Unpad the decrypted message
    unpadder = PKCS7(256).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    # Hash the decrypted message
    hashed_message = hash(decrypted_padded_message)
    # Compare the two hashes
    assert decrypted_hash == hashed_message, "Hashes do not match"
    return decrypted_message.decode()


def paddMessage(message: str):
    if not isinstance(message, bytes):
        message = bytes(message, encoding="utf-8")
    padder = PKCS7(256).padder() # 256 is the block size of AES
    return padder.update(message) + padder.finalize()

# Hashes padded data ONLY
def hash(data: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def hashPassword(password):
    password = paddMessage(password)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    return binascii.b2a_base64(digest.finalize()).decode()


def verify_password(password, hashed_password):
    # Verify the password by comparing the hash
    return hashed_password == hashPassword(password)
