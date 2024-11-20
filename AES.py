from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os 

def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_CTR) # new object
    ciphertext = cipher.encrypt(plaintext) # encrypt plaintext 
    return ciphertext, cipher.nonce # return cipher and nonce

def decrypt_message(key, ciphertext, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce) # new aes object
    decrypted_message = cipher.decrypt(ciphertext) # decrypt
    return decrypted_message

# Generate a random 256-bit key
key = get_random_bytes(32)

# Message to encrypt
plaintext = b"This is a secret message!"

# Encrypt the message
ciphertext, nonce = encrypt_message(key, plaintext)
print("Encrypted message:", ciphertext.hex())

# Decrypt the message
decrypted_message = decrypt_message(key, ciphertext, nonce)
print("Decrypted message:", decrypted_message)
