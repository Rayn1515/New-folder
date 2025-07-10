from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os

BLOCK_SIZE = 16 

def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def encrypt_data(data: bytes, password: str) -> bytes:
    key = derive_key(password)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data))
    return iv + encrypted  

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    key = derive_key(password)
    iv = encrypted_data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_data[BLOCK_SIZE:])
    return unpad(decrypted_padded)
