from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Cryptodome.Cipher import AES, DES, ARC4
from Cryptodome.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

import mysql.connector
import os

# ! ENCRYPT DECRYPT

def encrypt_message_aes(key, text):
    text_bytes = text.encode('utf-8')
    key_bytes = key
    iv = b'\x00' * 16
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text_bytes) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_text = b64encode(ciphertext).decode('utf-8')
    
    return encrypted_text

def decrypt_message_aes(key, encrypted_text):
    encrypted_bytes = b64decode(encrypted_text)
    key_bytes = key
    iv = b'\x00' * 16 
    
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    decrypted_text = unpadded_data.decode('utf-8')
    
    return decrypted_text

def encrypt_message_des(key, plaintext):
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key
    iv = b'\x00' * 8
    
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, 8))
    return b64encode(ciphertext, altchars=None).decode('utf-8')

def decrypt_message_des(key, encrypted_text):
    encrypted_bytes = b64decode(encrypted_text, altchars=None, validate=True)
    key_bytes = key
    iv = b'\x00' * 8
    
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_bytes)
    
    plaintext = unpad(decrypted_data, 8).decode('utf-8')
    
    return plaintext

def encrypt_message_arc4(key, plaintext):
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key
    
    cipher = ARC4.new(key_bytes)
    ciphertext = cipher.encrypt(plaintext_bytes)
    
    return b64encode(ciphertext, altchars=None).decode('utf-8')

def decrypt_message_arc4(key, encrypted_text):
    encrypted_bytes = b64decode(encrypted_text, altchars=None, validate=True)
    key_bytes = key
    
    cipher = ARC4.new(key_bytes)
    decrypted_data = cipher.decrypt(encrypted_bytes)
    
    plaintext = decrypted_data.decode('utf-8')
    
    return plaintext

