from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Cryptodome.Cipher import AES, DES, ARC4
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from PIL import Image

import moviepy.editor as mp
import mysql.connector
import os

# ! ENCRYPT DECRYPT


def encrypt_message_aes(key, plaintext, iv=None):
    if iv is None:
        iv = get_random_bytes(16)
    plaintext_bytes = plaintext.encode('utf-8')
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_message_aes(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext[16:])
    plaintext = unpad(decrypted_data, AES.block_size)
    return plaintext.decode('utf-8')

def encrypt_message_des(key, plaintext, iv=None):
    if iv is None:
        iv = get_random_bytes(8)
    plaintext_bytes = plaintext.encode('utf-8')
    padded_plaintext = pad(plaintext_bytes, 8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_message_des(key, ciphertext):
    iv = ciphertext[:8]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext[8:])
    plaintext = unpad(decrypted_data, 8)
    return plaintext.decode('utf-8')

def encrypt_message_arc4(key, plaintext):
    cipher = ARC4.new(key)
    plaintext = plaintext.encode('utf-8')
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt_message_arc4(key, ciphertext):
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext