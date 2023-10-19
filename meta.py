from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PyPDF2 import PdfWriter, PdfReader
from PIL import Image

import moviepy.editor as mp
import mysql.connector
import os

# ! ENCRYPT DECRYPT

def encrypt_message_aes(key, plaintext, iv):
    # Generate a random initialization vector (IV)
    # iv = get_random_bytes(16)
    # Konversi teks menjadi bytes
    plaintext = plaintext.encode('utf-8')
    # Pad the plaintext to be a multiple of 16 bytes (AES block size)
    padded_plaintext = plaintext + (16 - len(plaintext) % 16) * b"\0"
    # Create an AES cipher object in CBC mode with the given key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Encrypt the padded plaintext
    ciphertext = iv + cipher.encrypt(padded_plaintext)
    
    return ciphertext

def decrypt_message_aes(key, ciphertext, iv):
    # Extract the IV from the ciphertext
    # iv = ciphertext[:16]
    # Create an AES cipher object in CBC mode with the given key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the ciphertext
    # plaintext = cipher.decrypt(ciphertext[16:])
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    # Remove the padding to get the original plaintext
    # plaintext = plaintext.rstrip(b"\0")
    
    return plaintext.decode('utf-8')

def encrypt_message_des(key, plaintext, iv):
    # Generate a random initialization vector (IV)
    # iv = get_random_bytes(8)
    # Konversi teks menjadi bytes
    plaintext = plaintext.encode('utf-8')
    # Pad the plaintext to be a multiple of 8 bytes (DES block size)
    padded_plaintext = pad(plaintext, 8)
    # Create a DES cipher object in CBC mode with the given key and IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    # Encrypt the padded plaintext
    ciphertext = iv + cipher.encrypt(padded_plaintext)

    return ciphertext

def decrypt_message_des(key, ciphertext, iv):
    # Extract the IV from the ciphertext
    # iv = ciphertext[:8]
    # Create a DES cipher object in CBC mode with the given key and IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    # Decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext[8:])
    # Remove the padding to get the original plaintext
    plaintext = unpad(plaintext, 8)

    return plaintext

def encrypt_message_arc4(key, plaintext):
    # Membuat objek ARC4 dengan kunci yang diberikan
    cipher = ARC4.new(key)
    # Konversi teks menjadi bytes
    plaintext = plaintext.encode('utf-8')
    # Enkripsi pesan
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext

def decrypt_message_arc4(key, ciphertext):
    # Membuat objek ARC4 dengan kunci yang diberikan
    cipher = ARC4.new(key)
    # Mendekripsi pesan
    plaintext = cipher.decrypt(ciphertext)

    return plaintext
