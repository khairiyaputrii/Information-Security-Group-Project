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

# def encrypt_image_file(image_file_path, key, iv):
#     image = Image.open(image_file_path)
#     image = image.convert("RGB")
#     encrypted_data = encrypt_message_aes(key, image.tobytes(), iv)
#     with open(image_file_path, "wb") as output:
#         output.write(encrypted_data)

def encrypt_image_aes(file_name, key):
    # Open the image file in binary mode
    with open(file_name, 'rb') as f:
        data = f.read()

    # Create a new AES cipher object
    cipher = AES.new(key, AES.MODE_EAX)
    # Encrypt the data
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Write the encrypted data to a new file
    with open(file_name + ".enc", 'wb') as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]

def decrypt_image_aes(file_name, key):
    # Open the encrypted file in binary mode
    with open(file_name, 'rb') as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

    # Create a new AES cipher object
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    # Decrypt the data
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # Write the decrypted data to a new file
    with open(file_name.replace(".enc", ""), 'wb') as f:
        f.write(data)

# def encrypt_image_aes(input_image_path, output_image_path, key):
#     image = Image.open(input_image_path)
#     image_data = image.tobytes()
#     cipher = AES.new(key, AES.MODE_EAX)    
#     ciphertext, tag = cipher.encrypt_and_digest(pad(image_data, AES.block_size))

#     with open(output_image_path, 'wb') as f:
#         f.write(cipher.nonce)
#         f.write(tag)
#         f.write(ciphertext)

# def decrypt_image_aes(encrypted_image_path, output_image_path, key):
#     with open(encrypted_image_path, 'rb') as f:
#         nonce = f.read(16)
#         tag = f.read(16)
#         ciphertext = f.read()

#     cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
#     decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
#     image = Image.open(encrypted_image_path)
#     image = Image.frombytes("RGB", (image.size[0], image.size[1]), decrypted_data)
#     image.save(output_image_path)
