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

def encrypt_image_aes(input_image_path, output_image_path, key):
    image = Image.open(input_image_path)
    image_data = image.tobytes()
    cipher = AES.new(key, AES.MODE_EAX)    
    ciphertext, tag = cipher.encrypt_and_digest(pad(image_data, AES.block_size))

    with open(output_image_path, 'wb') as f:
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

def decrypt_image_aes(encrypted_image_path, output_image_path, key):
    with open(encrypted_image_path, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    image = Image.open(encrypted_image_path)
    image = Image.frombytes("RGB", (image.size[0], image.size[1]), decrypted_data)
    image.save(output_image_path)