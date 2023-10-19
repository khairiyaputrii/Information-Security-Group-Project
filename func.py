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

# def encrypt_message(message, key, algorithm):
#     cipher = None
#     if algorithm == 'AES':
#         cipher = AES.new(key, AES.MODE_CBC)
#     elif algorithm == 'DES':
#         cipher = DES.new(key, DES.MODE_ECB)
#     elif algorithm == 'ARC4':
#         cipher = ARC4.new(key)

#     if cipher:
#         plaintext = message.encode('utf-8')
#         if algorithm == 'AES':
#             ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
#         else:
#             ciphertext = cipher.encrypt(pad(plaintext, cipher.block_size))

#         return ciphertext
#     else:
#         raise ValueError("Unsupported encryption algorithm")

# def decrypt_message(ciphertext, key, algorithm):
#     if not isinstance(ciphertext, bytes):
#         # ? If ciphertext is a string, convert it to bytes
#         ciphertext = ciphertext.encode('utf-8')

#     cipher = None
#     if algorithm == 'AES':
#         cipher = AES.new(key, AES.MODE_CBC)
#     elif algorithm == 'DES':
#         cipher = DES.new(key, DES.MODE_ECB)
#     elif algorithm == 'ARC4':
#         cipher = ARC4.new(key)

#     if cipher:
#         decrypted = unpad(cipher.decrypt(ciphertext), cipher.block_size)
#         return decrypted.decode('utf-8')
#     else:
#         raise ValueError("Unsupported encryption algorithm")

# ? Function to check if the file type is allowed
# def allowed_file(filename, file_type):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ? Function to save and encrypt uploaded files
# def save_and_encrypt_file(file_key, file_type, encryption_method):
#     file = request.files[file_key]
#     if file and allowed_file(file.filename, file_type):
#         file_folder = app.config['UPLOAD_FOLDER']
#         filename = secure_filename(file.filename)
#         file_path = os.path.join(file_folder, filename)
#         file.save(file_path)

#         if encryption_method == 'AES':
#             key = aes_key
#         elif encryption_method == 'DES':
#             key = des_key
#         elif encryption_method == 'ARC4':
#             key = arc4_key

#         if file_type == 'pdf':
#             encrypt_pdf_file(file_path, key)
#         elif file_type == 'img':
#             encrypt_image_file(file_path, key)
#         elif file_type == 'video':
#             encrypt_video_file(file_path, key)

#         return file_path

# def encrypt_pdf_file(pdf_file_path, key):
#     output_pdf = PdfWriter()
#     input_pdf = PdfReader(open(pdf_file_path, "rb"))
#     for page_num in range(len(input_pdf.pages)):
#         page = input_pdf.pages[page_num]
#         output_pdf.add_page(page)
#     with open(pdf_file_path, "wb") as output:
#         output_pdf.encrypt(key)
#         output_pdf.write(output)

# def encrypt_image_file(image_file_path, key):
#     image = Image.open(image_file_path)
#     image = image.convert("RGB")
#     encrypted_data = encrypt_message_aes(image.tobytes(), key)
#     with open(image_file_path, "wb") as output:
#         output.write(encrypted_data)

# def encrypt_video_file(video_file_path, key):
#     with open(video_file_path, "rb") as video_file:
#         video_data = video_file.read()
#         encrypted_data = encrypt_message_aes(video_data, key)
#         with open(video_file_path, "wb") as output:
#             output.write(encrypted_data)