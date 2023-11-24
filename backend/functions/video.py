from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Cryptodome.Cipher import AES, DES, ARC4
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from PyPDF2 import PdfWriter, PdfReader
from PIL import Image

import moviepy.editor as mp
import mysql.connector
import os

def encrypt_video_file(video_file_path, key):
    with open(video_file_path, "rb") as video_file:
        video_data = video_file.read()
        encrypted_data = encrypt_message_aes(video_data, key)
        with open(video_file_path, "wb") as output:
            output.write(encrypted_data)