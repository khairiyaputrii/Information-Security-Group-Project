from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Cryptodome.Cipher import AES, DES, ARC4
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from PyPDF2 import PdfWriter, PdfReader

import moviepy.editor as mp
import mysql.connector
import os

def encrypt_pdf_file(pdf_file_path, key):
    output_pdf = PdfWriter()
    input_pdf = PdfReader(open(pdf_file_path, "rb"))
    for page_num in range(len(input_pdf.pages)):
        page = input_pdf.pages[page_num]
        output_pdf.add_page(page)
    with open(pdf_file_path, "wb") as output:
        output_pdf.encrypt(key)
        output_pdf.write(output)