from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Cryptodome.Cipher import AES, DES, ARC4
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from PyPDF2 import PdfWriter, PdfReader
from PIL import Image
import moviepy.editor as mp
import os
import io

from backend.database.db import create_connection
from backend.routes.authentication import authentication as routes_authentication
from backend.routes.encryption import encryption as routes_encryption
from backend.routes.decryption import decryption as routes_decryption

app = Flask(__name__)
app.secret_key = "secret_key_for_flash_messages"

app.register_blueprint(routes_authentication)
app.register_blueprint(routes_encryption)
app.register_blueprint(routes_decryption)

if __name__ == "__main__":
    app.run(debug=True)
