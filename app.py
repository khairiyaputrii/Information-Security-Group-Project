from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from PyPDF2 import PdfWriter, PdfReader
from PIL import Image
import moviepy.editor as mp
import os
import io

from backend.database.db import create_connection
from backend.routes.main import root as routes_root
from backend.routes.authentication import authentication as routes_authentication
from backend.routes.encryption import encryption as routes_encryption
from backend.routes.decryption import decryption as routes_decryption
from backend.routes.request import request as routes_request

app = Flask(__name__)
app.secret_key = "secret_key_for_flash_messages"

app.register_blueprint(routes_root)
app.register_blueprint(routes_authentication)
app.register_blueprint(routes_encryption)
app.register_blueprint(routes_decryption)
app.register_blueprint(routes_request)

if __name__ == "__main__":
    app.run(debug=True)
