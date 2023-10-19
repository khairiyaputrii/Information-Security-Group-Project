from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PyPDF2 import PdfWriter, PdfReader
from PIL import Image
from meta import encrypt_message_aes, decrypt_message_aes, encrypt_message_des, decrypt_message_des, encrypt_message_arc4, decrypt_message_arc4
from image import encrypt_image_file
from video import encrypt_video_file
from file import encrypt_pdf_file

import moviepy.editor as mp
import mysql.connector
import os
import io
import time

app = Flask(__name__)
app.secret_key = 'secret_key_for_flash_messages'

# ? Set the upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'
# ? Define allowed file extensions globally
ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg', 'png', 'mp4'}

# ? Function to create a connection to the MySQL database
def create_connection():
    return mysql.connector.connect(**db_config)

# ? Function to check if the file type is allowed
def allowed_file(filename, file_type):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ? Function to save and encrypt uploaded files
def save_and_encrypt_file(file_key, file_type, encryption_method, iv):
    file = request.files[file_key]
    if file and allowed_file(file.filename, file_type):
        file_folder = app.config['UPLOAD_FOLDER']
        filename = secure_filename(file.filename)
        file_path = os.path.join(file_folder, filename)
        file.save(file_path)

        if encryption_method == 'AES':
            key = aes_key
        elif encryption_method == 'DES':
            key = des_key
        elif encryption_method == 'ARC4':
            key = arc4_key

        if file_type == 'pdf':
            encrypt_pdf_file(file_path, key)
        elif file_type == 'img':
            encrypt_image_file(file_path, key, iv)
        elif file_type == 'video':
            encrypt_video_file(file_path, key)

        return file_path

# ! DATABASE CONNECTION

# ? Change to your database configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'keamananinf',
    'charset': 'utf8mb4',
    'connection_timeout': 300
}

# ! ROUTING

# ? Redirect the root URL to the login page
@app.route('/')
def root():
    return redirect(url_for('login'))

# ? Route for logging out
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if 'username' in session:
        session.pop('username', None)
        flash("Logout Successful.", "flash-warning")
    return redirect(url_for('login'))

# ? Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        connection = create_connection()
        cursor = connection.cursor()

        # ? Change to the appropriate table and column names in your database
        query = "SELECT username, password FROM user WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result and check_password_hash(result[1], password):
            flash("Login Successful.", "flash-success")
            session['username'] = username
            return redirect(url_for('data_form'))
        else:
            flash("Login failed. Check your data again.", "flash-error")

        cursor.close()
        connection.close()
    
    return render_template('login.html')

# ? Route for the registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        connection = create_connection()
        cursor = connection.cursor()

        check_username_query = "SELECT username FROM user WHERE username = %s"
        cursor.execute(check_username_query, (username,))
        existing_username = cursor.fetchone()

        if existing_username:
            flash("User name is already registered. Please come in.", "flash-warning")
        elif password != confirm_password:
            flash("Confirm password is incorrect.", "flash-error")
        else:
            hashed_password = generate_password_hash(password)

            insert_user_query = "INSERT INTO user (username, password) VALUES (%s, %s)"
            cursor.execute(insert_user_query, (username, hashed_password))

            connection.commit()
            cursor.close()
            connection.close()

            flash("Registration successful. Please log in.", "flash-success")
            return redirect(url_for('login'))

    return render_template('register.html')

# ? Route for the data submission form page (only accessible after login)
@app.route('/data_form', methods=['GET', 'POST'])
def data_form():
    if 'username' not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for('login'))

    # ? Retrieve the username from the session
    username = session['username']
    enc_full_name, enc_email, enc_phone_number, enc_last_education = None, None, None, None

    if request.method == 'POST':
        # ? Set the upload folder dynamically based on the username
        app.config['UPLOAD_FOLDER'] = f'uploads/{username}'
        # ? Ensure the user's upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        full_name = request.form['full_name']
        email = request.form['email']
        phone_number = request.form['phone_number']
        last_education = request.form['last_education']
        enc_dec_method = request.form['enc_dec_method']
        
        if enc_dec_method == 'AES':
            start_time = time.perf_counter()
            iv = get_random_bytes(16)
            enc_full_name = encrypt_message_aes(aes_key, full_name, iv)
            enc_email = encrypt_message_aes(aes_key, email, iv)
            enc_phone_number = encrypt_message_aes(aes_key, phone_number, iv)
            enc_last_education = encrypt_message_aes(aes_key, last_education, iv)
            # img_path = save_and_encrypt_file('img_upload', 'img', 'AES', iv)
            # pdf_path = save_and_encrypt_file('pdf_upload', 'pdf', 'AES')
            # video_path = save_and_encrypt_file('video_upload', 'video', 'AES')
            end_time = time.perf_counter()
            enc_dec_key = aes_key
        if enc_dec_method == 'DES':
            start_time = time.perf_counter()
            iv = get_random_bytes(8)
            enc_full_name = encrypt_message_des(des_key, full_name, iv)
            enc_email = encrypt_message_des(des_key, email, iv)
            enc_phone_number = encrypt_message_des(des_key, phone_number, iv)
            enc_last_education = encrypt_message_des(des_key, last_education, iv)
            # img_path = save_and_encrypt_file('img_upload', 'img', 'DES')
            # pdf_path = save_and_encrypt_file('pdf_upload', 'pdf', 'DES')
            # video_path = save_and_encrypt_file('video_upload', 'video', 'DES')
            end_time = time.perf_counter()
            enc_dec_key = des_key
        if enc_dec_method == 'ARC4':
            start_time = time.perf_counter()
            iv = None
            enc_full_name = encrypt_message_arc4(arc4_key, full_name)
            enc_email = encrypt_message_arc4(arc4_key, email)
            enc_phone_number = encrypt_message_arc4(arc4_key, phone_number)
            enc_last_education = encrypt_message_arc4(arc4_key, last_education)
            # img_path = save_and_encrypt_file('img_upload', 'img', 'ARC4')
            # pdf_path = save_and_encrypt_file('pdf_upload', 'pdf', 'ARC4')
            # video_path = save_and_encrypt_file('video_upload', 'video', 'ARC4')
            end_time = time.perf_counter()
            enc_dec_key = arc4_key

        connection = create_connection()
        cursor = connection.cursor()

        insert_data_query = """
        INSERT INTO data (
            iv,
            enc_dec_method,
            enc_dec_key,
            full_name,
            enc_full_name,
            email,
            enc_email,
            phone_number,
            enc_phone_number,
            last_education,
            enc_last_education
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        data = (iv, enc_dec_method, enc_dec_key, full_name, enc_full_name, email, enc_email, phone_number, enc_phone_number, last_education, enc_last_education)
        cursor.execute(insert_data_query, data)

        connection.commit()
        cursor.close()
        connection.close()
        encryption_time = end_time - start_time
        print(f"Encryption time using { enc_dec_method } : {encryption_time:.10f} seconds")
        flash(f"Data submitted successfully! Encryption Time using { enc_dec_method } : {encryption_time:.10f} seconds", "flash-success")

    return render_template('data_form.html')

# ? Route to decrypt and view submitted data

@app.route('/view_data_form', methods=['GET', 'POST'])
def view_data_form():
    if 'username' not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        enc_data_id = request.form['data_id']
        return redirect(url_for('view_data', data_id=enc_data_id))

    return render_template('view_data_form.html')

@app.route('/view_data/<int:data_id>')
def view_data(data_id):
    if 'username' not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for('login'))

    connection = create_connection()
    cursor = connection.cursor()

    select_data_query = """ 
        SELECT
            id,
            iv,
            enc_dec_method,
            enc_dec_key,
            full_name,
            enc_full_name,
            email,
            enc_email,
            phone_number,
            enc_phone_number,
            last_education,
            enc_last_education
        FROM data WHERE id = %s
    """
    cursor.execute(select_data_query, (data_id,))
    data = cursor.fetchone()

    cursor.close()
    connection.close()

    if data is None:
        flash("Data with the selected ID does not exist.", "flash-warning")
        return redirect(url_for('data_list')) 

    data_id, iv, enc_dec_method, enc_dec_key, full_name, enc_full_name, email, enc_email, phone_number, enc_phone_number, last_education, enc_last_education = data

    if enc_dec_method == 'AES':
        dec_full_name = decrypt_message_aes(aes_key, full_name.encode('utf-8'), iv)
        dec_email = decrypt_message_aes(aes_key, email.encode('utf-8'), iv)
        dec_phone_number = decrypt_message_aes(aes_key, phone_number.encode('utf-8'), iv)
        dec_last_education = decrypt_message_aes(aes_key, last_education.encode('utf-8'), iv)
    if enc_dec_method == 'DES':
        dec_full_name = decrypt_message_des(des_key, full_name, iv)
        dec_email = decrypt_message_des(des_key, email, iv)
        dec_phone_number = decrypt_message_des(des_key, phone_number, iv)
        dec_last_education = decrypt_message_des(des_key, last_education, iv)
    if enc_dec_method == 'ARC4':
        dec_full_name = decrypt_message_arc4(arc4_key, full_name)
        dec_email = decrypt_message_arc4(arc4_key, email)
        dec_phone_number = decrypt_message_arc4(arc4_key, phone_number)
        dec_last_education = decrypt_message_arc4(arc4_key, last_education)

    return render_template('view_data.html', data_id=data_id, full_name=full_name, dec_full_name=dec_full_name, email=email, dec_email=dec_email, phone_number=phone_number, dec_phone_number=dec_phone_number, last_education=last_education, dec_last_education=dec_last_education)

if __name__ == '__main__':
    # ? Generate a random 256-bit (32-byte) AES key
    # aes_key = get_random_bytes(32)
    aes_key = b'\x1a\xb2\x3c\xd4\x5e\x6f\x17\x88\x99\xaa\x0b\x4c\x1d\x6e\x7f\x30'
    # ? Generate a random 64-bit (8-byte) DES key
    # des_key = get_random_bytes(8)
    des_key = b'\x01\x23\x45\x67\x89\xab\xcd\xef'
    # ? Generate a random 128-bit (16-byte) RC4 key
    # arc4_key = get_random_bytes(16)
    arc4_key = b'\x4a\x2d\x90\x8c\xce\xf4\x0b\x6f\xe0\x1a\x0e\x63\x17\x45\x98\xf2'
    
    # input_image_path = 'uploads/NaufalIhza/jersey-ori.jpeg'
    # encrypted_image_path = 'uploads/NaufalIhza/jersey-enc.jpeg'
    # decrypted_image_path = 'uploads/NaufalIhza/jersey-dec.jpeg'
    # encrypt_image_aes(input_image_path, encrypted_image_path, aes_key)
    # decrypt_image_aes(encrypted_image_path, decrypted_image_path, aes_key)

    app.run(debug=True)