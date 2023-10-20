from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PyPDF2 import PdfWriter, PdfReader
from PIL import Image
from meta import encrypt_message_aes, decrypt_message_aes, encrypt_message_des, decrypt_message_des, encrypt_message_arc4, decrypt_message_arc4
from image import encrypt_image_aes, decrypt_image_aes
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
            # ? Generate a random initialization vector (IV)
            iv = get_random_bytes(16)
            # ? Generate a random 256-bit (32-byte) AES key
            aes_key = get_random_bytes(32)
            
            start_time_enc = time.perf_counter()
            enc_full_name = encrypt_message_aes(aes_key, full_name, iv)
            enc_email = encrypt_message_aes(aes_key, email, iv)
            enc_phone_number = encrypt_message_aes(aes_key, phone_number, iv)
            enc_last_education = encrypt_message_aes(aes_key, last_education, iv)
            # img_enc = encrypt_image_aes('uploads/NaufalIhza/jersey-ori.jpeg', aes_key)
            end_time_enc = time.perf_counter()

            start_time_dec = time.perf_counter()
            dec_full_name = decrypt_message_aes(aes_key, enc_full_name, iv)
            dec_email = decrypt_message_aes(aes_key, enc_email, iv)
            dec_phone_number = decrypt_message_aes(aes_key, enc_phone_number, iv)
            dec_last_education = decrypt_message_aes(aes_key, enc_last_education, iv)
            # img_dec = encrypt_image_aes('uploads/NaufalIhza/jersey-ori.jpeg', aes_key)
            end_time_dec = time.perf_counter()

            # img_path = save_and_encrypt_file('img_upload', 'img', 'AES', iv)
            # pdf_path = save_and_encrypt_file('pdf_upload', 'pdf', 'AES')
            # video_path = save_and_encrypt_file('video_upload', 'video', 'AES')
            
            enc_dec_key = aes_key
        if enc_dec_method == 'DES':
            # ? Generate a random initialization vector (IV)
            iv = get_random_bytes(8)
            des_key = get_random_bytes(8)

            start_time_enc = time.perf_counter()
            enc_full_name = encrypt_message_des(des_key, full_name, iv)
            enc_email = encrypt_message_des(des_key, email, iv)
            enc_phone_number = encrypt_message_des(des_key, phone_number, iv)
            enc_last_education = encrypt_message_des(des_key, last_education, iv)
            # img_enc = encrypt_image_aes('uploads/NaufalIhza/jersey-ori.jpeg', aes_key)
            end_time_enc = time.perf_counter()

            start_time_dec = time.perf_counter()
            dec_full_name = decrypt_message_des(des_key, enc_full_name, iv)
            dec_email = decrypt_message_des(des_key, enc_email, iv)
            dec_phone_number = decrypt_message_des(des_key, enc_phone_number, iv)
            dec_last_education = decrypt_message_des(des_key, enc_last_education, iv)
            # img_dec = encrypt_image_aes('uploads/NaufalIhza/jersey-ori.jpeg', aes_key)
            end_time_dec = time.perf_counter()

            # img_path = save_and_encrypt_file('img_upload', 'img', 'DES')
            # pdf_path = save_and_encrypt_file('pdf_upload', 'pdf', 'DES')
            # video_path = save_and_encrypt_file('video_upload', 'video', 'DES')
            
            enc_dec_key = des_key
        if enc_dec_method == 'ARC4':
            # ? ARC4 didn't need initialization vector (IV)
            iv = None
            arc4_key = get_random_bytes(16)
        
            start_time_enc= time.perf_counter()
            enc_full_name = encrypt_message_arc4(arc4_key, full_name)
            enc_email = encrypt_message_arc4(arc4_key, email)
            enc_phone_number = encrypt_message_arc4(arc4_key, phone_number)
            enc_last_education = encrypt_message_arc4(arc4_key, last_education)
            end_time_enc = time.perf_counter()

            start_time_dec = time.perf_counter()
            dec_full_name = decrypt_message_arc4(arc4_key, enc_full_name)
            dec_email = decrypt_message_arc4(arc4_key, enc_email)
            dec_phone_number = decrypt_message_arc4(arc4_key, enc_phone_number)
            dec_last_education = decrypt_message_arc4(arc4_key, enc_last_education)
            # img_dec = encrypt_image_aes('uploads/NaufalIhza/jersey-ori.jpeg', aes_key)
            end_time_dec = time.perf_counter()

            # img_path = save_and_encrypt_file('img_upload', 'img', 'ARC4')
            # pdf_path = save_and_encrypt_file('pdf_upload', 'pdf', 'ARC4')
            # video_path = save_and_encrypt_file('video_upload', 'video', 'ARC4')

            enc_dec_key = arc4_key

        connection = create_connection()
        cursor = connection.cursor()

        insert_data_query = """
        INSERT INTO data (
            user,
            iv,
            enc_dec_method,
            enc_dec_key,
            full_name,
            email,
            phone_number,
            last_education,
            enc_full_name,
            enc_email,
            enc_phone_number,
            enc_last_education,
            dec_full_name,
            dec_email,
            dec_phone_number,
            dec_last_education
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        data = (username, iv, enc_dec_method, enc_dec_key, full_name, email, phone_number, last_education, 
        enc_full_name, enc_email, enc_phone_number, enc_last_education, dec_full_name, dec_email, dec_phone_number, dec_last_education)
        cursor.execute(insert_data_query, data)

        connection.commit()
        cursor.close()
        connection.close()

        encryption_time = end_time_enc - start_time_enc
        decryption_time = end_time_dec - start_time_dec

        print(f"Using { enc_dec_method }, Encryption time : {encryption_time:.10f} sec, Decryption time : {decryption_time:.10f} sec")
        flash(f"Data submitted successfully!\nUsing { enc_dec_method }, Encryption time : {encryption_time:.10f} sec, Decryption time : {decryption_time:.10f} sec", "flash-success")

    return render_template('data_form.html')

# ? Route to decrypt and view submitted data

# @app.route('/view_data_form', methods=['GET', 'POST'])
# def view_data_form():
#     if 'username' not in session:
#         flash("You must log in first to access this page.", "flash-warning")
#         return redirect(url_for('login'))
#     if request.method == 'POST':
#         enc_data_id = request.form['data_id']
#         return redirect(url_for('view_data', data_id=enc_data_id))

#     return render_template('view_data_form.html')

@app.route('/view_data')
def view_data():
    if 'username' not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for('login'))

    connection = create_connection()
    cursor = connection.cursor()

    username = session['username']

    # Mengambil enc_dec_method pertama dari data user
    select_first_enc_dec_method_query = """ 
        SELECT enc_dec_method
        FROM data
        WHERE user = %s
        ORDER BY id ASC
        LIMIT 1;
    """
    cursor.execute(select_first_enc_dec_method_query, (username,))
    first_enc_dec_method = cursor.fetchone()

    if first_enc_dec_method:
        view_enc_dec_method = first_enc_dec_method[0]
    else:
        # Jika tidak ada data, maka default-kan ke 'AES'
        view_enc_dec_method = 'AES'

    select_data_query = """ 
        SELECT
            user,
            iv,
            enc_dec_method,
            enc_dec_key,
            full_name,
            email,
            phone_number,
            last_education,
            enc_full_name,
            enc_email,
            enc_phone_number,
            enc_last_education,
            dec_full_name,
            dec_email,
            dec_phone_number,
            dec_last_education
        FROM data WHERE user = %s AND enc_dec_method = %s
    """
    cursor.execute(select_data_query, (username, view_enc_dec_method))
    data = cursor.fetchone()

    cursor.close()
    connection.close()

    if data is None:
        flash("There is no data yet!", "flash-warning")
        return redirect(url_for('data_form')) 

    user, iv, enc_dec_method, enc_dec_key, full_name, email, phone_number, last_education, enc_full_name, enc_email, enc_phone_number, enc_last_education, dec_full_name, dec_email, dec_phone_number, dec_last_education = data

    return render_template('view_data.html', enc_dec_method=enc_dec_method, enc_full_name=enc_full_name, dec_full_name=dec_full_name, dec_email=dec_email, dec_phone_number=dec_phone_number, dec_last_education=dec_last_education)


if __name__ == '__main__':
    # ? Generate a random 256-bit (32-byte) AES key
    # aes_key = get_random_bytes(32)
    # aes_key = b"[\xcf\xe1\x9f\xb7\x87\xf9;5\x1d00F\xeb\x00\x92\xc1\xa2K\x0f\xab\xac\xa3r\xbe\x96\xf5\x19*\xba'\x18"
    # ? Generate a random 64-bit (8-byte) DES key
    # des_key = get_random_bytes(8)
    # des_key = b'P\xc1:\xba=\x1e\xd6X'
    # ? Generate a random 128-bit (16-byte) RC4 key
    # arc4_key = get_random_bytes(16)
    # arc4_key = b'\x06\xe0\n\xb3\xe0[S\xac\xb8\xce\xc01\xc6\xf6\x97\x81'
    
    # input_image_path = 'uploads/NaufalIhza/jersey-ori.jpeg'
    # encrypted_image_path = 'uploads/NaufalIhza/jersey-enc.jpeg'
    # decrypted_image_path = 'uploads/NaufalIhza/jersey-dec.jpeg'
    # encrypt_image_aes(input_image_path, encrypted_image_path, aes_key)
    # decrypt_image_aes(encrypted_image_path, decrypted_image_path, aes_key)

    app.run(debug=True)