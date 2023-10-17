from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PyPDF2 import PdfFileWriter, PdfFileReader
from PIL import Image

import moviepy.editor as mp
import mysql.connector
import os

app = Flask(__name__)
app.secret_key = 'secret_key_for_flash_messages'

# ? Set the upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'
# ? Define allowed file extensions globally
ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg', 'png', 'mp4'}

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

# ? Function to create a connection to the MySQL database
def create_connection():
    return mysql.connector.connect(**db_config)

# ! ENCRYPT DECRYPT

# ? Define a function to encrypt and decrypt data using AES
def encrypt_message_aes(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    plaintext = message.encode('utf-8')
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, cipher.iv 
def decrypt_message_aes(ciphertext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

# ? Define a function to encrypt and decrypt data using DES
def encrypt_message_des(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = message.encode('utf-8')
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
    return ciphertext
def decrypt_message_des(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted.decode('utf-8')

# ? Define a function to encrypt and decrypt data using RC4
def encrypt_message_arc4(message, key):
    cipher = ARC4.new(key)
    plaintext = message.encode('utf-8')
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext
def decrypt_message_arc4(ciphertext, key):
    cipher = ARC4.new(key)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode('utf-8')

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

# ? Route for the welcome page
@app.route('/welcome')
def welcome():
    return 'Selamat datang di aplikasi!'

# ? Route for the data submission form page (only accessible after login)
@app.route('/data_form', methods=['GET', 'POST'])
def data_form():
    if 'username' not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for('login'))

    # ? Retrieve the username from the session
    username = session['username']

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        phone_number = request.form['phone_number']
        last_education = request.form['last_education']
        
        # ? EAS Encrypt Method
        enc_eas_full_name, iv = encrypt_message_aes(full_name, eas_key)
        enc_eas_email, iv = encrypt_message_aes(email, eas_key)
        enc_eas_phone_number, iv = encrypt_message_aes(phone_number, eas_key)
        enc_eas_last_education, iv = encrypt_message_aes(last_education, eas_key)

        # ? DES Encrypt Method
        enc_des_full_name = encrypt_message_des(full_name, des_key)
        enc_des_email = encrypt_message_des(email, des_key)
        enc_des_phone_number = encrypt_message_des(phone_number, des_key)
        enc_des_last_education = encrypt_message_des(last_education, des_key)

        # ? ARC4 Encrypt Method
        enc_arc4_full_name = encrypt_message_arc4(full_name, des_key)
        enc_arc4_email = encrypt_message_arc4(email, des_key)
        enc_arc4_phone_number = encrypt_message_arc4(phone_number, des_key)
        enc_arc4_last_education = encrypt_message_arc4(last_education, des_key)

        # ? Set the upload folder dynamically based on the username
        app.config['UPLOAD_FOLDER'] = f'uploads/{username}'

        # ? Ensure the user's upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        # ? Handle file uploads
        pdf_path = save_and_encrypt_file('pdf_upload', 'pdf', encryption_method)
        img_path = save_and_encrypt_file('img_upload', 'img', encryption_method)
        video_path = save_and_encrypt_file('video_upload', 'video', encryption_method)

        connection = create_connection()
        cursor = connection.cursor()

        insert_data_query = """
        INSERT INTO data (
            full_name,
            enc_eas_full_name,
            enc_des_full_name,
            enc_arc4_full_name,
            email,
            enc_eas_email,
            enc_des_email,
            enc_arc4_email,
            phone_number,
            enc_eas_phone_number,
            enc_des_phone_number,
            enc_arc4_phone_number,
            last_education,
            enc_eas_last_education,
            enc_des_last_education,
            enc_arc4_last_education)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        data = (full_name, enc_eas_full_name, enc_des_full_name, enc_arc4_full_name, email, enc_eas_email, enc_des_email, enc_arc4_email, phone_number, enc_eas_phone_number, enc_des_phone_number, enc_arc4_phone_number, last_education, enc_eas_last_education, enc_des_last_education, enc_arc4_last_education)
        cursor.execute(insert_data_query, data)

        connection.commit()
        cursor.close()
        connection.close()

        flash("Data submitted successfully!", "flash-success")

    return render_template('data_form.html')

# ? Function to save and encrypt uploaded files
def save_and_encrypt_file(file_key, file_type, encryption_method):
    file = request.files[file_key]
    if file and allowed_file(file.filename, file_type):
        file_folder = app.config['UPLOAD_FOLDER']
        filename = secure_filename(file.filename)
        file_path = os.path.join(file_folder, filename)
        file.save(file_path)

        if encryption_method == 'AES':
            key = eas_key
        elif encryption_method == 'DES':
            key = des_key
        elif encryption_method == 'ARC4':
            key = arc4_key

        if file_type == 'pdf':
            encrypt_pdf_file(file_path, key)
        elif file_type == 'img':
            encrypt_image_file(file_path, key)
        elif file_type == 'video':
            encrypt_video_file(file_path, key)

        return file_path

def encrypt_pdf_file(pdf_file_path, key):
    output_pdf = PdfFileWriter()
    input_pdf = PdfFileReader(open(pdf_file_path, "rb"))

    for page_num in range(input_pdf.numPages):
        page = input_pdf.getPage(page_num)
        output_pdf.addPage(page)

    with open(pdf_file_path, "wb") as output:
        output_pdf.encrypt(key)
        output_pdf.write(output)

def encrypt_image_file(image_file_path, key):
    image = Image.open(image_file_path)
    image = image.convert("RGB")
    encrypted_data = encrypt_message_aes(image.tobytes(), key)
    with open(image_file_path, "wb") as output:
        output.write(encrypted_data)

def encrypt_video_file(video_file_path, key):
    clip = mp.VideoFileClip(video_file_path)
    encrypted_data = encrypt_message_aes(clip.to_videofile(), key)
    with open(video_file_path, "wb") as output:
        output.write(encrypted_data)

# ? Function to check if the file type is allowed
def allowed_file(filename, file_type):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ? Route to decrypt and view submitted data
@app.route('/view_data', methods=['GET', 'POST'])
def view_data():
    if 'username' not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        enc_data_id = request.form['data_id']
        encryption_method = request.form['encryption_method']

        connection = create_connection()
        cursor = connection.cursor()

        get_data_query = """
        SELECT 
            full_name, 
            email, 
            phone_number, 
            last_education, 
            enc_eas_full_name, 
            enc_eas_email, 
            enc_eas_phone_number, 
            enc_eas_last_education, 
            enc_des_full_name, 
            enc_des_email, 
            enc_des_phone_number, 
            enc_des_last_education, 
            enc_arc4_full_name, 
            enc_arc4_email, 
            enc_arc4_phone_number, 
            enc_arc4_last_education
        FROM data
        WHERE id = %s
        """
        cursor.execute(get_data_query, (enc_data_id,))
        data = cursor.fetchone()

        if data:
            if encryption_method == 'AES':
                decrypted_full_name = decrypt_message_aes(data[4], data[5], eas_key)
                decrypted_email = decrypt_message_aes(data[6], data[7], eas_key)
                decrypted_phone_number = decrypt_message_aes(data[8], data[9], eas_key)
                decrypted_last_education = decrypt_message_aes(data[10], data[11], eas_key)
            elif encryption_method == 'DES':
                decrypted_full_name = decrypt_message_des(data[12], eas_key)
                decrypted_email = decrypt_message_des(data[13], eas_key)
                decrypted_phone_number = decrypt_message_des(data[14], eas_key)
                decrypted_last_education = decrypt_message_des(data[15], eas_key)
            elif encryption_method == 'ARC4':
                decrypted_full_name = decrypt_message_arc4(data[16], eas_key)
                decrypted_email = decrypt_message_arc4(data[17], eas_key)
                decrypted_phone_number = decrypt_message_arc4(data[18], eas_key)
                decrypted_last_education = decrypt_message_arc4(data[19], eas_key)

            return render_template('view_data.html', data_id=enc_data_id, 
                                   decrypted_full_name=decrypted_full_name,
                                   decrypted_email=decrypted_email,
                                   decrypted_phone_number=decrypted_phone_number,
                                   decrypted_last_education=decrypted_last_education)

    return render_template('view_data_form.html')

# ? Generate a random 256-bit (32-byte) AES key
eas_key = get_random_bytes(32)
# ? Generate a random 64-bit (8-byte) DES key
des_key = get_random_bytes(8)
# ? Generate a random 128-bit (16-byte) RC4 key
arc4_key = get_random_bytes(16)

if __name__ == '__main__':
    app.run(debug=True)
