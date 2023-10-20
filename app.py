import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
<<<<<<< Updated upstream
<<<<<<< Updated upstream
=======
from werkzeug.utils import secure_filename  # Add this import
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import mysql.connector

>>>>>>> Stashed changes

app = Flask(__name__)
app.secret_key = 'secret_key_for_flash_messages'  # Change to a more secure secret key

<<<<<<< Updated upstream
=======
# Set the upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'


# Define allowed file extensions globally
ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg', 'png', 'mp4'}

# ! DATABASE CONNECTION

>>>>>>> Stashed changes
# Change to your database configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
<<<<<<< Updated upstream
    'password': 'Danindra123.',
=======
    'password': 'danindra123',
>>>>>>> Stashed changes
    'database': 'keamananinf',
    'charset': 'utf8mb4',
    'connection_timeout': 300  # Adjust the timeout value as needed
}

# Function to create a connection to the MySQL database
def create_connection():
    return mysql.connector.connect(**db_config)

<<<<<<< Updated upstream
=======
# ! ENCRYPT DECRYPT

# Define a function to encrypt and decrypt data using AES
def encrypt_message_aes(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    plaintext = message.encode('utf-8')
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, cipher.iv 

def decrypt_message_aes(ciphertext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

# ! ROUTING

>>>>>>> Stashed changes
# Redirect the root URL to the login page
=======
from werkzeug.utils import secure_filename
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from meta import encrypt_message_aes, encrypt_message_des, encrypt_message_arc4
from image import encrypt_image_file
from video import encrypt_video_file
from file import encrypt_pdf_file
import mysql.connector
import os
import time

app = Flask(__name__)
app.secret_key = 'secret_key_for_flash_messages'
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg', 'png', 'mp4'}

db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'danindra123',
    'database': 'keamananinf',
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',
    'connection_timeout': 300
}

def create_connection():
    return mysql.connector.connect(**db_config)

def allowed_file(filename, encryption_method):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_encryption_key(encryption_method):
    if encryption_method == 'AES':
        key_length = 16 
        return get_random_bytes(key_length)
    else:
        # Add conditions for other encryption methods if needed
        raise ValueError("Unsupported encryption method")


def decrypt_message_aes(key, encrypted_message, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode('utf-8')
    return decrypted_message

def save_and_encrypt_file(file_key, encryption_method, iv):
    file = request.files[file_key]
    if file and allowed_file(file.filename, encryption_method):
        file_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
        os.makedirs(file_folder, exist_ok=True)
        filename = secure_filename(file.filename)
        file_path = os.path.join(file_folder, filename)
        file.save(file_path)

        key = get_encryption_key(encryption_method)

        if encryption_method == 'pdf':
            encrypt_pdf_file(file_path, key)
        elif encryption_method == 'img':
            encrypt_image_file(file_path, key, iv)
        elif encryption_method == 'video':
            encrypt_video_file(file_path, key)

        return file_path

>>>>>>> Stashed changes
@app.route('/')
def root():
    return redirect(url_for('login'))

<<<<<<< Updated upstream
<<<<<<< Updated upstream
=======
# Route for logging out
=======
>>>>>>> Stashed changes
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if 'username' in session:
        session.pop('username', None)
        flash('Anda telah berhasil logout.', 'flash-warning')
    return redirect(url_for('login'))

<<<<<<< Updated upstream
>>>>>>> Stashed changes
# Route for the login page
=======
>>>>>>> Stashed changes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        connection = create_connection()
        cursor = connection.cursor()

<<<<<<< Updated upstream
        # Change to the appropriate table and column names in your database
=======
>>>>>>> Stashed changes
        query = "SELECT username, password FROM user WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result and check_password_hash(result[1], password):
            flash('Login berhasil!', 'success')
            session['username'] = username
            return redirect(url_for('data_form'))
        else:
            flash('Login gagal. Periksa kembali informasi Anda.', 'danger')

        cursor.close()
        connection.close()
    
    return render_template('login.html')

<<<<<<< Updated upstream
# Route for the registration page
=======
>>>>>>> Stashed changes
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
            flash('Username sudah terdaftar. Silakan login.', 'warning')
        elif password != confirm_password:
            flash('Konfirmasi password tidak sesuai.', 'danger')
        else:
            hashed_password = generate_password_hash(password)

            insert_user_query = "INSERT INTO user (username, password) VALUES (%s, %s)"
            cursor.execute(insert_user_query, (username, hashed_password))

            connection.commit()
            cursor.close()
            connection.close()

            flash('Registrasi berhasil. Silakan login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

<<<<<<< Updated upstream
# Route for the welcome page
@app.route('/welcome')
def welcome():
    return 'Selamat datang di aplikasi!'

# Route for the data submission form page (only accessible after login)
=======
>>>>>>> Stashed changes
@app.route('/data_form', methods=['GET', 'POST'])
def data_form():
    print(request.form)
    if 'username' not in session:
<<<<<<< Updated upstream
        flash('Anda harus login terlebih dahulu untuk mengakses halaman ini.', 'warning')
=======
        flash('You must log in first to access this page.', 'flash-warning')
>>>>>>> Stashed changes
        return redirect(url_for('login'))

<<<<<<< Updated upstream
    # Retrieve the username from the session
=======
>>>>>>> Stashed changes
    username = session['username']

    if request.method == 'POST':
<<<<<<< Updated upstream
=======
        app.config['UPLOAD_FOLDER'] = f'uploads/{username}'
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
>>>>>>> Stashed changes
        full_name = request.form['full_name']
        email = request.form['email']
<<<<<<< Updated upstream
        no_telepon = request.form['no_telepon']
        pendidikan = request.form['pendidikan']
=======
        phone_number = request.form['phone_number']
        last_education = request.form['last_education']
<<<<<<< Updated upstream

        # EAS Encrypt Method
        eas_key = get_random_bytes(32)
        enc_full_name, iv = encrypt_message_aes(full_name, eas_key)

        # Set the upload folder dynamically based on the username
        app.config['UPLOAD_FOLDER'] = f'uploads/{username}'

        # Ensure the user's upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        # Handle file uploads
        pdf_path = save_file('pdf_upload', 'pdf')
        img_path = save_file('img_upload', 'img')
        video_path = save_file('video_upload', 'video')
>>>>>>> Stashed changes
=======
        enc_dec_method = request.form['enc_dec_method']
        
        start_time = time.perf_counter()

        iv = get_random_bytes(16)
        enc_full_name = encrypt_message_aes(get_encryption_key('AES'), full_name, iv)
        enc_email = encrypt_message_aes(get_encryption_key('AES'), email, iv)
        enc_phone_number = encrypt_message_aes(get_encryption_key('AES'), phone_number, iv)
        enc_last_education = encrypt_message_aes(get_encryption_key('AES'), last_education, iv)

        end_time = time.perf_counter()
>>>>>>> Stashed changes

        connection = create_connection()
        cursor = connection.cursor()

        insert_data_query = """
<<<<<<< Updated upstream
<<<<<<< Updated upstream
        INSERT INTO data (nama_lengkap, email, no_telepon, pendidikan)
        VALUES (%s, %s, %s, %s)
        """
        data = (nama_lengkap, email, no_telepon, pendidikan)
=======
        INSERT INTO data (full_name, enc_full_name, enc_key_full_name, email, phone_number, last_education, pdf_path, img_path, video_path)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        data = (full_name, enc_full_name, eas_key, email, phone_number, last_education, pdf_path, img_path, video_path)
>>>>>>> Stashed changes
=======
        INSERT INTO data_form 
        (full_name, enc_full_name, email, enc_email, phone_number, enc_phone_number, last_education, enc_last_education, enc_dec_method, enc_dec_key) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        data = (
            full_name,
            enc_full_name,
            email,
            enc_email,
            phone_number,
            enc_phone_number,
            last_education,
            enc_last_education,
            enc_dec_method,
            get_encryption_key(enc_dec_method)
        )
>>>>>>> Stashed changes
        cursor.execute(insert_data_query, data)
        connection.commit()

        cursor.close()
        connection.close()
<<<<<<< Updated upstream

<<<<<<< Updated upstream
        flash('Data berhasil disubmit!', 'success')
=======
        flash('Data submitted successfully!', 'flash-success')
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes

        flash("Data submitted successfully.", "flash-success")
        flash(f"Encryption time: {end_time - start_time:.6f} seconds.", "flash-info")

<<<<<<< Updated upstream
# Function to save uploaded files
def save_file(file_key, file_type):
    file = request.files[file_key]
    if file and allowed_file(file.filename, file_type):
        # Use the dynamically set upload folder
        file_folder = app.config['UPLOAD_FOLDER']
        filename = secure_filename(file.filename)
        file_path = os.path.join(file_folder, filename)
        file.save(file_path)
        return file_path
    return None

# Function to check if the file type is allowed
def allowed_file(filename, file_type):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == '__main__':
    app.run(debug=True)
=======
    return render_template('data_form.html', username=username, enc_full_name=enc_full_name, enc_email=enc_email, enc_phone_number=enc_phone_number, enc_last_education=enc_last_education)

@app.route('/view_data_form', methods=['GET', 'POST'])
def view_data_form():
    if 'username' not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for('login'))

    connection = create_connection()
    cursor = connection.cursor()

    if request.method == 'POST':
        data_id = request.form.get('data_id')
        query = "SELECT * FROM data_form WHERE id = %s"
        cursor.execute(query, (data_id,))
        result = cursor.fetchone()

        cursor.close()
        connection.close()

        if result:
            # Dekripsi nilai yang diambil dari database
            dec_full_name = decrypt_message_aes(result[9], result[1], result[10])
            dec_email = decrypt_message_aes(result[9], result[3], result[11])
            dec_phone_number = decrypt_message_aes(result[9], result[5], result[12])
            dec_last_education = decrypt_message_aes(result[9], result[7], result[13])

            # Kirim data ke template
            return render_template(
                'view_data_form.html',
                data=result,
                dec_full_name=dec_full_name,
                dec_email=dec_email,
                dec_phone_number=dec_phone_number,
                dec_last_education=dec_last_education
            )
        else:
            flash("Data not found.", "flash-error")
            return redirect(url_for('data_form'))

    # Jika metode adalah GET, tampilkan formulir atau lakukan hal lain sesuai kebutuhan
    # ...

    return render_template('view_data_form.html')
        
@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'username' not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for('login'))

    username = session['username']
    enc_dec_method = request.form['enc_dec_method']
    encryption_method = request.form['encryption_method']

    if 'file' not in request.files:
        flash("No file part.", "flash-error")
        return redirect(request.url)

    file_path = save_and_encrypt_file('file', encryption_method, get_random_bytes(16))
    flash(f"File uploaded and encrypted successfully. Path: {file_path}", "flash-success")

    return redirect(url_for('data_form'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
>>>>>>> Stashed changes
