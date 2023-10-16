import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
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
@app.route('/')
def root():
    return redirect(url_for('login'))

<<<<<<< Updated upstream
=======
# Route for logging out
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if 'username' in session:
        session.pop('username', None)
        flash('Anda telah berhasil logout.', 'flash-warning')
    return redirect(url_for('login'))

>>>>>>> Stashed changes
# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        connection = create_connection()
        cursor = connection.cursor()

        # Change to the appropriate table and column names in your database
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

# Route for the registration page
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

# Route for the welcome page
@app.route('/welcome')
def welcome():
    return 'Selamat datang di aplikasi!'

# Route for the data submission form page (only accessible after login)
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

    # Retrieve the username from the session
    username = session['username']

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
<<<<<<< Updated upstream
        no_telepon = request.form['no_telepon']
        pendidikan = request.form['pendidikan']
=======
        phone_number = request.form['phone_number']
        last_education = request.form['last_education']

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

        connection = create_connection()
        cursor = connection.cursor()

        insert_data_query = """
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
        cursor.execute(insert_data_query, data)

        connection.commit()
        cursor.close()
        connection.close()

<<<<<<< Updated upstream
        flash('Data berhasil disubmit!', 'success')
=======
        flash('Data submitted successfully!', 'flash-success')
>>>>>>> Stashed changes

    return render_template('data_form.html')

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
