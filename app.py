from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = 'secret_key_for_flash_messages'  # Change to a more secure secret key

# ! DATABASE CONNECTION

# Change to your database configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'keamananinf',
}

# Function to create a connection to the MySQL database
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

# ? Generate a random 256-bit (32-byte) AES key
# eas_key = get_random_bytes(32)
# ? Generate a random 64-bit (8-byte) DES key
# des_key = get_random_bytes(8)
# ? Generate a random 128-bit (16-byte) RC4 key
# arc4_key = get_random_bytes(16)

# Message to be encrypted
message_to_encrypt = "Hello, this is a secret message!"

# ? Encrypt the message
# encrypted_message = encrypt_message_des(message_to_encrypt, encryption_key)
# print("Encrypted message:", encrypted_message)
# ? Decrypt the message
# decrypted_message = decrypt_message_des(encrypted_message, encryption_key)
# print("Decrypted message:", decrypted_message)


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
        flash('Anda telah berhasil logout.', 'flash-warning')
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
            flash('Login berhasil!', 'flash-success')
            session['username'] = username
            return redirect(url_for('data_form'))
        else:
            flash('Login gagal. Periksa kembali informasi Anda.', 'flash-error')

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
            flash('Username sudah terdaftar. Silakan login.', 'flash-warning')
        elif password != confirm_password:
            flash('Konfirmasi password tidak sesuai.', 'flash-error')
        else:
            hashed_password = generate_password_hash(password)

            insert_user_query = "INSERT INTO user (username, password) VALUES (%s, %s)"
            cursor.execute(insert_user_query, (username, hashed_password))

            connection.commit()
            cursor.close()
            connection.close()

            flash('Registrasi berhasil. Silakan login.', 'flash-success')
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
        flash('Anda harus login terlebih dahulu untuk mengakses halaman ini.', 'flash-warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nama_lengkap = request.form['nama_lengkap']
        email = request.form['email']
        no_telepon = request.form['no_telepon']
        pendidikan = request.form['pendidikan']
        
        # ? EAS Encrypt Method
        eas_key = get_random_bytes(32)
        enc_nama_lengkap, iv = encrypt_message_aes(nama_lengkap, eas_key)

        connection = create_connection()
        cursor = connection.cursor()

        insert_data_query = """
        INSERT INTO data (nama_lengkap, enc_nama_lengkap, enc_key_nama_lengkap, email, no_telepon, pendidikan)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        data = (nama_lengkap, enc_nama_lengkap, eas_key, email, no_telepon, pendidikan)
        cursor.execute(insert_data_query, data)

        connection.commit()
        cursor.close()
        connection.close()

        flash('Data berhasil disubmit!', 'flash-success')

    return render_template('data_form.html')

if __name__ == '__main__':
    app.run(debug=True)
