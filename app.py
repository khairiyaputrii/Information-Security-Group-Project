from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret_key_for_flash_messages'  # Change to a more secure secret key

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

# Redirect the root URL to the login page
@app.route('/')
def root():
    return redirect(url_for('login'))

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
    if 'username' not in session:
        flash('Anda harus login terlebih dahulu untuk mengakses halaman ini.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nama_lengkap = request.form['nama_lengkap']
        email = request.form['email']
        no_telepon = request.form['no_telepon']
        pendidikan = request.form['pendidikan']

        connection = create_connection()
        cursor = connection.cursor()

        insert_data_query = """
        INSERT INTO data (nama_lengkap, email, no_telepon, pendidikan)
        VALUES (%s, %s, %s, %s)
        """
        data = (nama_lengkap, email, no_telepon, pendidikan)
        cursor.execute(insert_data_query, data)

        connection.commit()
        cursor.close()
        connection.close()

        flash('Data berhasil disubmit!', 'success')

    return render_template('data_form.html')

if __name__ == '__main__':
    app.run(debug=True)
