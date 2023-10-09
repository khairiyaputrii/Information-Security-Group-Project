from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = 'secret_key_for_flash_messages'  # Ganti dengan kunci rahasia yang lebih aman

# Simpan data pengguna yang terdaftar (sederhana, seharusnya menggunakan database)
registered_users = {'user1': 'password1', 'user2': 'password2'}

# Arahkan root URL ke halaman login
@app.route('/')
def root():
    return redirect(url_for('login'))

# Rute untuk halaman login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in registered_users and registered_users[username] == password:
            flash('Login berhasil!', 'success')
            return redirect(url_for('data_form'))
        else:
            flash('Login gagal. Periksa kembali informasi Anda.', 'danger')
    
    return render_template('login.html')

# Rute untuk halaman registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if username in registered_users:
            flash('Username sudah terdaftar. Silakan login.', 'warning')
        elif password != confirm_password:
            flash('Konfirmasi password tidak sesuai.', 'danger')
        else:
            registered_users[username] = password
            flash('Registrasi berhasil. Silakan login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

# Rute untuk halaman selamat datang
@app.route('/welcome')
def welcome():
    return 'Selamat datang di aplikasi!'

# Rute untuk halaman form data (hanya dapat diakses setelah login)
@app.route('/data_form', methods=['GET', 'POST'])
def data_form():
    # Periksa apakah pengguna sudah login
    # if 'username' not in session:
    #     flash('Anda harus login terlebih dahulu untuk mengakses halaman ini.', 'warning')
    #     return redirect(url_for('login'))

    if request.method == 'POST':
        # Tangani data yang dikirimkan melalui formulir
        nama_lengkap = request.form['nama_lengkap']
        email = request.form['email']
        no_telepon = request.form['no_telepon']
        pendidikan = request.form['pendidikan']

        # Di sini Anda dapat melakukan sesuatu dengan data yang dikirim, seperti menyimpannya di database

        flash('Data berhasil disubmit!', 'success')

    return render_template('data_form.html')

if __name__ == '__main__':
    app.run(debug=True)