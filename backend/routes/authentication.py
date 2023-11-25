from flask import Blueprint, Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from backend.database.db import create_connection
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

authentication = Blueprint("authentication", __name__)

@authentication.route("/")
def root():
    return redirect(url_for("authentication.login"))

@authentication.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        connection = create_connection()
        cursor = connection.cursor()

        # ? Change to the appropriate table and column names in your database
        query = "SELECT username, password, id FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        session["userID"] = result[2]

        if result and check_password_hash(result[1], password):
            flash("Login Successful.", "flash-success")
            session["username"] = username
            
            return redirect(url_for("encryption.data_form"))
        else:
            flash("Login failed. Check your data again.", "flash-error")

        cursor.close()
        connection.close()
    return render_template("login.html")

@authentication.route("/logout", methods=["GET", "POST"])
def logout():
    if "username" in session:
        session.pop("username", None)
        flash("Logout Successful.", "flash-warning")
    return redirect(url_for("authentication.login"))

@authentication.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        aes_key = get_random_bytes(32)
        des_key = get_random_bytes(8)
        arc4_key = get_random_bytes(16)

        # Generate RSA key pair
        key_size = 2048
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        connection = create_connection()
        cursor = connection.cursor()

        check_username_query = "SELECT username FROM users WHERE username = %s"
        cursor.execute(check_username_query, (username,))
        existing_username = cursor.fetchone()

        if existing_username:
            flash("User name is already registered. Please come in.", "flash-warning")
        elif password != confirm_password:
            flash("Confirm password is incorrect.", "flash-error")
        else:
            hashed_password = generate_password_hash(password)

            insert_user_query = """
                INSERT INTO users (username, password, keyAES, keyDES, keyARC4, keyAsyPublic, keyAsyPrivate)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                insert_user_query,
                (
                    username,
                    hashed_password,
                    bytes(aes_key),
                    bytes(des_key),
                    bytes(arc4_key),
                    public_key_pem,
                    private_key_pem,
                ),
            )

            connection.commit()
            cursor.close()
            connection.close()

            flash("Registration successful. Please log in.", "flash-success")
            return redirect(url_for("authentication.login"))

    return render_template("register.html")

@authentication.route("/page_request")
def page_request():
    return render_template("page_request.html")