from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Cryptodome.Cipher import AES, DES, ARC4
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from PyPDF2 import PdfWriter, PdfReader
from PIL import Image
from meta import (
    encrypt_message_aes,
    decrypt_message_aes,
    encrypt_message_des,
    decrypt_message_des,
    encrypt_message_arc4,
    decrypt_message_arc4,
)
# from meta import encrypt_message_aes, decrypt_message_aes
from image import encrypt_image_aes, decrypt_image_aes
from video import encrypt_video_file
from file import encrypt_pdf_file

import moviepy.editor as mp
import mysql.connector
import os
import io
import time

# ! DATABASE CONNECTION
# ? Change to your database configuration
db_config = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "",
    "database": "informationsecurity",
    "charset": "utf8mb4",
    "connection_timeout": 300,
}

app = Flask(__name__)
app.secret_key = "secret_key_for_flash_messages"

# ? Set the upload folder
app.config["UPLOAD_FOLDER"] = "uploads"
# ? Define allowed file extensions globally
ALLOWED_EXTENSIONS = {"pdf", "jpeg", "jpg", "png", "mp4"}


# ? Function to create a connection to the MySQL database
def create_connection():
    return mysql.connector.connect(**db_config)


# ! ROUTING
# ? Redirect the root URL to the login page
@app.route("/")
def root():
    return redirect(url_for("login"))


# ? Route for logging out
@app.route("/logout", methods=["GET", "POST"])
def logout():
    if "username" in session:
        session.pop("username", None)
        flash("Logout Successful.", "flash-warning")
    return redirect(url_for("login"))


# ? Route for the login page
@app.route("/login", methods=["GET", "POST"])
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
            
            return redirect(url_for("data_form"))
        else:
            flash("Login failed. Check your data again.", "flash-error")

        cursor.close()
        connection.close()

    return render_template("login.html")


# ? Route for the registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        aes_key = get_random_bytes(32)
        des_key = get_random_bytes(8)
        arc4_key = get_random_bytes(16)

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

            insert_user_query = "INSERT INTO users (username, password,	keyAES, keyDES, keyARC4) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(
                insert_user_query,
                (
                    username,
                    hashed_password,
                    bytes(aes_key),
                    bytes(des_key),
                    bytes(arc4_key),
                ),
            )

            connection.commit()
            cursor.close()
            connection.close()

            flash("Registration successful. Please log in.", "flash-success")
            return redirect(url_for("login"))

    return render_template("register.html")


# ? Route for the data submission form page (only accessible after login)
@app.route("/data_form", methods=["GET", "POST"])
def data_form():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("login"))

    # ? Retrieve the username from the session
    username = session["username"]
    keyAES, keyDES, keyARC4 = None, None, None

    if request.method == "POST":
        full_name = request.form["full_name"]
        email = request.form["email"]
        phone_number = request.form["phone_number"]
        last_education = request.form["last_education"]

        connection = create_connection()
        cursor = connection.cursor()

        start_time_enc = time.perf_counter()
        cursor.execute(
            "SELECT id, keyAES, keyDES, keyARC4 FROM users WHERE username = %s",
            (username,),
        )
        result = cursor.fetchall()

        if result:
            user_data = result[0]
            user_id, keyAES, keyDES, keyARC4 = user_data

            fullnameAES = encrypt_message_aes(keyAES, full_name)
            fullnameDES = encrypt_message_des(keyDES, full_name)
            fullnameARC4 = encrypt_message_arc4(keyARC4, full_name)
            emailAES = encrypt_message_aes(keyAES, email)
            emailDES = encrypt_message_des(keyDES, email)
            emailARC4 = encrypt_message_arc4(keyARC4, email)
            phonenumberAES = encrypt_message_aes(keyAES, phone_number)
            phonenumberDES = encrypt_message_des(keyDES, phone_number)
            phonenumberARC4 = encrypt_message_arc4(keyARC4, phone_number)
            lasteducationAES = encrypt_message_aes(keyAES, last_education)
            lasteducationDES = encrypt_message_des(keyDES, last_education)
            lasteducationARC4 = encrypt_message_arc4(keyARC4, last_education)

            end_time_enc = time.perf_counter()

            # CHECK DATA EXISTANCE
            cursor.execute("SELECT id FROM fullnames WHERE user_id = %s", (user_id,))
            existing_data = cursor.fetchone()

            if existing_data:
                # FULLNAMES
                update_data_query = """
                UPDATE fullnames
                SET fullnameAES = %s, fullnameDES = %s, fullnameARC4 = %s
                WHERE user_id = %s
                """
                update_data = (fullnameAES, fullnameDES, fullnameARC4, user_id)
                cursor.execute(update_data_query, update_data)
                # EMAILS
                update_data_query = """
                UPDATE emails
                SET emailAES = %s, emailDES = %s, emailARC4 = %s
                WHERE user_id = %s
                """
                update_data = (emailAES, emailDES, emailARC4, user_id)
                cursor.execute(update_data_query, update_data)
                # PHONENUMBERS
                update_data_query = """
                UPDATE phonenumbers
                SET phonenumberAES = %s, phonenumberDES = %s, phonenumberARC4 = %s
                WHERE user_id = %s
                """
                update_data = (phonenumberAES, phonenumberDES, phonenumberARC4, user_id)
                cursor.execute(update_data_query, update_data)
                # LASTEDUCATIONS
                update_data_query = """
                UPDATE lasteducations
                SET lasteducationAES = %s, lasteducationDES = %s, lasteducationARC4 = %s
                WHERE user_id = %s
                """
                update_data = (
                    lasteducationAES,
                    lasteducationDES,
                    lasteducationARC4,
                    user_id,
                )
                cursor.execute(update_data_query, update_data)
            else:
                # FULLNAMES
                insert_data_query = """
                INSERT INTO fullnames (
                    fullnameAES,
                    fullnameDES,
                    fullnameARC4,
                    user_id
                ) VALUES (%s, %s, %s, %s)
                """
                data = (fullnameAES, fullnameDES, fullnameARC4, user_id)
                cursor.execute(insert_data_query, data)
                # EMAILS
                insert_data_query = """
                INSERT INTO emails (
                    emailAES,
                    emailDES,
                    emailARC4,
                    user_id
                ) VALUES (%s, %s, %s, %s)
                """
                data = (emailAES, emailDES, emailARC4, user_id)
                cursor.execute(insert_data_query, data)
                # PHONENUMBERS
                insert_data_query = """
                INSERT INTO phonenumbers (
                    phonenumberAES,
                    phonenumberDES,
                    phonenumberARC4,
                    user_id
                ) VALUES (%s, %s, %s, %s)
                """
                data = (phonenumberAES, phonenumberDES, phonenumberARC4, user_id)
                cursor.execute(insert_data_query, data)
                # LASTEDUCATIONS
                insert_data_query = """
                INSERT INTO lasteducations (
                    lasteducationAES,
                    lasteducationDES,
                    lasteducationARC4,
                    user_id
                ) VALUES (%s, %s, %s, %s)
                """
                data = (lasteducationAES, lasteducationDES, lasteducationARC4, user_id)
                cursor.execute(insert_data_query, data)

            connection.commit()

            end_time_dec = time.perf_counter()

            encryption_time = end_time_enc - start_time_enc
            decryption_time = end_time_dec - end_time_enc

            flash(
                f"Data submitted successfully!\n Encryption time : {encryption_time:.10f} sec, Decryption time : {decryption_time:.10f} sec",
                "flash-success",
            )

        cursor.close()
        connection.close()

    return render_template("data_form.html")


# ? Route to decrypt and view submitted data
@app.route("/view_data")
def view_data():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("login"))

    username = session["username"]
    userID = session["userID"]
    print("test")

    connection = create_connection()
    cursor = connection.cursor()

    query = "SELECT keyAES, keyDES, keyARC4 FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    keyAES, keyDES, keyARC4 = result

    # FULLNAMES
    cursor.execute("SELECT fullnameAES, fullnameDES, fullnameARC4 FROM fullnames WHERE user_id = %s", (userID,))
    result = cursor.fetchall()
    user_data = result[0]
    fullnameAES, fullnameDES, fullnameARC4 = user_data
    full_name_aes = decrypt_message_aes(keyAES, fullnameAES)
    full_name_des = decrypt_message_des(keyDES, fullnameDES)
    full_name_arc4 = decrypt_message_arc4(keyARC4, fullnameARC4)

    # EMAILS
    cursor.execute("SELECT emailAES, emailDES, emailARC4 FROM emails WHERE user_id = %s", (userID,))
    result = cursor.fetchall()
    user_data = result[0]
    emailAES, emailDES, emailARC4 = user_data
    email_aes = decrypt_message_aes(keyAES, emailAES)
    email_des = decrypt_message_des(keyDES, emailDES)
    email_arc4 = decrypt_message_arc4(keyARC4, emailARC4)

    # PHONENUMBERS
    cursor.execute("SELECT phonenumberAES, phonenumberDES, phonenumberARC4 FROM phonenumbers WHERE user_id = %s", (userID,))
    result = cursor.fetchall()
    user_data = result[0]
    phonenumberAES, phonenumberDES, phonenumberARC4 = user_data
    phone_number_aes = decrypt_message_aes(keyAES, phonenumberAES)
    phone_number_des = decrypt_message_des(keyDES, phonenumberDES)
    phone_number_arc4 = decrypt_message_arc4(keyARC4, phonenumberARC4)

    # LASTEDUCATIONS
    cursor.execute("SELECT lasteducationAES, lasteducationDES, lasteducationARC4 FROM lasteducations WHERE user_id = %s", (userID,))
    result = cursor.fetchall()
    user_data = result[0]
    lasteducationAES, lasteducationDES, lasteducationARC4 = user_data
    last_education_aes = decrypt_message_aes(keyAES, lasteducationAES)
    last_education_des = decrypt_message_des(keyDES, lasteducationDES)
    last_education_arc4 = decrypt_message_arc4(keyARC4, lasteducationARC4)


    return render_template("view_data.html", 
        full_name_aes = full_name_aes, email_aes = email_aes, phone_number_aes = phone_number_aes, last_education_aes = last_education_aes,
        full_name_des = full_name_des, email_des = email_des, phone_number_des = phone_number_des, last_education_des = last_education_des,
        full_name_arc4 = full_name_arc4, email_arc4 = email_arc4, phone_number_arc4 = phone_number_arc4, last_education_arc4 = last_education_arc4
    )


if __name__ == "__main__":
    app.run(debug=True)
