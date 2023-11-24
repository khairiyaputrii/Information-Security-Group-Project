from flask import Blueprint, Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
from backend.database.db import create_connection
from backend.functions.meta import (
    encrypt_message_aes,
    decrypt_message_aes,
    encrypt_message_des,
    decrypt_message_des,
    encrypt_message_arc4,
    decrypt_message_arc4,
)

decryption = Blueprint("decryption", __name__)

@decryption.route("/view_data")
def view_data():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("authentication.login"))

    username = session["username"]
    userID = session["userID"]

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