from flask import Blueprint, Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
from backend.database.db import create_connection
from backend.functions.meta import (
    encrypt_message_aes,
    encrypt_message_des,
    encrypt_message_arc4,
)
import time

encryption = Blueprint("encryption", __name__)

@encryption.route("/data_form", methods=["GET", "POST"])
def data_form():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("authentication.login"))

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

            # Commit only once after handling the existing or non-existing data
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

    return render_template("data_form.html")