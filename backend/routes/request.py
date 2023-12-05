from flask import Blueprint, render_template, request as flask_request, redirect, url_for, flash, session
from backend.database.db import create_connection
from backend.functions.data_fetching import (
    create_request,
    check_existing_request,
    fetch_users,
    fetch_existing_requests,
    fetch_approved_users
)
from backend.functions.asymmetric import (
    encrypt_asymmetric,
    decrypt_asymmetric
)

request_blueprint = Blueprint("request", __name__)

@request_blueprint.route("/request", methods=["GET", "POST"])
def req():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("authentication.login"))

    user_id = session["userID"]
    username = session["username"]

    user_destination = None;
    user_who_req = None;

    if flask_request.method == "POST":
        try:
            user_destination = flask_request.form["user_destination"]
        except:
            print("user_destination is null")
        try:
            user_who_req = flask_request.form["user_who_req"]
        except:
            print("user_who_req is null")
        try:
            user_req_view = flask_request.form["user_req_view"]
        except:
            print("user_req_view is null")

        if user_destination:
            if user_id == user_destination:
                flash("You cannot request to the same destination.", "flash-danger")
            else:
                existing_request = check_existing_request(user_id, user_destination)
                if existing_request:
                    flash("You have already requested to this destination.", "flash-danger")
                else:
                    create_request(user_id, username, user_destination)
                    flash("Request sent successfully.", "flash-success")
        elif user_who_req:
            connection = create_connection()
            cursor = connection.cursor()

            query_check = """
                SELECT cipherText
                FROM request
                WHERE destinationID = %s and sourceID = %s
            """
            cursor.execute(query_check, (user_id, user_who_req))
            there_is_cipher = cursor.fetchone()

            if not there_is_cipher[0]:
                query = """
                    SELECT keyAES
                    FROM users
                    WHERE id = %s
                """   
                cursor.execute(query, (user_id,))
                symmetricKey = cursor.fetchone()

                query_get_public = """
                    SELECT keyAsyPublic
                    FROM users
                    WHERE id = %s
                """
                cursor.execute(query_get_public, (user_who_req,))
                asymmetricPublicKey = cursor.fetchone()

                ciphertext_result = encrypt_asymmetric(asymmetricPublicKey, symmetricKey)

                query_insert_cipher = """
                    UPDATE request
                    SET cipherText = %s
                    WHERE destinationID = %s and sourceID = %s
                """
                cursor.execute(query_insert_cipher, (ciphertext_result, user_id, user_who_req))
                flash("Request Approved.", "flash-success")

                connection.commit()
                cursor.close()
                connection.close()
            else:
                flash("You've already approved this.", "flash-success")
        else:
            print(user_req_view)
            connection = create_connection()
            cursor = connection.cursor()
            
            query_get_cipher = """
                SELECT cipherText
                FROM request
                WHERE destinationID = %s and sourceID = %s
            """   
            cursor.execute(query_get_cipher, (user_id, user_req_view,))
            getCipherText = cursor.fetchone()

            query_get_private = """
                SELECT keyAsyPrivate
                FROM users
                WHERE id = %s
            """   
            cursor.execute(query_get_private, (user_req_view,))
            getPrivateKey = cursor.fetchone()

            plainText = decrypt_asymmetric(getPrivateKey[0], getCipherText[0])
            print(plainText)

            connection.commit()
            cursor.close()
            connection.close()

    result = fetch_users(user_id)
    result_two = fetch_existing_requests(user_id)
    result_three = fetch_approved_users(user_id)

    return render_template("request.html", result=result, result_two=result_two, result_three=result_three, current_user=user_id)