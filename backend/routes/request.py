from flask import Blueprint, render_template, request as flask_request, redirect, url_for, flash, session
from backend.database.db import create_connection

request_blueprint = Blueprint("request", __name__)

@request_blueprint.route("/request", methods=["GET", "POST"])
def req():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("authentication.login"))

    username = session["username"]
    userID = session["userID"]

    connection = create_connection()
    cursor = connection.cursor()
    
    if flask_request.method == "POST":
        user_destination = flask_request.form["user_destination"]

        connection = create_connection()
        cursor = connection.cursor()
        insert_data_query = """
            INSERT INTO request (
                sourceID,
                destinationID
            ) VALUES (%s, %s)
        """
        data = (userID, user_destination)
        cursor.execute(insert_data_query, data)

    query = """
    SELECT id, username
    FROM users
    WHERE id != %s
    """
    cursor.execute(query, (userID,))
    result = cursor.fetchall()

    query_two = """
    SELECT id
    FROM request
    """
    cursor.execute(query_two)
    result_two = cursor.fetchall()

    connection.commit()
    cursor.close()
    connection.close()
    
    return render_template("request.html", result=result, result_two=result_two, current_user= userID)
