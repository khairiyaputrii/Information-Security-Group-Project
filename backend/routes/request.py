from flask import Blueprint, Flask, render_template, request, redirect, url_for, flash, session
from backend.database.db import create_connection

request = Blueprint("request", __name__)

@request.route("/request")
def req():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("authentication.login"))

    username = session["username"]
    userID = session["userID"]

    connection = create_connection()
    cursor = connection.cursor()
    
    query = """
    SELECT id, username
    FROM users
    """
    cursor.execute(query)
    result = cursor.fetchall()
    
    return render_template("request.html", result=result)

@request.route("/request-to", methods=["POST"])
def req_to():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("authentication.login"))

    username = session["username"]
    userID = session["userID"]
    user_destination = request.form["user_destination"]

    connection = create_connection()
    cursor = connection.cursor()
    
    insert_data_query = """
    INSERT INTO request (
        source_id,
        destination_id
    ) VALUES (%s, %s)
    """
    data = (username, user_destination)
    cursor.execute(insert_data_query, data)

    connection.commit()
    cursor.close()
    connection.close()
    
    return render_template("request.html")