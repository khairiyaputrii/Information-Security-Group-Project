from flask import Blueprint, Flask, render_template, request, redirect, url_for, flash, session

root = Blueprint("root", __name__)

@root.route("/")
def default():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("authentication.login"))
    return redirect(url_for("root.home"))

@root.route("/home")
def home():
    if "username" not in session:
        flash("You must log in first to access this page.", "flash-warning")
        return redirect(url_for("authentication.login"))
    username = session["username"]
    return render_template("home.html", username=username)