from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import countries, login_required, login_not_required, greet_user

# Configure application
app = Flask(__name__)

# Use sqlite database with cs50
db = SQL("sqlite:///exchange.db")

# Configure session
# https://flask-session.readthedocs.io/en/latest/quickstart.html
# https://flask-session.readthedocs.io/en/latest/config.html
SESSION_TYPE = "filesystem"
app.config.from_object(__name__)
Session(app)

# Auto refresh the app for development use
app.config["TEMPLATES_AUTO_RELOAD"] = True



@app.route("/")
def index():
    return render_template("index.html", greet=greet_user())



@app.route("/register", methods=["GET", "POST"])
@login_not_required
def register():
    # Register a user

    # Collect user's inputs
    user_username = request.form.get("username")
    user_email = request.form.get("email")
    user_password = request.form.get("password")
    user_confirm = request.form.get("confirmpass")
    user_country = request.form.get("countries")
    user_city = request.form.get("city")
    
    # Query the all usernames in database
    users = db.execute("SELECT username FROM users WHERE username = ?;", user_username)
    emails = db.execute("SELECT email FROM users WHERE email = ?;", user_email)

    # INSERT the user's inputs in the database if request method is POST
    if request.method == "POST":

        # Ensure if username is already exists in the database
        for i in range(len(users)):
            if users[i]["username"] == user_username:
                flash("The username you choose already exists.")
                return redirect("/register")

        # Ensure if user filled Username field
        if len(user_username) < 1:
            flash("Please fill the \"Username\" field.")
            return redirect("/register")
        
        # Ensure if user filled email field
        if len(user_email) < 1:
            flash("Please fill the \"E-mail\" field.")
            return redirect("/register")
        
        # Ensure if user input a valid email
        if "@" not in user_email:
            flash("Please choose a valid E-mail address.")
            return redirect("/register")
        
        # Ensure if email is not already exists in the database
        for i in range(len(emails)):
            if emails[i]["email"] == user_email:
                flash("The email you entered already exists.")
                return redirect("/register")
        
        # Ensure if user filled password field
        if len(user_password) < 1:
            flash("Please fill the \"Password\" field.")
            return redirect("/register")
        
        # Ensure if user filled password confirmation field
        if len(user_confirm) < 1:
            flash("Please fill the \"Confirm Password\" field.")
            return redirect("/register")
        
        # Ensure if password and confirmation is the same
        if user_password != user_confirm:
            flash("\"Password\" and \"Confirm Password\" fields didn't match.")
            return redirect("/register")
        
        # Ensure if password length minimum 6 and maximum 21 characters
        if len(user_password) < 6 or len(user_password) > 21:
            flash("The password must be between 6 and 21 characters in length.")
            return redirect("/register")

        # Ensure if user choose the correct country
        if user_country not in countries():
            flash("Please choose a country.")
            return redirect("/register")
        
        # Ensure if user filled password field
        if len(user_city) < 1:
            flash("Please fill the \"City\" field.")
            return redirect("/register")
        
        # Hash the user's password input
        hashed_password = generate_password_hash(user_password, method='sha256', salt_length=16)

        # INSERT user's inputs in database
        db.execute("INSERT INTO users (username, email, hash, country, city) VALUES (?, ?, ?, ? ,?);", user_username, user_email, hashed_password, user_country, user_city.lower())

        # Flash the success
        flash("You have successfully registered! You are ready to log in.")

        # Redirect user to home page
        return redirect("/login")
        
    else:
        return render_template("register.html", countries=countries())



@app.route("/login", methods=["GET", "POST"])
@login_not_required
def login():
    # User log in

    # Collect user's inputs
    user_username = request.form.get("username")
    user_password = request.form.get("password")

    # Query the all usernames in database for username
    users = db.execute("SELECT * FROM users WHERE username = ?;", user_username)

    if request.method == "POST":

        # Ensure if username field filled
        if len(user_username) < 1:
            flash("Please insert your username.")
            return redirect("/login")

        # Ensure if password field filled
        if len(user_password) < 1:
            flash("Please insert your password.")
            return redirect("/login")

        # Ensure username exists and password is correct
        if len(users) < 1 or not check_password_hash(users[0]["hash"], user_password):
            flash("The username and/or password you entered is incorrect.")
            return redirect("/login")
        
        # Clear all users
        session.clear()

        # Remember which user has logged in
        session["user_id"] = users[0]["id"]

        # Flash the success
        flash("Successfully logged in.")

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")



@app.route("/logout")
def logout():
    # User log out

    # Clear all users
    session.clear()

    # Redirect user to index.html page
    return redirect("/")



@app.route("/exchange")
@login_required
def exchange():
    ...
    # TODO



@app.route("/myprofile", methods=["GET", "POST"])
@login_required
def myprofile():
    # take user informations from data to variables
    date = db.execute("SELECT date FROM users WHERE id = ?", session["user_id"])[0]["date"]
    fname = db.execute("SELECT fname FROM users WHERE id = ?", session["user_id"])[0]["fname"]
    lname = db.execute("SELECT lname FROM users WHERE id = ?", session["user_id"])[0]["lname"]
    uname = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    email = db.execute("SELECT email FROM users WHERE id = ?", session["user_id"])[0]["email"]
    country = db.execute("SELECT country FROM users WHERE id = ?", session["user_id"])[0]["country"]
    city = db.execute("SELECT city FROM users WHERE id = ?", session["user_id"])[0]["city"].title()
    address = db.execute("SELECT address FROM users WHERE id = ?", session["user_id"])[0]["address"]
    phone = db.execute("SELECT phone FROM users WHERE id = ?", session["user_id"])[0]["phone"]

    if request.method == "POST":
        ...
        # TODO
    else:
        return render_template("myprofile.html", greet=greet_user(), date=date, fname=fname, lname=lname, username=uname, email=email, user_country=country, countries=countries(), city=city, address=address, phone=phone)
