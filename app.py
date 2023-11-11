import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import countries, login_required, login_not_required, greet_user, allowed_file, profile_picture, message_notification, offer_notification


# Configure application
app = Flask(__name__)

# Set a secret key
app.secret_key = "justrandombyteshere"

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



@app.route("/", methods=["GET", "POST"])
def index():
    # Show all books, search

    if request.method == "POST":
        # Search button
        ...

    # Redirect to clicked book or user / show all books
    else:
        # Query all available books
        all_books = db.execute("SELECT (users.id) AS userid, username, (books.id) AS bookid, title, author, condition, image, strftime('%m/%d/%Y %H:%M', books.date) AS date FROM books JOIN users ON books.user_id = users.id INNER JOIN images ON books.id = images.book_id WHERE is_offered = 0 AND is_available = 1 GROUP BY books.id, images.book_id ORDER BY RANDOM();")

        return render_template("index.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), all_books=all_books)



# https://flask.palletsprojects.com/en/3.0.x/quickstart/#url-building
@app.route("/book/<int:books_id><string:books_name>", methods=["GET", "POST"])
@login_required
def book(books_id, books_name):

    # Show book details
    book_details = db.execute("SELECT books.user_id, (books.id) AS bookid, title, author, condition, description, strftime('%m/%d/%Y %H:%M', books.date) AS date, is_offered, is_available FROM books JOIN users ON books.user_id = users.id WHERE books.id = ?", books_id)

    conditions = [
        "As new",
        "Fine",
        "Very good",
        "Good",
        "Fair",
        "Poor",
        "Ex-library",
        "Book club",
        "Binding copy"
        ]
    
    if request.method == "POST":
        # Book offering inputs
        # Collect user's data from exchange.html template
        img = request.files.getlist("image")
        user_title = request.form.get("book_title")
        user_author = request.form.get("book_author").lower()
        user_condition = request.form.get("conditions")
        user_description = request.form.get("description")

        # Lowercase the user inputs if not None
        if user_condition != None:
            user_condition.lower()
        if user_description != None:
            user_description.lower()

        # Ensure if user filled title field
        if not user_title:
            flash("Please fill the \"Book Title\" field.")
            return redirect(f"/book/{books_id}{books_name}")
        
        # Ensure if user filled author field
        if not user_author:
            flash("Please fill the \"Book Author\" field.")
            return redirect(f"/book/{books_id}{books_name}")
        
        # Ensure if user enters right condition
        if user_condition != None and user_condition not in conditions:
            flash("Invalid condition.")
            return redirect(f"/book/{books_id}{books_name}")

        # Keep user description None instead of '' for jinja usage
        if user_description == '':
            user_description = None

        # Insert book informations to database's books table as offer
        db.execute("INSERT INTO books (user_id, title, author, condition, description, is_offered) VALUES (?, ?, ?, ?, ?, ?);", session["user_id"], user_title.lower(), user_author, user_condition, user_description, 1)

        # Insert offer informations to database's offers table
        offerer_book = db.execute("SELECT id FROM books WHERE user_id = ? AND is_offered = ? ORDER BY id DESC;", session["user_id"], 1)[0]["id"]
        receiver = db.execute("SELECT user_id FROM books WHERE id = ?;", books_id)[0]["user_id"]
        db.execute("INSERT INTO offers (offerer, offerer_book, receiver, receiver_book) VALUES (?, ?, ?, ?);", session["user_id"], offerer_book, receiver, books_id)

        
        # Iterate over the input image(s)
        for i in range(len(img)):

            # Save as an empty log if user not input an image
            if img[i].filename == '':
                empty_book_id = db.execute("SELECT id FROM books WHERE id = ?;", offerer_book)[0]["id"]
                db.execute("INSERT INTO images (user_id, book_id) VALUES (?, ?);", session["user_id"], empty_book_id)
                flash(f"You're successfully offered \"{user_title.title()}\" book for \"{book_details[0]['title'].title()}\" book. You can offer more books!")
                return redirect(f"/book/{books_id}{books_name}")
        
            # Ensure if input file format is right
            elif img[i].filename != '' and allowed_file(img[i].filename) == False:
                flash("Only .jpg, .jpeg, .png and .gif file formats allowed.")
                return redirect(f"/book/{books_id}{books_name}")
            
            # Save the image(s)
            elif img[i].filename != '' and allowed_file(img[i].filename) == True:

                # Save the latest image id number in a variable
                img_id = db.execute("SELECT id FROM images ORDER BY id DESC;")

                # Create a directory for book images if not exists
                if os.path.exists(f"static/pictures/{session['user_id']}/bp") == False:
                    os.makedirs(f"static/pictures/{session['user_id']}/bp")
                
                # Determine the image saving path
                upload_path = f'{os.getcwd()}/static/pictures/{session["user_id"]}/bp'

                # Rename image(s) name(s)
                if len(img_id) < 1:
                    img[i].filename = f"1.{img[i].filename.rsplit('.', 1)[1].lower()}"
                else:
                    img[i].filename = f'{img_id[0]["id"] + 1}.{img[i].filename.rsplit(".", 1)[1].lower()}'

                # Sanitize the file to save
                secure = secure_filename(img[i].filename)

                # Select user's latest book id
                book_id = db.execute("SELECT id FROM books WHERE user_id = ? AND title = ? AND author = ? AND is_offered = ? ORDER BY id DESC;", session["user_id"], user_title.lower(), user_author, 1)[0]["id"]
                

                # Save the image in directory
                img[i].save(os.path.join(upload_path, secure))
                # Save the image in database
                db.execute("INSERT INTO images (user_id, book_id, image) VALUES (?, ?, ?);", session["user_id"], book_id, secure)
            
        # Flash the success and redirect to book.html
        flash(f"You're successfully offered \"{user_title.title()}\" book for \"{book_details[0]['title'].title()}\" book. You can offer more books!")
        return redirect(f"/book/{books_id}{books_name}")
    else:
        # Show user informations of main book owner
        user_details = db.execute("SELECT (users.id) AS userid, country, city, username, picture, strftime('%m/%d/%Y %H:%M', users.date) AS date from users JOIN books ON users.id = books.user_id WHERE books.id = ?", books_id)

        # Show book images of main book
        book_images = db.execute("SELECT image FROM images WHERE book_id = ?", books_id)

        # Show other offers
        offered_books = db.execute("SELECT books.user_id, books.id, title, author, condition, description, image, strftime('%m/%d/%Y %H:%M', books.date) AS date FROM books LEFT JOIN images ON books.id = images.book_id JOIN offers ON books.id = offers.offerer_book WHERE books.is_available = 1 AND books.is_offered = 1 AND offers.receiver_book = ? GROUP BY books.id ORDER BY books.id DESC;", books_id)

        # Take user's own informations to restriction on jinja
        user = db.execute("SELECT fname, lname,address, phone FROM users WHERE id = ?", session["user_id"])
        
        return render_template("book.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), books_id=books_id, books_name=books_name, book_images=book_images, offered_books=offered_books, book_details=book_details, conditions=conditions, user_details=user_details, user=user)



@app.route("/offered/<int:offered_id><string:offered_name>", methods=["GET", "POST"])
@login_required
def offered(offered_id, offered_name):
    # Display, remove, accept/decline offered books

    # Take previous book in a variable
    prev_book = db.execute("SELECT books.title, books.id FROM books JOIN offers ON books.id = receiver_book WHERE receiver_book IN (SELECT receiver_book FROM offers WHERE offerer_book = ?) AND books.is_offered = 0 AND books.is_available = 1 GROUP BY books.id;", offered_id)

    if request.method == "POST":
        # Collect buttons informations in a variable
        offer_remove = request.form.get("offer_remove")
        offer_accept = request.form.get("offer_accept")
        offer_decline = request.form.get("offer_decline")

        accepted = 1

        # Ensure if remove button points the right book
        if offer_remove and int(offer_remove) != offered_id:
            flash("Invalid book to remove.")
            return redirect(f"/offered/{offered_id}{offered_name}")
        
        # Ensure if accept button points the right book
        if offer_accept and int(offer_accept) != offered_id:
            flash("Invalid book to accept.")
            return redirect(f"/offered/{offered_id}{offered_name}")
        
        # Ensure if decline button points the right book
        if offer_decline and int(offer_decline) != offered_id:
            flash("Invalid book to decline.")
            return redirect(f"/offered/{offered_id}{offered_name}")
        
        # Remove the offered book if button points to the right book
        if offer_remove and int(offer_remove) == offered_id:
            db.execute("UPDATE books SET is_available = ?, is_accepted = ?, is_readed = ? WHERE id = ?;", 0, -abs(accepted), 1, offered_id)
            flash("Your offer successfully removed.")
            return redirect(f"/book/{prev_book[0]['id']}{prev_book[0]['title']}")

        # Decline the offered book if button points to the right book
        if offer_decline and int(offer_decline) == offered_id:
            db.execute("UPDATE books SET is_available = ?, is_accepted = ?, is_readed = ? WHERE id = ?;", 0, -abs(accepted), 1, offered_id)
            flash("Offer rejected.")
            return redirect(f"/book/{prev_book[0]['id']}{prev_book[0]['title']}")
        
        # Look up the availability of the accepted book
        is_available = db.execute("SELECT is_available FROM books WHERE id = ?;", offered_id)
        
        # Accept the offered book if button points to the right book
        if offer_accept and int(offer_accept) == offered_id and is_available[0]["is_available"] == 1:

            # Query the all informations about offeror and offeree
            offerer_informations = db.execute("SELECT username, fname, lname, address, phone, email, country, city FROM users WHERE id IN (SELECT offerer FROM offers WHERE offerer_book = ?);", offered_id)
            o_fname = offerer_informations[0]["fname"]
            o_lname = offerer_informations[0]["lname"]
            o_address = offerer_informations[0]["address"]
            o_email = offerer_informations[0]["email"]
            o_phone = offerer_informations[0]["phone"]

            receiver_informations = db.execute("SELECT fname, lname, address, phone, email, country, city FROM users WHERE id IN (SELECT receiver FROM offers WHERE offerer_book = ?);", offered_id)
            r_fname = receiver_informations[0]["fname"]
            r_lname = receiver_informations[0]["lname"]
            r_address = receiver_informations[0]["address"]
            r_email = receiver_informations[0]["email"]
            r_phone = receiver_informations[0]["phone"]

            
            # Update the accepted book and make it unavailable
            db.execute("UPDATE books SET is_available = 0, is_accepted = ? WHERE id = ?;", accepted, offered_id)
            # Update the other offered books are not accepted and make them unavailable
            db.execute("UPDATE books SET is_available = 0, is_accepted = ? WHERE id IN (SELECT offerer_book FROM offers WHERE receiver_book IN (SELECT receiver_book FROM offers WHERE offerer_book = ?));", -abs(accepted), offered_id)
            # Update the main book and make it unavailable
            db.execute("UPDATE books SET is_available = 0 WHERE id IN (SELECT receiver_book FROM offers WHERE offerer_book = ?) AND is_available = 1 AND is_offered = 0;", offered_id)


            # Set an auto-message to send contact informations to each other
            # Query the offeror and offeree's user id
            sender = db.execute("SELECT receiver FROM offers WHERE offerer_book = ?", offered_id)[0]["receiver"]
            receiver = db.execute("SELECT offerer FROM offers WHERE offerer_book = ?", offered_id)[0]["offerer"]
            # Query the offeror and offeree's book titles
            sender_book = db.execute("SELECT title FROM books WHERE id IN (SELECT receiver_book FROM offers WHERE offerer_book = ?)", offered_id)[0]["title"]
            receiver_book = db.execute("SELECT title FROM books WHERE id IN (SELECT offerer_book FROM offers WHERE offerer_book = ?)", offered_id)[0]["title"]
            # Create an auto message to send each other
            sender_message = f"Hello, {o_fname.title()}! I accepted the \"{receiver_book.title()}\" book you offered me for my \"{sender_book.title()}\" book.\nHere is my contact informations:\nMy Address: {r_address.title()}, {receiver_informations[0]['city'].title()} / {receiver_informations[0]['country'].title()} \nMy email: {r_email} \nMy phone number: {r_phone}\n{r_fname.title()} {r_lname.title()}"
            receiver_message = f"Hello, {r_fname.title()}! You accepted my \"{receiver_book.title()}\" book for your \"{sender_book.title()}\" book.\nLet's exchange the books. Here is my contact informations:\nMy Address: {o_address.title()}, {offerer_informations[0]['city'].title()} / {offerer_informations[0]['country'].title()} \nMy email: {o_email} \nMy phone number: {o_phone}\n{o_fname.title()} {o_lname.title()}"
            # INSERT the message in the database
            db.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?);", sender, receiver, sender_message)
            db.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?);", receiver, sender, receiver_message)

            # Flash the success and redirect user
            flash("Congratulations! Don't forget to check your inbox!")
            return redirect("/")
    else:
        # Take offerer user informations from database
        offerer_user = db.execute("SELECT users.id, username, country, city, picture, strftime('%m/%d/%Y %H:%M', users.date) AS date FROM users JOIN offers ON users.id = offers.offerer WHERE offers.offerer_book = ?;", offered_id)

        # Take receiver user informations from database
        receiver_user = db.execute("SELECT receiver FROM offers WHERE offerer_book = ?;", offered_id)

        # Take offerer user's book informations from database
        offerer_book = db.execute("SELECT * FROM books JOIN offers ON books.id = offers.offerer_book WHERE offerer_book = ?;", offered_id)

        # Take offered book's images from database
        book_images = db.execute("SELECT * FROM images WHERE book_id = ?;", offered_id)

        return render_template("offered.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), offered_id=offered_id, offered_name=offered_name, offerer_user=offerer_user, receiver_user=receiver_user, offerer_book=offerer_book, book_images=book_images)




@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    # Display messages and UPDATE database

    # Set as readed when user click to message when method is POST
    if request.method == "POST":
        readed = request.form.get("readed")
        
        # Ensure if clicked to not an empty input
        if not readed:
            flash("Invalid message.")
            return redirect("/messages")
        
        # UPDATE database and set as readed when user click to a message
        db.execute("UPDATE messages SET is_readed = 1 WHERE receiver = ? AND sender IN (SELECT id FROM users WHERE username = ?);", session["user_id"], readed)
        return redirect(f"/message/{readed}")

    else:
        # Display all received messages
        messages = db.execute("SELECT users.username, COUNT(CASE WHEN is_readed = 0 THEN 1 END) AS count FROM messages JOIN users ON sender = users.id WHERE receiver = ? GROUP BY sender ORDER BY messages.id DESC;", session["user_id"])
        return render_template("messages.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), messages=messages)



@app.route("/message/<username>")
@login_required
def message(username):
    # Show the received auto messages
    messages = db.execute("SELECT * FROM messages WHERE sender IN (SELECT id FROM users WHERE username = ?) AND receiver = ?;", username, session["user_id"])
    return render_template("message.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), username=username, messages=messages)



@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    # Show the received offers

    # Query the database for user's all taken offers
    offers = db.execute("SELECT offerer_book.id AS offerer_book_id, offerer.username AS offerer_username, offerer_book.title AS offerer_book_title, receiver.username AS receiver_username, receiver_book.title AS receiver_book_title, COUNT(CASE WHEN offerer_book.is_readed = 0 THEN 1 END) AS count, strftime('%m/%d/%Y %H:%M', offerer_book.date) AS date FROM offers JOIN users AS offerer ON offers.offerer = offerer.id JOIN books AS offerer_book ON offers.offerer_book = offerer_book.id JOIN users AS receiver ON offers.receiver = receiver.id JOIN books AS receiver_book ON offers.receiver_book = receiver_book.id WHERE offerer_book.is_offered = 1 AND offerer_book.is_available = 1 AND receiver = ? GROUP BY offerer_book ORDER BY offerer_book.date DESC;", session["user_id"])

    if request.method == "POST":
        # Collect the user's inputs in the variables
        choose_offerer = request.form.get("offerer")
        choose_offerer_book_id = request.form.get("offerer_book_id")
        choose_offerer_book_title = request.form.get("offerer_book_title")

        # Ensure if user clicked to the right offer
        for i in range(len(offers)):
            if choose_offerer in offers[i]["offerer_username"] and str(choose_offerer_book_id) in str(offers[i]["offerer_book_id"]) and choose_offerer_book_title in offers[i]["offerer_book_title"]:
                db.execute("UPDATE books SET is_readed = ? WHERE id = ?", 1, choose_offerer_book_id)
                return redirect(f"/offered/{choose_offerer_book_id}{choose_offerer_book_title}")
        
        # Throw error in any invalid input
        flash("Invalid selection.")
        return redirect("/notifications")
    else:
        
        return render_template("notifications.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), offers=offers)



@app.route("/user/<username>")
@login_required
def user(username):
    # Show clicked user and book informations
    
    # Query the user informations
    user = db.execute("SELECT id, username, country, city, picture, strftime('%m/%d/%Y %H:%M', users.date) AS date FROM users WHERE username = ?", username)

    # Query the user's books
    books = db.execute("SELECT (books.id) AS id, title, author, condition, strftime('%m/%d/%Y %H:%M', books.date) AS date, image FROM books JOIN images ON books.id = images.book_id WHERE books.user_id IN (SELECT id FROM users WHERE username = ?) AND is_offered = 0 AND is_available = 1 GROUP BY books.id;", username)

    return render_template("user.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), user=user, books=books)



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
        if not user_username:
            flash("Please insert your username.")
            return redirect("/login")

        # Ensure if password field filled
        if not user_password:
            flash("Please insert your password.")
            return redirect("/login")

        # https://cs50.harvard.edu/x/2023/psets/9/finance/
        # Ensure username exists and password is correct
        if not users or not check_password_hash(users[0]["hash"], user_password):
            flash("The username and/or password you entered is incorrect.")
            return redirect("/login")
        
        # https://cs50.harvard.edu/x/2023/psets/9/finance/
        # Clear all users
        session.clear()

        # https://cs50.harvard.edu/x/2023/psets/9/finance/
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
    
    # Query the all users in database
    all_users = db.execute("SELECT * FROM users;")

    # INSERT the user's inputs in the database if request method is POST
    if request.method == "POST":

        # Ensure if user filled Username field
        if not user_username:
            flash("Please fill the \"Username\" field.")
            return redirect("/register")

        # Ensure if username is already exists in the database
        for i in range(len(all_users)):
            if user_username in all_users[i]["username"]:
                flash("The username you choose already exists.")
                return redirect("/register")
        
        # Ensure if user filled email field
        if not user_email:
            flash("Please fill the \"E-mail\" field.")
            return redirect("/register")
        
        # Ensure if user input a valid email
        if "@" not in user_email:
            flash("Please choose a valid E-mail address.")
            return redirect("/register")
        
        # Ensure if email is not already exists in the database
        for i in range(len(all_users)):
            if user_email in all_users[i]["email"]:
                flash("The email you entered already exists.")
                return redirect("/register")
        
        # Ensure if user filled password field
        if not user_password:
            flash("Please fill the \"Password\" field.")
            return redirect("/register")
        
        # Ensure if user filled password confirmation field
        if not user_confirm:
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
        if not user_city:
            flash("Please fill the \"City\" field.")
            return redirect("/register")
        
        # Hash the user's password input
        hashed_password = generate_password_hash(user_password, method='sha256', salt_length=16)

        # INSERT user's inputs in database
        db.execute("INSERT INTO users (username, email, hash, country, city) VALUES (?, ?, ?, ? ,?);", user_username, user_email, hashed_password, user_country.lower(), user_city.lower())

        # Flash the success
        flash("You have successfully registered! You are ready to log in.")

        # Redirect user to home page
        return redirect("/login")
        
    else:
        return render_template("register.html", countries=countries())



@app.route("/myprofile", methods=["GET", "POST"])
@login_required
def myprofile():
    # Collect user informations from database to variables
    all_users = db.execute("SELECT * FROM users;")
    database = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])
    date = db.execute("SELECT strftime('%m,%d, %Y', date) AS date FROM users WHERE id = ?;", session["user_id"])[0]["date"]
    fname = database[0]["fname"]
    lname = database[0]["lname"]
    uname = database[0]["username"]
    email = database[0]["email"]
    password = database[0]["hash"]
    country = database[0]["country"]
    city = database[0]["city"]
    address = database[0]["address"]
    phone = database[0]["phone"]

    if request.method == "POST":
        # Collect user's inputs in a variable
        input_fname = request.form.get("fname")
        input_lname = request.form.get("lname")
        input_uname = request.form.get("username")
        input_email = request.form.get("email")
        input_password = request.form.get("password")
        input_new_password = request.form.get("newpass")
        input_confirm_password = request.form.get("confirmpass")
        input_country = request.form.get("countries")
        input_city = request.form.get("city")
        input_address = request.form.get("address")
        input_phone = request.form.get("phone")

        # Update first name if input field not empty
        if len(input_fname) > 0:
            db.execute("UPDATE users SET fname = ? WHERE id = ?;", input_fname.lower(), session["user_id"])

        # Update last name if input field not empty
        if len(input_lname) > 0:
            db.execute("UPDATE users SET lname = ? WHERE id = ?;", input_lname.lower(), session["user_id"])

        # Ensure if username is already exists in the database and update if not exists
        if len(input_uname) > 0:
            for i in range(len(all_users)):
                if input_uname in all_users[i]["username"]:
                    flash("The username you choose already exists.")
                    return redirect("/myprofile")
                elif input_uname not in all_users[i]["username"]:
                    db.execute("UPDATE users SET username = ? WHERE id = ?;", input_uname, session["user_id"])

        # Ensure if email is already exists in the database and update if not exists
        if len(input_email) > 0:
            for i in range(len(all_users)):
                if input_uname in all_users[i]["email"]:
                    flash("The email you entered already exists.")
                    return redirect("/myprofile")
                elif input_email not in all_users[i]["email"]:
                    db.execute("UPDATE users SET email = ? WHERE id = ?;", input_email, session["user_id"])
        
        # Save the new password if user inputs
        if len(input_password) > 0:
            # Ensure if user knows their own current password
            if not check_password_hash(password, input_password):
                flash("Invalid password.")
                return redirect("/myprofile")
            # Chack if new password is between 6-21 characters length
            elif len(input_new_password) < 6 or len(input_new_password) > 21:
                flash("The new password must be between 6 and 21 characters in length.")
                return redirect("/myprofile")
            # Chack if new password matches with confirmation
            elif input_new_password != input_confirm_password:
                flash("\"Your New Password\" and \"Confirm New Password\" fields didn't match.")
                return redirect("/myprofile")
            else:
                hashed_password = generate_password_hash(input_password, method='sha256', salt_length=16)
                db.execute("UPDATE users SET hash = ? WHERE id = ?;", hashed_password, session["user_id"])
        

        # Save the new country if user inputs
        if input_country != country:
        # Ensure if user choose the correct country
            if input_country not in countries():
                flash("Please choose a country in the list.")
                return redirect("/myprofile")
            else:
                db.execute("UPDATE users SET country = ? WHERE id = ?;", input_country.lower(), session["user_id"])
        

        # Save the new city if user inputs
        if len(input_city) > 0:
            db.execute("UPDATE users SET city = ? WHERE id = ?;", input_city.lower(), session["user_id"])

        
        # Save the address if user inputs
        if len(input_address) > 0:
            db.execute("UPDATE users SET address = ? WHERE id = ?;", input_address.lower(), session["user_id"])
        
        
        # Save the phone number if user inputs
        if len(input_phone) > 0:
            db.execute("UPDATE users SET phone = ? WHERE id = ?;", input_phone, session["user_id"])
        

        # Show success
        flash("Your information(s) successfully updated.")
        return redirect("/myprofile")

    else:
        # Return string if there's no information in the database
        if fname != None:
            fname = fname.title()
        if lname != None:
            lname = lname.title()
        if country != None:
            country = country.title()
        if city != None:
            city = city.title()
        if address != None:
            address = address.title()
        
        return render_template("myprofile.html", greet=greet_user(), message_notification=message_notification(), offer_notification=offer_notification(), date=date, fname=fname, lname=lname, username=uname, email=email, user_country=country, countries=countries(), city=city, address=address, phone=phone, picture=profile_picture())




@app.route('/pp', methods=['POST'])
@login_required
def upload_profile_picture():
    # Save / remove user's profile picture in file system and database

    # Collect the image file to a variable
    img = request.files['image']

    # Collect the user's image from the database to a variable
    data_img = db.execute("SELECT picture FROM users WHERE id = ?;", session["user_id"])[0]["picture"]
    
    # Ensure if input is not empty
    if img.filename == '':
        flash("You didn't select your profile picture.")
        return redirect("/myprofile")
    
    # Ensure if input file format is right
    if allowed_file(img.filename) == False:
        flash("Only .jpg, .jpeg, .png and .gif file formats allowed.")
        return redirect("/myprofile")

    # Save the image file only input requirements are satisfied
    if img.filename != '' and allowed_file(img.filename) == True:

        # Determine the image saving path
        upload_path = f'{os.getcwd()}/static/pictures/{session["user_id"]}/pp'

        # Rename the input image file
        img.filename = f"user_pp.{img.filename.rsplit('.', 1)[1].lower()}"

        # Sanitize the file to save
        secure = secure_filename(img.filename)

        # Save image in directory and database if doesn't exists in database
        if data_img == None:
            # Create a directory for user's profile picture if not exists
            # https://docs.python.org/3/library/os.html
            # https://docs.python.org/3/library/os.path.html
            if os.path.exists(f"static/pictures/{session['user_id']}/pp") == False:
                os.makedirs(f"static/pictures/{session['user_id']}/pp")
            
            # Save the image in directory
            img.save(os.path.join(upload_path, secure))
            # Update the database with the new name of image
            db.execute("UPDATE users SET picture = ? WHERE id = ?;", secure, session["user_id"])
            # Flash the success and redirect to myprofile.html
            flash("Your profile picture successfully added.")
            return redirect("/myprofile")

        # Remove the previous image and save new image in directory and database
        else:
            # Delete previous image if exists
            os.remove(os.path.join(upload_path, data_img))
            # Save image in directory
            img.save(os.path.join(upload_path, secure))
            # Update database
            db.execute("UPDATE users SET picture = ? WHERE id = ?;", secure, session["user_id"])
            # Flash the success and redirect to myprofile.html
            flash("Your profile picture successfully updated.")
            return redirect("/myprofile")
    
    flash("Something went wrong. Please try again.")
    return redirect("/myprofile")




@app.route("/delete", methods=["POST"])
@login_required
def delete_myprofile():
    # Delete parts with buttons

    # Collect the data from myprofile.html
    d_fname = request.form.get("fname")
    d_lname = request.form.get("lname")
    d_address = request.form.get("address")
    d_phone = request.form.get("phone")
    d_picture = db.execute("SELECT picture FROM users WHERE id = ?;", session["user_id"])[0]["picture"]

    # Delete first name
    if d_fname != None:
        db.execute("UPDATE users SET fname = NULL WHERE id = ?;", session["user_id"])
        flash("Your name successfully deleted.")
        return redirect("/myprofile")
    # Delete last name
    if d_lname != None:
        db.execute("UPDATE users SET lname = NULL WHERE id = ?;", session["user_id"])
        flash("Your last name successfully deleted.")
        return redirect("/myprofile")
    # Delete address
    if d_address != None:
        db.execute("UPDATE users SET address = NULL WHERE id = ?;", session["user_id"])
        flash("Your address successfully deleted.")
        return redirect("/myprofile")
    # Delete phone
    if d_phone != None:
        db.execute("UPDATE users SET phone = NULL WHERE id = ?;", session["user_id"])
        flash("Your phone successfully deleted.")
        return redirect("/myprofile")
    # Delete profile picture
    if d_picture != None:
        # Determine the image path
        path = f'{os.getcwd()}/static/pictures/{session["user_id"]}/pp/{d_picture}'
        # Remove image from directory
        os.remove(path)
        # Remove image from database
        db.execute("UPDATE users SET picture = NULL WHERE id = ?;", session["user_id"])
        flash("Your profile picture successfully deleted.")
        return redirect("/myprofile")
    else:
        flash("Something went wrong. Please try again.")
        return redirect("/myprofile")



@app.route("/mybooks", methods=["GET", "POST"])
@login_required
def mybooks():
    # Show data from mybooks.html
    if request.method == "POST":

        # Collect book's id from template
        book_id = request.form.get("book")
        offer_id = request.form.get("offer")
       
        # Remove user's book
        if book_id and not offer_id:
             # Query user's all active but non-offer books
            all_books = db.execute("SELECT id FROM books WHERE is_available = 1 AND is_offered = 0 AND user_id = ?;", session["user_id"])

            # Iterate over all the books
            for i in range(len(all_books)):
                #  Ensure if the book wanted to be deleted is in the database
                if int(book_id) == all_books[i]["id"]:

                    # Update the book's offers and set them unavailable if there are any
                    db.execute("UPDATE books SET is_available = ?, is_accepted = ?, is_readed = ? WHERE id IN (SELECT offerer_book FROM offers WHERE receiver_book = ?);", 0, -1, 1, book_id)

                    # Update the book itself and set it as unavailable
                    db.execute("UPDATE books SET is_available = ? WHERE id = ?;", 0, book_id)
                    
                    # Flash the success and redirect to mybooks.html
                    flash("Book removed successfully.")
                    return redirect("/mybooks")
        
        # Remove user's offer
        elif not book_id and offer_id:
            # Query user's all active offer books
            all_offers = db.execute("SELECT id FROM books WHERE is_available = 1 AND is_offered = 1 AND user_id = ?;", session["user_id"])

            # Iterate over all offer books
            for i in range(len(all_offers)):
                if int(offer_id) == all_offers[i]["id"]:

                    # Update the offer and set it as unavailable
                    db.execute("UPDATE books SET is_available = ?, is_accepted = ?, is_readed = ? WHERE id = ?;", 0, -1, 1, offer_id)

                    # Flash the success and redirect to mybooks.html
                    flash("Offered book removed successfully.")
                    return redirect("/mybooks")

        # Show error to user in any misuse
        flash("Something went wrong. Please try again to delete your book.")
        return redirect("/mybooks")

    else:
        # Query the user's all available non-offered books
        active_books = db.execute("SELECT (books.id) AS bookid, books.user_id, title, author, condition, image, strftime('%m/%d/%Y %H:%M', books.date) AS date FROM books INNER JOIN images ON books.id = images.book_id WHERE is_offered = 0 AND is_available = 1 AND books.user_id = ? GROUP BY books.id, images.book_id;", session["user_id"])

        # Query the user's all unavailable non-offered books
        passive_books = db.execute("SELECT (books.id) AS bookid, books.user_id, title, author, condition, image, strftime('%m/%d/%Y %H:%M', books.date) AS date FROM books INNER JOIN images ON books.id = images.book_id WHERE is_offered = 0 AND is_available = 0 AND books.user_id = ? GROUP BY books.id, images.book_id;", session["user_id"])

        # Query the user's all available offered books
        active_offers = db.execute("SELECT (books.id) AS bookid, books.user_id, title, author, condition, image, strftime('%m/%d/%Y %H:%M', books.date) AS date FROM books INNER JOIN images ON books.id = images.book_id WHERE is_offered = 1 AND is_available = 1 AND books.user_id = ? GROUP BY books.id, images.book_id;", session["user_id"])

        # Query the user's all unavailable offered books
        passive_offers = db.execute("SELECT (books.id) AS bookid, books.user_id, title, author, condition, image, strftime('%m/%d/%Y %H:%M', books.date) AS date FROM books INNER JOIN images ON books.id = images.book_id WHERE is_offered = 1 AND is_available = 0 AND books.user_id = ? GROUP BY books.id, images.book_id;", session["user_id"])
        return render_template("mybooks.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), active_books=active_books, passive_books=passive_books, active_offers=active_offers, passive_offers=passive_offers)



@app.route("/exchange", methods=["GET", "POST"])
@login_required
def exchange():

    # Take condition types in a variable
    conditions = [
        "As new",
        "Fine",
        "Very good",
        "Good",
        "Fair",
        "Poor",
        "Ex-library",
        "Book club",
        "Binding copy"
        ]
    
    if request.method == "POST":

        # Collect user's data from exchange.html template
        img = request.files.getlist("image")
        user_title = request.form.get("book_title").lower()
        user_author = request.form.get("book_author").lower()
        user_condition = request.form.get("conditions")
        user_description = request.form.get("description")

        # Lowercase the user inputs if not None
        if user_condition != None:
            user_condition.lower()
        if user_description != None:
            user_description.lower()

        # Ensure if user filled title field
        if not user_title:
            flash("Please fill the \"Book Title\" field.")
            return redirect("/exchange")
        
        # Ensure if user filled author field
        if not user_author:
            flash("Please fill the \"Book Author\" field.")
            return redirect("/exchange")
        
        # Ensure if user enters right condition
        if user_condition != None and user_condition not in conditions:
            flash("Invalid condition.")
            return redirect("/exchange")

        # Keep user description None instead of '' for jinja usage
        if user_description == '':
            user_description = None
        
        # Save book informations in database
        db.execute("INSERT INTO books (user_id, title, author, condition, description) VALUES (?, ?, ?, ?, ?);", session["user_id"], user_title, user_author, user_condition, user_description)
        
        # Iterate over the input image(s)
        for i in range(len(img)):

            # Save as an empty log if user not input an image
            if img[i].filename == '':
                empty_book_id = db.execute("SELECT id FROM books WHERE user_id = ? AND title = ? AND author = ? ORDER BY id DESC;", session["user_id"], user_title, user_author)[0]["id"]
                db.execute("INSERT INTO images (user_id, book_id) VALUES (?, ?);", session["user_id"], empty_book_id)
                flash("Your book ready to exchange.")
                return redirect("/mybooks")
        
            # Ensure if input file format is right
            elif img[i].filename != '' and allowed_file(img[i].filename) == False:
                flash("Only .jpg, .jpeg, .png and .gif file formats allowed.")
                return redirect("/exchange")
            
            # Save the image(s)
            elif img[i].filename != '' and allowed_file(img[i].filename) == True:

                # Save the latest image id number in a variable
                img_id = db.execute("SELECT id FROM images ORDER BY id DESC;")

                # Create a directory for book images if not exists
                if os.path.exists(f"static/pictures/{session['user_id']}/bp") == False:
                    os.makedirs(f"static/pictures/{session['user_id']}/bp")
                
                # Determine the image saving path
                upload_path = f'{os.getcwd()}/static/pictures/{session["user_id"]}/bp'

                # Rename image(s) name(s)
                if len(img_id) < 1:
                    img[i].filename = f"1.{img[i].filename.rsplit('.', 1)[1].lower()}"
                else:
                    img[i].filename = f'{img_id[0]["id"] + 1}.{img[i].filename.rsplit(".", 1)[1].lower()}'

                # Sanitize the file to save
                secure = secure_filename(img[i].filename)

                # Select user's latest book id
                book_id = db.execute("SELECT id FROM books WHERE user_id = ? AND title = ? AND author = ? ORDER BY id DESC;", session["user_id"], user_title, user_author)[0]["id"]
                

                # Save the image in directory
                img[i].save(os.path.join(upload_path, secure))
                # Save the image in database
                db.execute("INSERT INTO images (user_id, book_id, image) VALUES (?, ?, ?);", session["user_id"], book_id, secure)

        # Flash the success and redirect to mybooks.html
        flash("Your book ready to exchange.")
        return redirect("/mybooks")
    else:
        return render_template("exchange.html", greet=greet_user(), picture=profile_picture(), message_notification=message_notification(), offer_notification=offer_notification(), conditions=conditions)
