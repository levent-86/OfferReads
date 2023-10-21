import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import countries, login_required, login_not_required, greet_user, allowed_file, profile_picture


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



@app.route("/", methods=["GET", "POST"])
def index():
    # Show all books, search
    

    if request.method == "POST":
        # Search button
        ...

    # Redirect to clicked book or user / show all books
    else:
        # Query all available books
        all_books = db.execute("SELECT (users.id) AS userid, username, (books.id) AS bookid, title, author, condition, image, strftime('%m/%d/%Y %H:%M', books.date) AS date FROM books JOIN users ON books.user_id = users.id INNER JOIN images ON books.id = images.book_id WHERE is_offered = 0 AND is_available = 1 GROUP BY books.id, images.book_id;")

        return render_template("index.html", greet=greet_user(), picture=profile_picture(), all_books=all_books)



# https://flask.palletsprojects.com/en/3.0.x/quickstart/#url-building
@app.route("/book/<int:books_id><string:books_name>", methods=["GET", "POST"])
@login_required
def book(books_id, books_name):
    if request.method == "POST":
        # Book offering inputs
        ...
    else:
        # Show user informations
        user_details = db.execute("SELECT (users.id) AS userid, country, city, username, picture, strftime('%m/%d/%Y %H:%M', users.date) AS date from users JOIN books ON users.id = books.user_id WHERE books.id = ?", books_id)

        # Show book details
        book_details = db.execute("SELECT books.user_id, (books.id) AS bookid, title, author, condition, description, strftime('%m/%d/%Y %H:%M', books.date) AS date FROM books JOIN users ON books.user_id = users.id WHERE books.id = ?", books_id)
        book_images = db.execute("SELECT image FROM images WHERE book_id = ?", books_id)

        bune = db.execute("SELECT image FROM images WHERE id = 1")
        
        
        return render_template("book.html", greet=greet_user(), picture=profile_picture(), books_name=books_name.title(), author=book_details[0]["author"].title(), condition=book_details[0]["condition"], description=book_details[0]["description"], user_id=user_details[0]["userid"], profile_picture=user_details[0]["picture"], username=user_details[0]["username"], country=user_details[0]["country"].title(), city=user_details[0]["city"].title(), date=user_details[0]["date"], book_images=book_images, book_date=book_details[0]["date"])



@app.route("/user/<username>")
@login_required
def user(username):
    # Book display and offer button
    return render_template("user.html", greet=greet_user(), picture=profile_picture())



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

        # Ensure if username is already exists in the database
        for i in range(len(all_users)):
            if user_username in all_users[i]["username"]:
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
        for i in range(len(all_users)):
            if user_email in all_users[i]["email"]:
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
        
        return render_template("myprofile.html", greet=greet_user(), date=date, fname=fname, lname=lname, username=uname, email=email, user_country=country, countries=countries(), city=city, address=address, phone=phone, picture=profile_picture())




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
            if os.path.exists(f"static/pictures/{session['user_id']}/pp") == False:
                os.makedirs(f"static/pictures/{session['user_id']}/pp")
            """ try:
                os.makedirs(f"static/pictures/{session['user_id']}/pp")
            except FileExistsError:
                pass """
            
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
        # Query all the user's books
        all_books = db.execute("SELECT id FROM books WHERE user_id = ?;", session["user_id"])

        # Iterate over all the books
        for i in range(len(all_books)):
            #  Ensure if the book wanted to be deleted is in the database
            if all_books[i]["id"] == int(book_id):
                # Choose the specific book's images
                book_img = db.execute("SELECT image FROM images WHERE user_id = ? AND book_id = ?", session["user_id"], book_id)
                for j in range(len(book_img)):
                    # Determine the directory of book
                    book_path = f'{os.getcwd()}/static/pictures/{session["user_id"]}/bp/{book_img[j]["image"]}'
                    # Delete book images from directory
                    os.remove(book_path)
                    # Delete book images from database
                    db.execute("DELETE FROM images WHERE user_id = ? AND image  = ?;", session["user_id"], book_img[j]["image"])
                
                # Delete the book in books table
                db.execute("DELETE FROM books WHERE user_id = ? AND id = ?;", session["user_id"], book_id)
                
                # Flash the success and redirect to mybooks.html
                flash("Book deleted successfully.")
                return redirect("/mybooks")
        
        # Show error to user in any misuse
        flash("Something went wrong. Please try again to delete your book.")
        return redirect("/mybooks")

    else:
        # Create an empty list to make it a list of dict
        books = []

        # Query for user's books
        user_books = db.execute("SELECT * FROM books WHERE user_id = ?", session["user_id"])

        # Iterate over all user's books
        for i in range(len(user_books)):
            # Collect user's book data
            book_data = db.execute("SELECT id, title, author, condition, strftime('%m/%d/%Y %H:%M', date) AS date FROM books WHERE user_id = ?;", session["user_id"])[i]
            # Collect user's image data
            image_data = db.execute("SELECT image FROM images WHERE user_id = ? AND book_id = ?;", session["user_id"], book_data["id"])

            # save as None if there's no any image
            if len(image_data) > 0:
                images = image_data[0]
            else:
                images = {'image': None}

            # Save all informations in book list
            book_data.update(images)
            books.append(dict(book_data))
        return render_template("mybooks.html", greet=greet_user(), picture=profile_picture(), book_data=books)



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
        if len(user_title) < 1:
            flash("Please fill the \"Book Title\" field.")
            return redirect("/exchange")
        
        # Ensure if user filled author field
        if len(user_author) < 1:
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

                # Save the latest image id number in the database
                img_id = db.execute("SELECT id FROM images ORDER BY id DESC;")

                # Create a directory for book images if not exists
                # https://docs.python.org/3/library/os.html
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
        return render_template("exchange.html", greet=greet_user(), picture=profile_picture(), conditions=conditions)
