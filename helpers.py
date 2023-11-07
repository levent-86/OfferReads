from cs50 import SQL
from functools import wraps
from flask import g, request, redirect, flash, session

db = SQL("sqlite:///exchange.db")

# https://cs50.harvard.edu/x/2023/psets/9/finance/
# https://flask.palletsprojects.com/en/2.3.x/patterns/viewdecorators/#view-decorators
# Create login required function
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Login required first.")
            return redirect("/login")            
        return f(*args, **kwargs)
    return decorated_function



def login_not_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id"):
            flash("You're currently logged in.")
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function



# https://simple.wikipedia.org/wiki/List_of_countries
# Put 214 country names in a function to use on select / option in the html
def countries():
    return [
        "Afghanistan", "Åland", "Albania", "Algeria", "American Samoa", "Andorra", "Angola", "Anguilla", "Antigua and Barbuda", "Argentina", 
        "Armenia", "Aruba", "Australia", "Austria", "Azerbaijan", "Bahamas, The", "Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", 
        "Belize", "Benin", "Bermuda", "Bhutan", "Bolivia", "Bonaire", "Bosnia and Herzegovina", "Botswana", "Brazil", 
        "British Indian Ocean Territory", "British Virgin Islands", "Brunei", "Bulgaria", "Burkina Faso", "Burundi", "Cambodia", "Cameroon", 
        "Canada", "Cape Verde", "Central African Republic", "Chad", "Chile", "China, People's Republic of", "Colombia", "Comoros", 
        "Congo, Democratic Republic of the", "Congo, Republic of the", "Costa Rica", "Croatia", "Cuba", "Curaçao", "Cyprus", "Czech Republic", 
        "Denmark", "Djibouti", "Dominica", "Dominican Republic", "East Timor", "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", 
        "Eritrea", "Estonia", "Eswatini", "Ethiopia", "Fiji", "Finland", "France", "Gabon", "Gambia, The", "Georgia", "Germany", "Ghana", 
        "Greece", "Grenada", "Guatemala", "Guinea", "Guinea-Bissau", "Guyana", "Haiti", "Honduras", "Hong Kong", "Hungary", "Iceland", "India", 
        "Indonesia", "Iran", "Iraq", "Ireland", "Israel", "Italy", "Ivory Coast", "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya", 
        "Kiribati", "Korea, North", "Korea, South", "Kuwait", "Kyrgyzstan", "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libya", 
        "Liechtenstein", "Lithuania", "Luxembourg", "Macau", "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", "Malta", 
        "Marshall Islands", "Martinique", "Mauritania", "Mauritius", "Mexico", "Micronesia, Federated States of", "Moldova", "Monaco", 
        "Mongolia", "Montenegro", "Morocco", "Mozambique", "Myanmar", "Namibia", "Nauru", "Nepal", "Netherlands", "New Caledonia", 
        "New Zealand", "Nicaragua", "Niger", "Nigeria", "Norfolk Island", "North Macedonia", "Norway", "Oman", "Pakistan", "Palau", 
        "Palestine", "Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines", "Poland", "Portugal", "Qatar", "Réunion", "Romania", 
        "Russia", "Rwanda", "Saint Kitts and Nevis", "Saint Lucia", "Saint Vincent and the Grenadines", "Samoa", "San Marino", 
        "São Tomé and Príncipe", "Saudi Arabia", "Senegal", "Serbia", "Seychelles", "Sierra Leone", "Singapore", "Slovakia", "Slovenia", 
        "Solomon Islands", "Somalia", "South Africa", "South Sudan", "Spain", "Sri Lanka", "Sudan", "Suriname", "Sweden", " Switzerland", 
        "Syria  Saint Martin", "Sint Maarten", "Tajikistan", "Tanzania", "Thailand", "Togo", "Tonga", "Trinidad and Tobago", "Tunisia", 
        "Turkey", "Turkmenistan", "Tuvalu", "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom", "United States", "Uruguay", 
        "Uzbekistan", "Vanuatu", "Vatican City (Holy See)", "Venezuela", "Vietnam", "Wales", "Wallis and Futuna", "Western Sahara", 
        "Yemen", "Zambia", "Zimbabwe"
        ]



# Greet the user on navbar with their name or username
def greet_user():
    # Check if user logged in
    if session.get("user_id"):
        # If user inputs their name, use the name. Otherwise use their username.
        if db.execute("SELECT fname FROM users WHERE id = ?", session["user_id"])[0]["fname"] is None:
            return db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
        else:
            return db.execute("SELECT fname FROM users WHERE id = ?", session["user_id"])[0]["fname"].title()



# Message notification
def message_notification():
    if session.get("user_id"):
        return db.execute("SELECT COUNT(*) AS count FROM messages WHERE receiver = ? AND is_readed = 0;", session["user_id"])[0]["count"]
    


# Offer notifications
def offer_notification():
    if session.get("user_id"):
        return db.execute("SELECT COUNT(CASE WHEN is_readed = 0 THEN 1 END) AS count FROM offers JOIN books ON offers.offerer_book = books.id WHERE receiver = ? AND is_available = 1 AND is_readed = 0 AND is_offered = 1;", session["user_id"])[0]["count"]



# User's profile picture
def profile_picture():
    # Check if user logged in
    if session.get("user_id"):
        # Show the profile picture only if it's exists
        if db.execute("SELECT picture FROM users WHERE id = ?", session["user_id"])[0]["picture"] != None:
            return db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])[0]["picture"]



# Restrict the file formats to upload image
# https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
