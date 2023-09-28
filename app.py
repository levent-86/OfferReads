from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

# Configure application
app = Flask(__name__)

#! set a secret key while the session still didn't configured - this will be deleted when session configurated
app.secret_key = "justrandombyteshere"

# Auto refresh the app
app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Put countries in a list
    COUNTRIES = [
        "Afghanistan", "Albania", "Algeria", "Andorra", "Angola", "Antigua and Barbuda", "Argentina", "Armenia", "Australia", "Austria",
        "Azerbaijan", "Bahamas", "Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin", "Bhutan",
        "Bolivia", "Bosnia and Herzegovina", "Botswana", "Brazil", "Brunei", "Bulgaria", "Burkina Faso", "Burundi", "Cape Verde", "Cambodia",
        "Cameroon", "Canada", "Central African Republic", "Chad", "Chile", "China", "Colombia", "Comoros", "Congo (Brazzaville)", "Congo (Kinshasa)",
        "Costa Rica", "Croatia", "Cuba", "Cyprus", "Czech Republic", "Denmark", "Djibouti", "Dominica", "Dominican Republic", "East Timor",
        "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", "Eswatini", "Ethiopia", "Fiji", "Finland",
        "France", "Gabon", "Gambia", "Georgia", "Germany", "Ghana", "Greece", "Grenada", "Guatemala", "Guinea",
        "Guinea-Bissau", "Guyana", "Haiti", "Honduras", "Hungary", "Iceland", "India", "Indonesia", "Iran", "Iraq",
        "Ireland", "Israel", "Italy", "Ivory Coast", "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya", "Kiribati",
        "North Korea", "South Korea", "Kosovo", "Kuwait", "Kyrgyzstan", "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia",
        "Libya", "Liechtenstein", "Lithuania", "Luxembourg", "North Macedonia", "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali",
        "Malta", "Marshall Islands", "Mauritania", "Mauritius", "Mexico", "Micronesia", "Moldova", "Monaco", "Mongolia", "Montenegro",
        "Morocco", "Mozambique", "Myanmar", "Namibia", "Nauru", "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Niger",
        "Nigeria", "Northern Cyprus", "Norway", "Oman", "Pakistan", "Palau", "Palestine", "Panama", "Papua New Guinea", "Paraguay",
        "Peru", "Philippines", "Poland", "Portugal", "Qatar", "Romania", "Russia", "Rwanda", "Saint Kitts and Nevis", "Saint Lucia",
        "Saint Vincent and the Grenadines", "Samoa", "San Marino", "Sao Tome and Principe", "Saudi Arabia", "Senegal", "Serbia", "Seychelles",
        "Sierra Leone", "Singapore", "Slovakia", "Slovenia", "Solomon Islands", "Somalia", "South Africa", "South Sudan", "Spain", "Sri Lanka",
        "Sudan", "Suriname", "Sweden", "Switzerland", "Syria", "Taiwan", "Tajikistan", "Tanzania", "Thailand", "Togo",
        "Tonga", "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Tuvalu", "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom",
        "United States", "Uruguay", "Uzbekistan", "Vanuatu", "Vatican City", "Venezuela", "Vietnam", "Yemen", "Zambia", "Zimbabwe"
        ]
    
    # INSERT the user's inputs in database if request method is POST
    if request.method == "POST":
        user_username = request.form.get("username")
        user_email = request.form.get("email")
        user_password = request.form.get("password")
        user_confirm = request.form.get("confirmpass")
        user_country = request.form.get("countries")
        user_city = request.form.get("city")

        # Ensure if user filled Username field
        if len(user_username) < 1:
            flash("Please fill 'Username' field.")
            return render_template("/register.html", countries=COUNTRIES)
        
        # Ensure if user filled email field
        if len(user_email) < 1:
            flash("Please fill 'E-mail' field.")
            return render_template("/register.html", countries=COUNTRIES)
        
        # Ensure if user input a valid email
        if "@" not in user_email:
            flash("Please choose a valid E-mail address.")
            return render_template("/register.html", countries=COUNTRIES)
        
        # Ensure if user filled password field
        if len(user_password) < 1:
            flash("Please fill 'Password' field.")
            return render_template("/register.html", countries=COUNTRIES)
        
        # Ensure if user filled password field
        if len(user_confirm) < 1:
            flash("Please fill 'Password (again)' field.")
            return render_template("/register.html", countries=COUNTRIES)
        
        # Ensure if password and confirmation is the same
        if user_password != user_confirm:
            flash("'Password' and 'Password (again)' fields didn't match.")
            return render_template("/register.html", countries=COUNTRIES)
        
        # Ensure if password length minimum 6 and maximum 21 characters
        if len(user_password) < 6 or len(user_password) > 21:
            flash("The password must be between 6 and 21 characters in length.")
            return render_template("/register.html", countries=COUNTRIES)

        # Ensure if user choose the correct country
        if user_country not in COUNTRIES:
            flash("Please choose correct country.")
            return render_template("/register.html", countries=COUNTRIES)
        
        # Ensure if user filled password field
        if len(user_city) < 1:
            flash("Please fill 'City' field.")
            return render_template("/register.html", countries=COUNTRIES)
        
    else:
        return render_template("register.html", countries=COUNTRIES)
