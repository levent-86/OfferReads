# OfferReads
#### Video Demo:  https://youtu.be/mNeBwb-HXw8
#### Description:  A web app where individuals can showcase their books for book swapping and make offers to each other for exchanging books.
#### This is my final project for CS50X
#### Mustafa Levent FİDANCI

This web app written with Flask, JavaScript, HTML, CSS and SQLite

Python 3.11.2

SQLite 3.40.1

cs50==9.2.6

Flask==2.2.2

Flask-Session==0.5.0

python-dotenv==0.21.0

requests==2.28.1

(See "requirements.txt" file.)

Don't forget to create .env file in your root folder and insert a secret key inside.
Example:
"SECRET_KEY"="rondombytescominghere"

### Folder tree of the project
OfferReads/

│    ├──── static - includes .css, .js and image files

│    ├──── templates - includes .html files

├ app.py - the main file of web app

├ exchange.db - database of the web app

├ helpers.py - helper functions for app.py

└ requirements.txt - a list of the libraries i use (list of libraries required to run the application)

### How to run this web app
After the prerequisites in the requirements.txt file are installed, we run the ```flask run``` command from the terminal screen and click on the link that appears.


## Overview

OfferReads is a web application developed using Flask. It addresses the idea that many people have storybooks in their libraries that they have read once and are unlikely to read again. These physical books, no longer in use, are produced from trees. Therefore, every new book we purchase contributes to the cutting down of another tree.

In the current context of discussions about global warming and other natural disasters, instead of contributing to deforestation by buying new books, OfferReads encourages the exchange of second-hand books that people no longer read. With this web application, users can engage in book swaps, thereby making a positive impact in preventing further tree cutting.

## Usage

OfferReads is user-friendly. By clicking on the "Exchange A Book" button in the navbar, users can showcase the second-hand book they want to swap on the index page for everyone to see. Alternatively, users can make an offer on a book they like from the index page that belongs to someone else using the "OFFER A BOOK" button.

## Features

- Upload photos of your second-hand book.
- Provide information about the book's condition.
- Describe the book, including its title, author, and condition.
- View offers in a small list, visible to all users.
- Only the users involved in the offer (sender and receiver) can see detailed offer information.
- Pagination feature added to the index page for faster performance of the web app.

## Privacy

While OfferReads requests all personal information for a book swap, none of the personal details are shared with others. The "contact information" section is automatically sent to the parties approving the book swap via an automated message, simplifying the process.

## Additional Features

- Users receive notifications when they receive an offer.
- If the offer sender deletes their offer, the offered book becomes inactive.
- If the user who posted the book deletes it, the book becomes inactive, and any offers made on that book become inactive as well.
- Deleting personal information results in all active books (including offers made and received) becoming inactive.

## Guidance and Alerts

OfferReads provides small info messages to guide users and remind them to avoid misuse. The application issues warnings if users engage in any incorrect usage.

## Contribution

We hope OfferReads makes a positive contribution to halting the production of books from cut trees. Feel free to contribute and make this initiative even more impactful!

## Acknowledgements

We extend our gratitude to:

- Harvard University
- Prof. David J. Malan

This is CS50, and this is my final project.
