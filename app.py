from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# MongoDB connection
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)

# Adding in database and collection from MongoDB Atlas
db = client["userManagement"]
users = db["users"]

# Instantiating new object with "name"
app = Flask(__name__)

# Secret key
app.secret_key = os.environ.get('SECRET_KEY')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')  # Changed from username to email
        password = request.form.get('password')
        user = users.find_one({"email": email})  # Changed from username to email

        if user and check_password_hash(user['password'], password):
            session['user'] = email  # Changed from username to email
            return redirect(url_for('loggedhome'))
        else:
            flash("Invalid email or password")  # Updated error message
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')  # Added first name field
        email = request.form.get('email')  # Changed from username to email
        password = request.form.get('password')

        if users.find_one({"email": email}):  # Changed from username to email
            flash("Email already exists")  # Updated error message
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='sha256')
        user_data = {
            "first_name": first_name,  # Added first name field
            "email": email,  # Changed from username to email
            "password": hashed_password
        }

        try:
            users.insert_one(user_data)
            flash("Registration successful! You can now log in.")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/loggedhome')
def loggedhome():
    if 'user' in session:
        email = session['user']  # Changed from username to email
        return render_template('loggedhome.html', email=email)  # Changed from username to email
    else:
        return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
