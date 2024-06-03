import os
from flask import Flask, render_template, request, redirect, url_for, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# MongoDB connection
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)
db = client.userManagement
users_collection = db.users

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login logic
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.find_one({"username": username})
        
        if user and check_password_hash(user['password'], password):
            return redirect(url_for('loggedhome'))
        else:
            flash("Invalid username or password")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if user already exists
        if users.find_one({"username": username}):
            flash("Username already exists")
            return redirect(url_for('register'))
        
        # Hash the password and insert into the database
        hashed_password = generate_password_hash(password, method='sha256')
        user_data = {
            "username": username,
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
def logged_home():
    return render_template('loggedhome.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)